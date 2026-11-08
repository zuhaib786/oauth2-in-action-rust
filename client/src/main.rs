//! The OAuth client (http://localhost:9000).
//!
//! It gets an access token from the authorization server using the
//! authorization code grant, then uses it to call the protected resource.
//! When the access token stops working, it gets a new one with the
//! refresh token.
//!
//! Run it with:  cargo run -p client

use std::{collections::HashMap, sync::Arc};

use axum::{
    Router,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use oauth_common::{build_url, context, encode_client_credentials, param, random_string, render};
use serde_json::{Value, json};
use tokio::sync::Mutex;

// authorization server information
struct AuthServer {
    authorization_endpoint: &'static str,
    token_endpoint: &'static str,
}

const AUTH_SERVER: AuthServer = AuthServer {
    authorization_endpoint: "http://localhost:9001/authorize",
    token_endpoint: "http://localhost:9001/token",
};

// client information
struct ClientInfo {
    client_id: &'static str,
    client_secret: &'static str,
    redirect_uris: &'static [&'static str],
    /// The scopes we ask for, separated by spaces.
    scope: &'static str,
}

const CLIENT: ClientInfo = ClientInfo {
    client_id: "oauth-client-1",
    client_secret: "oauth-client-secret-1",
    redirect_uris: &["http://localhost:9000/callback"],
    scope: "foo bar read write delete fruit veggies meats",
};

const PROTECTED_RESOURCE: &str = "http://localhost:9002/resource";
const WORDS_API: &str = "http://localhost:9002/words";
const PRODUCE_API: &str = "http://localhost:9002/produce";

/// The JS keeps these in global variables (`var state = null;` etc.).
/// Here they live in one struct behind a lock that every handler can reach
/// through `State(app)`. `Option<String>` plays the role of "string or null".
#[derive(Default)]
struct ClientState {
    state: Option<String>,
    access_token: Option<String>,
    scope: Option<String>,
    refresh_token: Option<String>,
}

type AppState = Arc<Mutex<ClientState>>;

/// The home page, showing the tokens we currently hold.
fn show_tokens(s: &ClientState) -> Response {
    render(
        "index",
        context! { access_token => s.access_token, scope => s.scope, refresh_token => s.refresh_token },
    )
}

async fn index(State(app): State<AppState>) -> Response {
    show_tokens(&*app.lock().await)
}

async fn authorize(State(app): State<AppState>) -> Response {
    let mut s = app.lock().await;
    s.access_token = None;
    s.scope = None;

    let state = random_string(32);
    s.state = Some(state.clone());

    let authorize_url = build_url(
        AUTH_SERVER.authorization_endpoint,
        &[
            ("response_type", "code"),
            ("scope", CLIENT.scope),
            ("client_id", CLIENT.client_id),
            ("redirect_uri", CLIENT.redirect_uris[0]),
            ("state", &state),
        ],
    );

    println!("redirect {authorize_url}");
    Redirect::to(&authorize_url).into_response()
}

async fn callback(
    State(app): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(error) = params.get("error") {
        // it's an error response, act accordingly
        return render("error", context! { error => error });
    }

    let mut s = app.lock().await;

    if params.get("state") != s.state.as_ref() {
        println!("State DOES NOT MATCH: expected {:?} got {:?}", s.state, params.get("state"));
        return render("error", context! { error => "State value did not match" });
    }

    let code = params.get("code").map(String::as_str).unwrap_or("");

    println!("Requesting access token for code {code}");

    let tok_res = reqwest::Client::new()
        .post(AUTH_SERVER.token_endpoint)
        .header(
            "Authorization",
            format!("Basic {}", encode_client_credentials(CLIENT.client_id, CLIENT.client_secret)),
        )
        // `.form(...)` sends the body as application/x-www-form-urlencoded
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", CLIENT.redirect_uris[0]),
        ])
        .send()
        .await;

    // Unlike JS, Rust makes us handle "the server didn't answer at all".
    let tok_res = match tok_res {
        Ok(res) => res,
        Err(err) => {
            return render("error", context! { error => format!("Token request failed: {err}") });
        }
    };

    if !tok_res.status().is_success() {
        return render(
            "error",
            context! {
                error => format!("Unable to fetch access token, server response: {}", tok_res.status().as_u16())
            },
        );
    }

    let body: Value = tok_res.json().await.unwrap_or_default();

    s.access_token = body["access_token"].as_str().map(String::from);
    println!("Got access token: {:?}", s.access_token);

    if let Some(refresh_token) = body["refresh_token"].as_str() {
        s.refresh_token = Some(refresh_token.to_string());
        println!("Got refresh token: {refresh_token}");
    }

    s.scope = body["scope"].as_str().map(String::from);
    println!("Got scope: {:?}", s.scope);

    show_tokens(&s)
}

async fn fetch_resource(State(app): State<AppState>) -> Response {
    let mut s = app.lock().await;

    let Some(access_token) = s.access_token.clone() else {
        return render("error", context! { error => "Missing Access Token" });
    };

    println!("Making request with access token {access_token}");

    let resource = reqwest::Client::new()
        .post(PROTECTED_RESOURCE)
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await;

    match resource {
        Ok(res) if res.status().is_success() => {
            let body: Value = res.json().await.unwrap_or_default();
            render("data", context! { resource => body })
        }
        Ok(res) => {
            // The access token didn't work (maybe it expired). Try to get a
            // new one with the refresh token, if we have one.
            s.access_token = None;
            if s.refresh_token.is_some() {
                refresh_access_token(&mut s).await
            } else {
                render("error", context! { error => res.status().as_u16() })
            }
        }
        Err(err) => render("error", context! { error => format!("Resource request failed: {err}") }),
    }
}

/// Trades our refresh token for a new access token, then sends the browser
/// back to /fetch_resource to try again.
async fn refresh_access_token(s: &mut ClientState) -> Response {
    let refresh_token = s.refresh_token.clone().unwrap_or_default();
    println!("Refreshing token {refresh_token}");

    let tok_res = reqwest::Client::new()
        .post(AUTH_SERVER.token_endpoint)
        .header(
            "Authorization",
            format!("Basic {}", encode_client_credentials(CLIENT.client_id, CLIENT.client_secret)),
        )
        .form(&[("grant_type", "refresh_token"), ("refresh_token", refresh_token.as_str())])
        .send()
        .await;

    match tok_res {
        Ok(res) if res.status().is_success() => {
            let body: Value = res.json().await.unwrap_or_default();

            s.access_token = body["access_token"].as_str().map(String::from);
            println!("Got access token: {:?}", s.access_token);

            if let Some(new_refresh_token) = body["refresh_token"].as_str() {
                s.refresh_token = Some(new_refresh_token.to_string());
                println!("Got refresh token: {new_refresh_token}");
            }

            s.scope = body["scope"].as_str().map(String::from);
            println!("Got scope: {:?}", s.scope);

            // try again
            Redirect::to("/fetch_resource").into_response()
        }
        _ => {
            println!("No refresh token, asking the user to get a new access token");
            // tell the user to get a new access token
            s.refresh_token = None;
            render("error", context! { error => "Unable to refresh token." })
        }
    }
}

// ---------------------------------------------------------------------------
// Words API (chapter 4)
// ---------------------------------------------------------------------------

/// The `Authorization` header value for calling the protected resource.
fn bearer(s: &ClientState) -> String {
    format!("Bearer {}", s.access_token.as_deref().unwrap_or(""))
}

/// Shows the Words page. `result` says which button was pressed and whether
/// it worked ("get", "noget", "add", "noadd", "rm", "norm"), or is "".
fn words_page(words: &str, timestamp: u64, result: &str) -> Response {
    render("words", context! { words => words, timestamp => timestamp, result => result })
}

async fn words() -> Response {
    words_page("", 0, "")
}

async fn get_words(State(app): State<AppState>) -> Response {
    let s = app.lock().await;
    let res = reqwest::Client::new()
        .get(WORDS_API)
        .header("Authorization", bearer(&s))
        .send()
        .await;

    match res {
        Ok(res) if res.status().is_success() => {
            let body: Value = res.json().await.unwrap_or_default();
            let words = body["words"].as_str().unwrap_or("");
            words_page(words, body["timestamp"].as_u64().unwrap_or(0), "get")
        }
        _ => words_page("", 0, "noget"),
    }
}

async fn add_word(
    State(app): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let s = app.lock().await;
    let res = reqwest::Client::new()
        .post(WORDS_API)
        .header("Authorization", bearer(&s))
        .form(&[("word", param(&params, "word"))])
        .send()
        .await;

    let worked = matches!(&res, Ok(r) if r.status().is_success());
    words_page("", 0, if worked { "add" } else { "noadd" })
}

async fn delete_word(State(app): State<AppState>) -> Response {
    let s = app.lock().await;
    let res = reqwest::Client::new()
        .delete(WORDS_API)
        .header("Authorization", bearer(&s))
        .send()
        .await;

    let worked = matches!(&res, Ok(r) if r.status().is_success());
    words_page("", 0, if worked { "rm" } else { "norm" })
}

// ---------------------------------------------------------------------------
// Produce API (chapter 4)
// ---------------------------------------------------------------------------

async fn produce(State(app): State<AppState>) -> Response {
    let s = app.lock().await;
    let res = reqwest::Client::new()
        .get(PRODUCE_API)
        .header("Authorization", bearer(&s))
        .send()
        .await;

    let data: Value = match res {
        Ok(res) if res.status().is_success() => res.json().await.unwrap_or_default(),
        _ => json!({ "fruit": [], "veggies": [], "meats": [] }),
    };
    render("produce", context! { scope => s.scope, data => data })
}

#[tokio::main]
async fn main() {
    oauth_common::set_views_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/templates"));

    let app = Router::new()
        .route("/", get(index))
        .route("/authorize", get(authorize))
        .route("/callback", get(callback))
        .route("/fetch_resource", get(fetch_resource))
        .route("/words", get(words))
        .route("/get_words", get(get_words))
        .route("/add_word", get(add_word))
        .route("/delete_word", get(delete_word))
        .route("/produce", get(produce))
        .with_state(AppState::default());

    oauth_common::serve(app, 9000, "OAuth Client").await;
}
