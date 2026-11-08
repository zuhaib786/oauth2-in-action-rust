//! The OAuth client (http://localhost:9000).
//!
//! EXERCISE 3-2 (book chapter 3): the client starts with an access token that
//! doesn't work and a refresh token that does. Make it refresh:
//!   1. in `fetch_resource`, when the protected resource says no, call
//!      `refresh_access_token` instead of showing an error
//!   2. fill in `refresh_access_token`
//!
//! Compare with the solution:  git diff ch3-ex2-done -- client
//!
//! Run it with:  cargo run -p client

// Silences "unused variable/import" warnings until you've written your code.
// Delete this line when you're done, to see if anything is left unused.

use std::{collections::HashMap, sync::Arc};

use axum::{
    Router,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use oauth_common::{build_url, context, encode_client_credentials, random_string, render};
use serde_json::Value;
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
    scope: "foo",
};

const PROTECTED_RESOURCE: &str = "http://localhost:9002/resource";

/// The JS keeps these in global variables (`var state = null;` etc.).
/// Here they live in one struct behind a lock that every handler can reach
/// through `State(app)`. `Option<String>` plays the role of "string or null".
struct ClientState {
    state: Option<String>,
    access_token: Option<String>,
    scope: Option<String>,
    refresh_token: Option<String>,
}

impl ClientState {
    fn new() -> Self {
        ClientState {
            state: None,
            // Exercise 3-2: the authorization server doesn't know this access
            // token, but it does know this refresh token.
            access_token: Some("987tghjkiu6trfghjuytrghj".into()),
            scope: None,
            refresh_token: Some("j2r3oj32r23rmasd98uhjrk2o3i".into()),
        }
    }
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
        println!(
            "State DOES NOT MATCH: expected {:?} got {:?}",
            s.state,
            params.get("state")
        );
        return render("error", context! { error => "State value did not match" });
    }

    let code = params.get("code").map(String::as_str).unwrap_or("");

    println!("Requesting access token for code {code}");

    let tok_res = reqwest::Client::new()
        .post(AUTH_SERVER.token_endpoint)
        .header(
            "Authorization",
            format!(
                "Basic {}",
                encode_client_credentials(CLIENT.client_id, CLIENT.client_secret)
            ),
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
            return render(
                "error",
                context! { error => format!("Token request failed: {err}") },
            );
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
        Ok(_res) => {
            /*
             * TODO: Instead of always returning an error like we do here,
             * refresh the access token if we have a refresh token.
             *
             * Hint: `refresh_access_token(&mut s).await` hands our state to
             * the function below.
             */
            println!("Refreshing access token");
            refresh_access_token(&mut s).await
        }
        Err(err) => render(
            "error",
            context! { error => format!("Resource request failed: {err}") },
        ),
    }
}

/// Trades our refresh token for a new access token, then sends the browser
/// back to /fetch_resource to try again.
async fn refresh_access_token(s: &mut ClientState) -> Response {
    /*
     * TODO: Use the refresh token to get a new access token
     *
     * Hints:
     *   - it's a POST to the token endpoint, like the one in `callback`, but
     *     with grant_type=refresh_token and refresh_token=<our refresh token>
     *   - on success, save the new access token (and the new refresh token
     *     and scope, if the response has them), then
     *     `Redirect::to("/fetch_resource").into_response()` to try again
     *   - on failure, forget the refresh token (the user has to log in
     *     again) and show an error page
     */

    s.access_token = None;
    let Some(refresh_token) = s.refresh_token.as_ref() else {
        return render("error", context! {error => "No usable refresh token found"});
    };
    let res = reqwest::Client::new()
        .post(AUTH_SERVER.token_endpoint)
        .header(
            "Authorization",
            format!(
                "Basic {}",
                encode_client_credentials(CLIENT.client_id, CLIENT.client_secret)
            ),
        )
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await;
    match res {
        Ok(response) if response.status().is_success() => {
            let body = if let Ok(body) = response.json::<Value>().await {
                body
            } else {
                return render("error", context! {error => "Failed to parse json"});
            };
            let Some(access_token) = body["access_token"].as_str() else {
                return render("error", context! {error => "No access token returned"});
            };
            let ref_token = if let Some(token) = body["refresh_token"].as_str() {
                token
            } else {
                refresh_token
            }; // old refresh token only if not returned
            s.access_token = Some(access_token.to_owned());
            s.refresh_token = Some(ref_token.to_owned());
            Redirect::to("/fetch_resource").into_response()
        }
        Ok(response) => {
            s.refresh_token = None;
            s.access_token = None;
            render(
                "error",
                context! {error => format!("Request failed with status code: {}", response.status())},
            )
        }
        Err(err) => render(
            "error",
            context! {error => format!("Request failed with error : {err}")},
        ),
    }
}

#[tokio::main]
async fn main() {
    oauth_common::set_views_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/templates"));

    let app = Router::new()
        .route("/", get(index))
        .route("/authorize", get(authorize))
        .route("/callback", get(callback))
        .route("/fetch_resource", get(fetch_resource))
        .with_state(Arc::new(Mutex::new(ClientState::new())));

    oauth_common::serve(app, 9000, "OAuth Client").await;
}
