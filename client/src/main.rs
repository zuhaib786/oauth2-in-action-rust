//! The OAuth client (http://localhost:9000).
//!
//! It gets an access token from the authorization server using the
//! authorization code grant, then uses it to call the protected resource.
//!
//! Run it with:  cargo run -p client

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
}

const CLIENT: ClientInfo = ClientInfo {
    client_id: "oauth-client-1",
    client_secret: "oauth-client-secret-1",
    redirect_uris: &["http://localhost:9000/callback"],
};

const PROTECTED_RESOURCE: &str = "http://localhost:9002/resource";

/// The JS keeps these in global variables (`var state = null;` etc.).
/// Here they live in one struct behind a lock that every handler can reach
/// through `State(app)`. `Option<String>` plays the role of "string or null".
#[derive(Default)]
struct ClientState {
    state: Option<String>,
    access_token: Option<String>,
    scope: Option<String>,
}

type AppState = Arc<Mutex<ClientState>>;

async fn index(State(app): State<AppState>) -> Response {
    let s = app.lock().await;
    render("index", context! { access_token => s.access_token, scope => s.scope })
}

async fn authorize(State(app): State<AppState>) -> Response {
    let mut s = app.lock().await;
    s.access_token = None;

    let state = random_string(32);
    s.state = Some(state.clone());

    let authorize_url = build_url(
        AUTH_SERVER.authorization_endpoint,
        &[
            ("response_type", "code"),
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

    if tok_res.status().is_success() {
        let body: Value = tok_res.json().await.unwrap_or_default();

        s.access_token = body["access_token"].as_str().map(String::from);
        println!("Got access token: {:?}", s.access_token);

        render("index", context! { access_token => s.access_token, scope => s.scope })
    } else {
        render(
            "error",
            context! {
                error => format!("Unable to fetch access token, server response: {}", tok_res.status().as_u16())
            },
        )
    }
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
            s.access_token = None;
            render("error", context! { error => res.status().as_u16() })
        }
        Err(err) => render("error", context! { error => format!("Resource request failed: {err}") }),
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
        .with_state(AppState::default());

    oauth_common::serve(app, 9000, "OAuth Client").await;
}
