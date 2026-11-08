//! The OAuth client (http://localhost:9000).
//!
//! EXERCISE 3-1 (book chapter 3): fill in the three handlers marked TODO
//! (`authorize`, `callback`, `fetch_resource`) plus the client credentials.
//! Everything you need is already imported.
//! Compare with the solution:  git diff ch3-ex1-done -- client
//!
//! Run it with:  cargo run -p client

// Silences "unused variable/import" warnings until you've written your code.
// Delete this line when you're done, to see if anything is left unused.
#![allow(unused)]

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

/*
 * Add the client information in here
 */
const CLIENT: ClientInfo = ClientInfo {
    client_id: "",
    client_secret: "",
    redirect_uris: &["http://localhost:9000/callback"],
};

const PROTECTED_RESOURCE: &str = "http://localhost:9002/resource";

/// The JS keeps these in global variables (`var state = null;` etc.).
/// Here they live in one struct behind a lock that every handler can reach
/// through `State(app)`. `Option<String>` plays the role of "string or null".
///
/// To read or change them inside a handler:
///     let mut s = app.lock().await;
///     s.state = Some(random_string(32));
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
    /*
     * Send the user to the authorization server
     *
     * Hints:
     *   - build_url(base, &[("key", "value"), ...]) builds a URL with a query string
     *   - Redirect::to(&url).into_response() sends the browser there
     */

    render("error", context! { error => "TODO: implement /authorize in client/src/main.rs" })
}

async fn callback(
    State(app): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    /*
     * Parse the response from the authorization server and get a token
     *
     * Hints:
     *   - params.get("code") is `req.query.code`; it gives an Option<&String>
     *   - an HTTP POST with a form body looks like:
     *         let res = reqwest::Client::new()
     *             .post(url)
     *             .header("Authorization", format!("Basic {}", ...))
     *             .form(&[("key", "value"), ...])
     *             .send()
     *             .await;
     *   - `res` is a Result: Ok(response) or Err(network error)
     *   - response.status().is_success() and response.json::<Value>().await
     */

    render("error", context! { error => "TODO: implement /callback in client/src/main.rs" })
}

async fn fetch_resource(State(app): State<AppState>) -> Response {
    /*
     * Use the access token to call the resource server
     *
     * Hints:
     *   - render("data", context! { resource => body }) shows the JSON you got back
     */

    render("error", context! { error => "TODO: implement /fetch_resource in client/src/main.rs" })
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
