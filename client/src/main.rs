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
    client_id: "oauth-client-1",
    client_secret: "oauth-client-secret-1",
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
    render(
        "index",
        context! { access_token => s.access_token, scope => s.scope },
    )
}

async fn authorize(State(app): State<AppState>) -> Response {
    /*
     * Send the user to the authorization server
     *
     * Hints:
     *   - build_url(base, &[("key", "value"), ...]) builds a URL with a query string
     *   - Redirect::to(&url).into_response() sends the browser there
     */
    let mut s = app.lock().await;
    s.state = Some(random_string(20));
    let uri = build_url(
        AUTH_SERVER.authorization_endpoint,
        &[
            ("response_type", "code"),
            ("client_id", CLIENT.client_id),
            ("redirect_uri", CLIENT.redirect_uris[0]),
            ("state", s.state.as_ref().unwrap()),
        ],
    );
    Redirect::to(&uri).into_response()
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
    let mut s = app.lock().await;
    // Handle deny
    if let Some(deny) = params.get("error") {
        return render(
            "error",
            context! {error => format!("Authorization Request denied: {}", deny)},
        );
    }
    // Get the code
    if let Some(code) = params.get("code") {
        // run the code on the token fetch endpoint

        if params.get("state") != s.state.as_ref() {
            return render("error", context! {error => "Invalid state returned"});
        }
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
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", CLIENT.redirect_uris[0]),
            ])
            .send()
            .await;
        match res {
            Ok(response) => {
                // on success
                if response.status().is_success() {
                    let body = if let Ok(body) = response.json::<Value>().await {
                        body
                    } else {
                        return render("error", context! {error => "Failed to parse json"});
                    };

                    let Some(access_token) = body["access_token"].as_str() else {
                        return render(
                            "error",
                            context! {error => "Access token not returned by the endpoint"},
                        );
                    };
                    s.access_token = Some(access_token.to_owned());
                    render(
                        "index",
                        context! {access_token => s.access_token, scope => s.scope},
                    )
                } else {
                    render(
                        "error",
                        context! {error => format!("Could not reach the token endpoint successfully. Status code: {}", response.status())},
                    )
                }
            }
            Err(err) => render(
                "error",
                context! {error => format!("Could not connect: {err}")},
            ),
        }
    } else {
        render(
            "error",
            context! {error => "Invalid authorization request. Code param is required"},
        )
    }
}

async fn fetch_resource(State(app): State<AppState>) -> Response {
    /*
     * Use the access token to call the resource server
     *
     * Hints:
     *   - render("data", context! { resource => body }) shows the JSON you got back
     */

    let s = app.lock().await;
    let Some(access_token) = s.access_token.as_ref() else {
        return render(
            "error",
            context! {error => "Unauthorized Request. Please authenticate first"},
        );
    };
    let resp = reqwest::Client::new()
        .post(PROTECTED_RESOURCE)
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await;
    match resp {
        Ok(response) => {
            if response.status().is_success() {
                let body = if let Ok(body) = response.json::<Value>().await {
                    body
                } else {
                    return render("error", context! {error => "Failed to parse json"});
                };
                render("data", context! {resource => body})
            } else {
                render(
                    "error",
                    context! {error => format!("Request failed with status code: {}",response.status())},
                )
            }
        }
        Err(err) => render(
            "error",
            context! {error => format!("Error while fetching the resource: {err}")},
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
        .with_state(AppState::default());

    oauth_common::serve(app, 9000, "OAuth Client").await;
}
