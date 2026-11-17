//! native-client: a native app that logs in through the system browser and
//! gets the authorization code back on a loopback redirect (chapter 6).
//!
//! Run it with:  cargo run -p native-client

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use oauth_common::{build_url, param, random_string};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

const AUTHORIZATION_ENDPOINT: &str = "http://localhost:9001/authorize";
const TOKEN_ENDPOINT: &str = "http://localhost:9001/token";
const PROTECTED_RESOURCE: &str = "http://localhost:9002/resource";

const CLIENT_ID: &str = "oauth-native-client";
const SCOPE: &str = "foo bar";

/// What the callback hands to `main`: the code, or why the login failed.
type Outcome = Result<String, String>;

#[derive(Clone)]
struct AppState {
    expected_state: String,
    reply: Arc<Mutex<Option<oneshot::Sender<Outcome>>>>,
}

/// Where the browser lands after the user approves or denies. Works out the
/// outcome, hands it to `main`, and tells the browser what happened.
async fn callback(
    State(app): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    // Check `state` first: if it's wrong, nothing else in this request can be
    // trusted, including an `error` or a `code`. A missing state is "", which
    // never matches, so it fails too.
    let outcome = if param(&query, "state") != app.expected_state {
        Err("the callback's state doesn't match ours, so it didn't come from our login".to_string())
    } else if let Some(error) = query.get("error") {
        Err(format!("the authorization server said: {error}"))
    } else if let Some(code) = query.get("code").filter(|code| !code.is_empty()) {
        Ok(code.clone())
    } else {
        Err("the callback has no code".to_string())
    };

    // Only the first callback counts. The lock is released at the `;`.
    let sender = app.reply.lock().unwrap().take();
    let Some(sender) = sender else {
        return (
            StatusCode::CONFLICT,
            Html("<p>This login has already finished. You can close this tab.</p>"),
        )
            .into_response();
    };

    // The pages are fixed text: never echo query values into HTML.
    let page = match &outcome {
        Ok(_) => (
            StatusCode::OK,
            Html("<p>Logged in. You can close this tab and go back to the app.</p>"),
        ),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Html("<p>Login failed. The app says why.</p>"),
        ),
    };
    let _ = sender.send(outcome); // Err only if main has stopped waiting
    page.into_response()
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state: String = random_string(16);
    let (tx, rx) = oneshot::channel::<Outcome>();
    let app_state = AppState {
        reply: Arc::new(Mutex::new(Some(tx))),
        expected_state: state.clone(),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{}/callback", port);
    let authorization_url = build_url(
        AUTHORIZATION_ENDPOINT,
        &[
            ("state", &state),
            ("redirect_uri", &redirect_uri),
            ("response_type", "code"),
            ("client_id", "oauth-native-client"),
            ("scope", SCOPE),
        ],
    );
    println!("{authorization_url}");
    if std::env::var_os("NO_BROWSER").is_none() {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        let _ = std::process::Command::new(opener)
            .arg(&authorization_url)
            .spawn();
    }
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let app = axum::Router::new()
        .route("/callback", get(callback))
        .with_state(app_state);
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = stop_rx.await;
            })
            .await
    });
    let outcome = tokio::time::timeout(Duration::from_secs(5 * 60), rx).await;
    let _ = stop_tx.send(());
    server.await??;
    let code = match outcome {
        Err(_) => return Err("No callback withing 5 minutes".into()),
        Ok(Err(_)) => return Err("The server stopped without callback".into()),
        Ok(Ok(Err(reason))) => return Err(reason.into()),
        Ok(Ok(Ok(code))) => code,
    };
    let http = reqwest::Client::new();
    let token: serde_json::Value = http
        .post(TOKEN_ENDPOINT)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", &redirect_uri),
            ("client_id", CLIENT_ID),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let access_token = token["access_token"]
        .as_str()
        .ok_or("no access token in the token response")?;
    let resource = http
        .post(PROTECTED_RESOURCE)
        .header("Authorization", &format!("Bearer {}", access_token))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    println!("Protected resource: {resource}");

    Ok(())
}
