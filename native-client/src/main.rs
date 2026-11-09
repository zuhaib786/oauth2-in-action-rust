//! A native app: a command-line OAuth client (chapter 6).
//!
//! It's a public client, so it has no secret. To get the authorization code
//! back from the browser, it runs a tiny web server on the loopback address
//! for as long as the login takes (RFC 8252 §7.3). PKCE (chapter 10) makes
//! sure only this process can redeem the code.
//!
//! Run it with:  cargo run -p native-client

use std::{
    collections::HashMap,
    process::ExitCode,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    extract::{Query, State},
    response::Html,
    routing::get,
};
use oauth_common::{build_url, pkce_challenge, random_string};
use serde_json::Value;
use tokio::{net::TcpListener, sync::oneshot};

const AUTHORIZATION_ENDPOINT: &str = "http://localhost:9001/authorize";
const TOKEN_ENDPOINT: &str = "http://localhost:9001/token";
const PROTECTED_RESOURCE: &str = "http://localhost:9002/resource";

const CLIENT_ID: &str = "oauth-native-client";
const SCOPE: &str = "foo bar";

/// How long to wait for the user to finish in the browser.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);

type Error = Box<dyn std::error::Error>;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(resource) => {
            println!("{resource}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("native-client: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<String, Error> {
    // Port 0: the operating system picks a free one.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let redirect_uri = format!("http://127.0.0.1:{}/callback", listener.local_addr()?.port());
    let state = random_string(32);
    let code_verifier = random_string(64);

    let authorize_url = build_url(
        AUTHORIZATION_ENDPOINT,
        &[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", &redirect_uri),
            ("scope", SCOPE),
            ("state", &state),
            ("code_challenge", &pkce_challenge(&code_verifier)),
            ("code_challenge_method", "S256"),
        ],
    );
    println!("Open this URL in your browser to log in:");
    println!("{authorize_url}");
    if std::env::var_os("NO_BROWSER").is_none() {
        open_browser(&authorize_url);
    }

    let code = wait_for_code(listener, state).await?;
    let access_token = trade_code(&code, &redirect_uri, &code_verifier).await?;

    let resource: Value = reqwest::Client::new()
        .post(PROTECTED_RESOURCE)
        .bearer_auth(access_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(serde_json::to_string_pretty(&resource)?)
}

// ---------------------------------------------------------------------------
// The loopback server
// ---------------------------------------------------------------------------

/// What the callback handler needs: the state we sent, and a way to hand
/// the outcome back to `wait_for_code`. A handler may run more than once,
/// but a oneshot sender can only be used once, hence `Option`.
struct Callback {
    expected_state: String,
    outcome: Mutex<Option<oneshot::Sender<Result<String, String>>>>,
}

/// Serves `/callback` until the browser comes back to it, then returns the
/// authorization code.
async fn wait_for_code(listener: TcpListener, expected_state: String) -> Result<String, Error> {
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();

    let callback = Arc::new(Callback { expected_state, outcome: Mutex::new(Some(outcome_tx)) });
    let app = Router::new().route("/callback", get(callback_page)).with_state(callback);

    // Graceful shutdown: finish sending the page to the browser, then stop.
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stop_rx.await;
            })
            .await
    });

    let outcome = tokio::time::timeout(LOGIN_TIMEOUT, outcome_rx).await;
    let _ = stop_tx.send(());
    let _ = server.await;

    match outcome {
        Err(_) => Err("gave up waiting for the browser".into()),
        Ok(Err(_)) => Err("the loopback server stopped unexpectedly".into()),
        Ok(Ok(result)) => result.map_err(Into::into),
    }
}

async fn callback_page(
    State(callback): State<Arc<Callback>>,
    Query(params): Query<HashMap<String, String>>,
) -> Html<&'static str> {
    let result = check_callback(&params, &callback.expected_state);
    let page = if result.is_ok() {
        "<h1>Logged in</h1><p>You can close this tab and go back to the terminal.</p>"
    } else {
        "<h1>Login failed</h1><p>See the terminal for details.</p>"
    };
    if let Some(outcome) = callback.outcome.lock().unwrap_or_else(|p| p.into_inner()).take() {
        let _ = outcome.send(result);
    }
    Html(page)
}

/// The code, if this really is the answer to our request.
fn check_callback(params: &HashMap<String, String>, expected_state: &str) -> Result<String, String> {
    // Check state first: without it, anyone could feed us their own code.
    if params.get("state").map(String::as_str) != Some(expected_state) {
        return Err("the state in the callback doesn't match: refusing it".into());
    }
    if let Some(error) = params.get("error") {
        return Err(format!("the authorization server said: {error}"));
    }
    params.get("code").cloned().ok_or_else(|| "the callback has no code".into())
}

// ---------------------------------------------------------------------------
// The token endpoint
// ---------------------------------------------------------------------------

/// Trades the code for an access token. A public client has no secret, so
/// it says who it is and proves it started this login with the verifier.
async fn trade_code(code: &str, redirect_uri: &str, code_verifier: &str) -> Result<String, Error> {
    let res = reqwest::Client::new()
        .post(TOKEN_ENDPOINT)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", CLIENT_ID),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await?;

    let status = res.status();
    let body: Value = res.json().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("the token endpoint answered {status}: {}", body["error"]).into());
    }
    body["access_token"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| "the token response has no access_token".into())
}

fn open_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    if std::process::Command::new(opener).arg(url).spawn().is_err() {
        eprintln!("(couldn't open a browser; open the URL yourself)");
    }
}
