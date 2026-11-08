//! The OAuth protected resource (http://localhost:9002).
//!
//! APIs that only answer requests carrying a valid access token issued by
//! the authorization server.
//!
//! Run it with:  cargo run -p protected-resource

use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, StatusCode, header::WWW_AUTHENTICATE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use oauth_common::{Db, context, parse_form, render};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct AppState {
    /// Issued tokens, written by the authorization server.
    db: Db,
    /// The Words API's data (`var savedWords = []` in the JS).
    saved_words: Arc<Mutex<Vec<String>>>,
}

// ---------------------------------------------------------------------------
// Finding and checking the access token
// ---------------------------------------------------------------------------

/// Looks for an access token in (1) the `Authorization: Bearer` header,
/// (2) the form body, or (3) the query string, then checks it against the
/// database the authorization server writes to. Returns the stored token
/// record (with its `client_id`, `scope`, ...) if it is valid.
fn get_access_token(
    db: &Db,
    headers: &HeaderMap,
    query: &HashMap<String, String>,
    form: &HashMap<String, String>,
) -> Option<Value> {
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());

    let in_token = if let Some(auth) = auth.filter(|a| a.to_lowercase().starts_with("bearer ")) {
        Some(auth["bearer ".len()..].to_string())
    } else if let Some(token) = form.get("access_token") {
        // not in the header, check in the form body
        Some(token.clone())
    } else {
        query.get("access_token").cloned()
    };

    println!("Incoming token: {}", in_token.as_deref().unwrap_or("(none)"));
    let in_token = in_token?;

    let found = db.find_one(|doc| doc["access_token"] == in_token.as_str());
    match &found {
        Some(_) => println!("We found a matching token: {in_token}"),
        None => println!("No matching token was found."),
    }
    found
}

/// A valid access token that came with the request.
///
/// Putting `token: AccessToken` in a handler's arguments means "this endpoint
/// needs a valid token". Without one, axum answers 401 Unauthorized and never
/// calls the handler. This replaces the book's `getAccessToken` and
/// `requireAccessToken` Express middleware.
struct AccessToken {
    /// The token's record from the database: `client_id`, `scope`, ...
    record: Value,
    /// The request's form body. We had to read the body to look for a token
    /// in it, so handlers that need other form fields get them from here.
    form: HashMap<String, String>,
}

impl AccessToken {
    /// True if the token was issued with this scope. Stored scopes are a JSON
    /// list like `["read", "write"]`.
    fn has_scope(&self, scope: &str) -> bool {
        self.record["scope"]
            .as_array()
            .is_some_and(|scopes| scopes.iter().any(|s| s == scope))
    }
}

/// This is the code that runs when a handler asks for an `AccessToken`.
impl FromRequest<AppState> for AccessToken {
    type Rejection = StatusCode;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let query = parse_form(parts.uri.query().unwrap_or(""));
        let body = axum::body::to_bytes(body, 64 * 1024)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let form = parse_form(&String::from_utf8_lossy(&body));

        match get_access_token(&state.db, &parts.headers, &query, &form) {
            Some(record) => Ok(AccessToken { record, form }),
            None => Err(StatusCode::UNAUTHORIZED),
        }
    }
}

// ---------------------------------------------------------------------------
// APIs
// ---------------------------------------------------------------------------

async fn resource(_token: AccessToken) -> Response {
    Json(json!({
        "name": "Protected Resource",
        "description": "This data has been protected by OAuth 2.0"
    }))
    .into_response()
}

/// Milliseconds since 1970, like JavaScript's `Date.now()`.
fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// 403 Forbidden, telling the client which scope it was missing.
fn insufficient_scope(scope: &str) -> Response {
    let challenge =
        format!(r#"Bearer realm=localhost:9002, error="insufficient_scope", scope="{scope}""#);
    (StatusCode::FORBIDDEN, [(WWW_AUTHENTICATE, challenge)]).into_response()
}

async fn get_words(State(app): State<AppState>, token: AccessToken) -> Response {
    if !token.has_scope("read") {
        return insufficient_scope("read");
    }
    let saved_words = app.saved_words.lock().await;
    Json(json!({ "words": saved_words.join(" "), "timestamp": now_millis() })).into_response()
}

async fn add_word(State(app): State<AppState>, token: AccessToken) -> Response {
    if !token.has_scope("write") {
        return insufficient_scope("write");
    }
    if let Some(word) = token.form.get("word") {
        app.saved_words.lock().await.push(word.clone());
    }
    StatusCode::CREATED.into_response()
}

async fn delete_word(State(app): State<AppState>, token: AccessToken) -> Response {
    if !token.has_scope("delete") {
        return insufficient_scope("delete");
    }
    app.saved_words.lock().await.pop();
    StatusCode::NO_CONTENT.into_response()
}

async fn produce(token: AccessToken) -> Response {
    let mut produce = json!({ "fruit": [], "veggies": [], "meats": [] });
    if token.has_scope("fruit") {
        produce["fruit"] = json!(["apple", "banana", "kiwi"]);
    }
    if token.has_scope("veggies") {
        produce["veggies"] = json!(["lettuce", "onion", "potato"]);
    }
    if token.has_scope("meats") {
        produce["meats"] = json!(["bacon", "steak", "chicken breast"]);
    }
    println!("Sending produce: {produce}");
    Json(produce).into_response()
}

async fn favorites(token: AccessToken) -> Response {
    let alice_favorites = json!({
        "movies": ["The Multidmensional Vector", "Space Fights", "Jewelry Boss"],
        "foods": ["bacon", "pizza", "bacon pizza"],
        "music": ["techno", "industrial", "alternative"],
    });
    let bob_favorites = json!({
        "movies": ["An Unrequited Love", "Several Shades of Turquoise", "Think Of The Children"],
        "foods": ["bacon", "kale", "gravel"],
        "music": ["baroque", "ukulele", "baroque ukulele"],
    });

    // The authorization server recorded who approved this token.
    let response = match token.record["user"].as_str() {
        Some("alice") => json!({ "user": "Alice", "favorites": alice_favorites }),
        Some("bob") => json!({ "user": "Bob", "favorites": bob_favorites }),
        _ => json!({ "user": "Unknown", "favorites": { "movies": [], "foods": [], "music": [] } }),
    };
    Json(response).into_response()
}

#[tokio::main]
async fn main() {
    oauth_common::set_views_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/templates"));

    let state = AppState { db: Db::shared(), saved_words: Arc::default() };

    let app = Router::new()
        .route("/", get(|| async { render("index", context! {}) }))
        .route("/resource", post(resource))
        .route("/words", get(get_words).post(add_word).delete(delete_word))
        .route("/produce", get(produce))
        .route("/favorites", get(favorites))
        .layer(CorsLayer::permissive()) // `app.use(cors())`
        .with_state(state);

    oauth_common::serve(app, 9002, "OAuth Resource Server").await;
}
