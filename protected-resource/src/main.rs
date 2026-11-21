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
    extract::{FromRequest, Query, Request, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{self, WWW_AUTHENTICATE},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use oauth_common::{Db, context, param, parse_form, render};
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

/// Looks for an access token in (1) the `Authorization: Bearer` header or
/// (2) the form body, never the query string (R4), then checks it against
/// the database the authorization server writes to. Returns the stored token
/// record (with its `client_id`, `scope`, ...) if it is valid, or the reason
/// the request is refused.
fn get_access_token(
    db: &Db,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Result<Value, AuthError> {
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());

    let in_token = if let Some(auth) = auth.filter(|a| a.to_lowercase().starts_with("bearer ")) {
        // A token in both places is an invalid request (R6).
        if form.contains_key("access_token") {
            return Err(AuthError::InvalidRequest);
        }
        Some(auth["bearer ".len()..].to_string())
    } else {
        // Not in the header, so check the form body. `form` is empty unless
        // the request really was a form (see `AccessToken::from_request`).
        form.get("access_token").cloned()
    };

    println!(
        "Incoming token: {}",
        in_token.as_deref().unwrap_or("(none)")
    );
    let Some(in_token) = in_token else {
        return Err(AuthError::NoToken);
    };

    let found = db.find_one(|doc| doc["access_token"] == in_token.as_str());
    match &found {
        Some(token) => {
            println!("We found a matching token: {in_token}");
            Ok(token.clone())
        }
        None => {
            println!("No matching token was found.");
            Err(AuthError::InvalidToken)
        }
    }
}

/// A valid access token that came with the request.
///
/// Putting `token: AccessToken` in a handler's arguments means "this endpoint
/// needs a valid token". Without one, axum answers with the matching
/// [`AuthError`] (400 or 401) and never calls the handler. This replaces the
/// book's `getAccessToken` and `requireAccessToken` Express middleware.
struct AccessToken {
    /// The token's record from the database: `client_id`, `scope`, ...
    record: Value,
    /// The request's form body, empty unless the request was a form. We had
    /// to read the body to look for a token in it, so handlers that need
    /// other form fields get them from here.
    form: HashMap<String, String>,
}

enum AuthError {
    NoToken,
    InvalidToken,
    InvalidRequest,
    InsufficientScope(&'static str),
}
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, challenge) = match self {
            AuthError::NoToken => (
                StatusCode::UNAUTHORIZED,
                r#"Bearer realm="localhost:9002""#.to_string(),
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                r#"Bearer realm="localhost:9002", error="invalid_token""#.to_string(),
            ),
            AuthError::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                r#"Bearer realm="localhost:9002", error="invalid_request""#.to_string(),
            ),
            AuthError::InsufficientScope(scope) => (
                StatusCode::FORBIDDEN,
                format!(
                    r#"Bearer realm="localhost:9002", error="insufficient_scope", scope="{scope}""#
                ),
            ),
        };
        (status, [(WWW_AUTHENTICATE, challenge)]).into_response()
    }
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
    type Rejection = AuthError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();

        // A body only counts as a form for a non-GET request whose media type
        // is `application/x-www-form-urlencoded`, parameters such as
        // `; charset=UTF-8` aside (R5). Any other body is never read, which
        // also saves reading up to 64 KiB for every GET.
        let is_form = parts.method != Method::GET
            && parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .and_then(|ct| ct.split(';').next())
                .is_some_and(|mt| {
                    mt.trim()
                        .eq_ignore_ascii_case("application/x-www-form-urlencoded")
                });

        let form = if is_form {
            let body = axum::body::to_bytes(body, 64 * 1024)
                .await
                .map_err(|_| AuthError::InvalidRequest)?;
            parse_form(&String::from_utf8_lossy(&body))
        } else {
            HashMap::new()
        };

        get_access_token(&state.db, &parts.headers, &form)
            .map(|record| AccessToken { record, form })
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// 403 Forbidden, telling the client which scope it was missing.
fn insufficient_scope(scope: &'static str) -> Response {
    AuthError::InsufficientScope(scope).into_response()
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

// ---------------------------------------------------------------------------
// Hello World API (chapter 8)
// ---------------------------------------------------------------------------

/// Greets you in the language you ask for: `/helloWorld?language=en`.
///
/// Always answers JSON (R1), and never echoes an unknown language back, so
/// there's no page for a reflected script to run in (R2).
async fn hello_world(
    Query(query): Query<HashMap<String, String>>,
    _token: AccessToken,
) -> Response {
    let greeting = match param(&query, "language") {
        "en" => "Hello World",
        "de" => "Hallo Welt",
        "it" => "Ciao Mondo",
        "fr" => "Bonjour monde",
        "es" => "Hola mundo",
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_language"})),
            )
                .into_response();
        }
    };
    Json(json! ({"greeting": greeting})).into_response()
}

#[tokio::main]
async fn main() {
    oauth_common::set_views_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/templates"));

    let state = AppState {
        db: Db::shared(),
        saved_words: Arc::default(),
    };

    let app = Router::new()
        .route("/", get(|| async { render("index", context! {}) }))
        .route("/resource", post(resource))
        .route("/words", get(get_words).post(add_word).delete(delete_word))
        .route("/produce", get(produce))
        .route("/favorites", get(favorites))
        .route("/helloWorld", get(hello_world))
        .layer(CorsLayer::permissive()) // `app.use(cors())`
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .with_state(state);

    oauth_common::serve(app, 9002, "OAuth Resource Server").await;
}
