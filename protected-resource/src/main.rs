//! The OAuth protected resource (http://localhost:9002).
//!
//! An API that only answers requests carrying a valid access token issued by
//! the authorization server. You work on this in chapter 4.
//!
//! Run it with:  cargo run -p protected-resource

use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use oauth_common::{Db, context, parse_form, render};
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;

/// Looks for an access token in (1) the `Authorization: Bearer` header,
/// (2) the form body, or (3) the query string, then checks it against the
/// database the authorization server writes to. Returns the stored token
/// record (with its `client_id`, `scope`, ...) if it is valid.
///
/// In the JS this is Express middleware (`getAccessToken`). Here it's a plain
/// function the handlers call.
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

async fn resource(
    State(db): State<Db>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: String,
) -> Response {
    let form = parse_form(&body);
    match get_access_token(&db, &headers, &query, &form) {
        Some(_token) => Json(json!({
            "name": "Protected Resource",
            "description": "This data has been protected by OAuth 2.0"
        }))
        .into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

#[tokio::main]
async fn main() {
    oauth_common::set_views_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/templates"));

    let app = Router::new()
        .route("/", get(|| async { render("index", context! {}) }))
        .route("/resource", post(resource))
        .layer(CorsLayer::permissive()) // `app.use(cors())`
        .with_state(Db::shared());

    oauth_common::serve(app, 9002, "OAuth Resource Server").await;
}
