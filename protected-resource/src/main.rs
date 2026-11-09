//! The OAuth protected resource (http://localhost:9002).
//!
//! An API that only answers requests carrying a valid access token issued by
//! the authorization server.
//!
//! EXERCISE 4-1 (book chapter 4): right now anyone gets the data, token or
//! not. Fill in `get_access_token` and use it in `resource`.
//! Compare with the solution:  git diff ch4-ex1-done -- protected-resource
//!
//! Run it with:  cargo run -p protected-resource

// Silences "unused variable/import" warnings until you've written your code.
// Delete this line when you're done, to see if anything is left unused.
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
    /*
     * TODO: Scan for an access token on the incoming request.
     *
     * Hints:
     *   - look in this order: the Authorization header ("Bearer <token>",
     *     any capitalization of "bearer"), then form.get("access_token"),
     *     then query.get("access_token")
     *   - headers.get("authorization").and_then(|v| v.to_str().ok()) gives
     *     an Option<&str> with the header's text
     *   - db.find_one(|doc| doc["access_token"] == token) finds the stored
     *     token record (token must be a &str here)
     *   - println! what you find; the logs help a lot when debugging
     */

    let access_token = match get_header(headers, "authorization") {
        Some(s) => {
            if s.to_lowercase().starts_with("bearer ") {
                &s[7..]
            } else {
                return None;
            }
        }
        None => {
            if let Some(token) = form.get("access_token") {
                token
            } else if let Some(token) = query.get("access_token") {
                token
            } else {
                return None;
            }
        }
    };
    println!("Found access_token: {}", access_token);
    db.find_one(|doc| doc["access_token"] == access_token)
}

fn get_header<'a>(headers: &'a HeaderMap, header: &str) -> Option<&'a str> {
    headers.get(header).and_then(|v| v.to_str().ok())
}

async fn resource(
    State(db): State<Db>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: String,
) -> Response {
    let form = parse_form(&body);

    /*
     * TODO: Call get_access_token. Only send the resource if a valid token
     * was found. Otherwise answer with StatusCode::UNAUTHORIZED.into_response()
     */
    let access_token = get_access_token(&db, &headers, &query, &form);
    if access_token.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    Json(json!({
        "name": "Protected Resource",
        "description": "This data has been protected by OAuth 2.0"
    }))
    .into_response()
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
