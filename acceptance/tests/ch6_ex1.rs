//! Exercise 6-1: the implicit grant. Spec: `exercises/ch6-ex1.md`.

use acceptance::*;

const IMPLICIT_ID: &str = "oauth-client-implicit";
const IMPLICIT_REDIRECT: &str = "http://localhost:9000/implicit";

fn implicit_request(scope: &str) -> [(&'static str, &str); 5] {
    [
        ("response_type", "token"),
        ("client_id", IMPLICIT_ID),
        ("redirect_uri", IMPLICIT_REDIRECT),
        ("scope", scope),
        ("state", "st-123"),
    ]
}

/// Runs the implicit flow as alice and returns where the browser is sent.
fn implicit_redirect(scope: &str) -> String {
    let reqid = approval_page(&implicit_request(scope));
    let scopes: Vec<&str> = scope.split_whitespace().collect();
    approve(&reqid, "alice", &scopes).location().to_string()
}

#[track_caller]
fn assert_back_at(location: &str, redirect_uri: &str) {
    assert_eq!(without_query(location), redirect_uri, "redirected to the wrong place: {location}");
}

#[test]
fn r10_the_token_comes_back_in_the_fragment() {
    let location = implicit_redirect("foo bar");
    assert_back_at(&location, IMPLICIT_REDIRECT);

    let response = fragment_params(&location);
    assert!(response.get("access_token").is_some_and(|t| !t.is_empty()), "no access_token in {location}");
    assert!(response["token_type"].eq_ignore_ascii_case("bearer"), "token_type was {}", response["token_type"]);
    assert_eq!(scope_set(response["scope"].as_str()), scope_set("foo bar"));
    assert_eq!(response.get("state").map(String::as_str), Some("st-123"));
}

#[test]
fn r11_no_refresh_token_no_code_no_query() {
    let location = implicit_redirect("foo");
    let response = fragment_params(&location);
    assert!(!response.contains_key("refresh_token"), "the implicit grant must not issue a refresh token");
    assert!(!response.contains_key("code"));
    assert!(query_params(&location).is_empty(), "nothing goes in the query: {location}");
}

#[test]
fn r9_the_token_works_and_knows_the_user() {
    let token = fragment_params(&implicit_redirect("foo"))["access_token"].clone();
    get_resource(&token).assert_status(200);

    let favorites = http().get(format!("{RS_URL}/favorites")).bearer_auth(&token).call();
    assert_eq!(favorites.json()["user"], "Alice", "the token should record who approved it");
}

#[test]
fn r7_r8_deny_puts_the_error_and_state_in_the_fragment() {
    let reqid = approval_page(&implicit_request("foo"));
    let location = deny(&reqid).location().to_string();
    assert_back_at(&location, IMPLICIT_REDIRECT);
    let response = fragment_params(&location);
    assert_eq!(response.get("error").map(String::as_str), Some("access_denied"));
    assert_eq!(response.get("state").map(String::as_str), Some("st-123"));
    assert!(query_params(&location).is_empty(), "errors for response_type=token go in the fragment: {location}");
}

#[test]
fn r6_r7_invalid_scope_goes_in_the_fragment() {
    let reply = authorize(&implicit_request("foo write"));
    if !reply.is_redirect() {
        // From 9-2 on, the server shows an error page here instead.
        reply.assert_status(400);
        return;
    }
    let response = fragment_params(reply.location());
    assert_eq!(response.get("error").map(String::as_str), Some("invalid_scope"));
    assert_eq!(response.get("state").map(String::as_str), Some("st-123"));
}

#[test]
fn r5_the_implicit_client_cannot_ask_for_a_code() {
    let reply = authorize(&[
        ("response_type", "code"),
        ("client_id", IMPLICIT_ID),
        ("redirect_uri", IMPLICIT_REDIRECT),
        ("state", "st-5"),
    ]);
    let back = query_params(reply.location());
    assert_eq!(back.get("error").map(String::as_str), Some("unauthorized_client"));
    assert_eq!(back.get("state").map(String::as_str), Some("st-5"));
}

#[test]
fn r5_r7_the_code_client_cannot_ask_for_a_token() {
    let reply = authorize(&[
        ("response_type", "token"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("state", "st-6"),
    ]);
    assert_back_at(reply.location(), REDIRECT_URI);
    let response = fragment_params(reply.location());
    assert_eq!(response.get("error").map(String::as_str), Some("unauthorized_client"));
    assert_eq!(response.get("state").map(String::as_str), Some("st-6"));
}

#[test]
fn r4_unknown_or_missing_response_type() {
    for response_type in [Some("banana"), None] {
        let mut params = vec![("client_id", CLIENT_ID), ("redirect_uri", REDIRECT_URI), ("state", "st-4")];
        if let Some(rt) = response_type {
            params.push(("response_type", rt));
        }
        let reply = authorize(&params);
        let back = query_params(reply.location());
        assert_eq!(back.get("error").map(String::as_str), Some("unsupported_response_type"), "for {response_type:?}");
        assert_eq!(back.get("state").map(String::as_str), Some("st-4"));
    }
}

#[test]
fn r8_code_flow_errors_carry_state_too() {
    let reqid = approval_page(&[
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "foo"),
        ("state", "st-8"),
    ]);
    let back = query_params(deny(&reqid).location());
    assert_eq!(back.get("error").map(String::as_str), Some("access_denied"));
    assert_eq!(back.get("state").map(String::as_str), Some("st-8"));
}

#[test]
fn r3_unknown_client_or_redirect_uri_is_a_400_page() {
    let unknown = authorize(&[("response_type", "token"), ("client_id", "nobody"), ("redirect_uri", IMPLICIT_REDIRECT)]);
    assert!(!unknown.is_redirect());
    unknown.assert_status(400);

    // A redirect URI registered for a *different* client doesn't count.
    let wrong = authorize(&[("response_type", "token"), ("client_id", IMPLICIT_ID), ("redirect_uri", REDIRECT_URI)]);
    assert!(!wrong.is_redirect());
    wrong.assert_status(400);
}

#[test]
fn r12_a_public_client_that_sends_a_secret_is_refused() {
    let basic = token_request_as(IMPLICIT_ID, "guess", &[("grant_type", "authorization_code"), ("code", "x")]);
    basic.assert_status(401);
    assert_eq!(error_code(&basic), "invalid_client");

    let body = token_request_form(&[
        ("client_id", IMPLICIT_ID),
        ("client_secret", "guess"),
        ("grant_type", "authorization_code"),
        ("code", "x"),
    ]);
    body.assert_status(401);
    assert_eq!(error_code(&body), "invalid_client");
}

#[test]
fn r13_the_implicit_client_may_not_use_the_token_endpoint() {
    for grant_type in ["authorization_code", "refresh_token"] {
        let reply = token_request_form(&[("client_id", IMPLICIT_ID), ("grant_type", grant_type), ("code", "x")]);
        reply.assert_status(400);
        assert_eq!(error_code(&reply), "unauthorized_client", "for grant_type={grant_type}");
    }
}

#[test]
fn r13_an_unknown_grant_type_is_still_unsupported() {
    let reply = token_request_form(&[("client_id", IMPLICIT_ID), ("grant_type", "magic")]);
    reply.assert_status(400);
    assert_eq!(error_code(&reply), "unsupported_grant_type");
}
