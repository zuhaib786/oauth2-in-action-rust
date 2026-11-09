//! Exercise 9-2: not an open redirector. Spec: `exercises/ch9-ex2.md`.

use acceptance::*;

#[track_caller]
fn assert_error_page(reply: &Reply, what: &str) {
    assert!(!reply.is_redirect(), "{what}: must not redirect, but went to {}", reply.location());
    assert_eq!(reply.status.as_u16(), 400, "{what}: expected the error page with 400");
}

#[test]
fn r1_a_forbidden_scope_is_not_redirected() {
    let code = authorize(&[
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "foo nuclear-launch"),
        ("state", "s"),
    ]);
    assert_error_page(&code, "response_type=code");

    let token = authorize(&[
        ("response_type", "token"),
        ("client_id", "oauth-client-implicit"),
        ("redirect_uri", "http://localhost:9000/implicit"),
        ("scope", "foo write"),
        ("state", "s"),
    ]);
    assert_error_page(&token, "response_type=token");
}

#[test]
fn r2_approve_cannot_add_scopes_that_were_not_requested() {
    let request = [
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "read"),
        ("state", "s"),
    ];
    let reqid = approval_page(&request);
    let reply = approve(&reqid, "alice", &["read", "delete"]);
    assert_error_page(&reply, "approving delete when only read was requested");

    // approving what was asked for, or less, still works
    let reqid = approval_page(&request);
    assert!(query_params(approve(&reqid, "alice", &["read"]).location()).contains_key("code"));
    let reqid = approval_page(&request);
    assert!(query_params(approve(&reqid, "alice", &[]).location()).contains_key("code"));
}

#[test]
fn r3_repeated_parameters_at_authorize() {
    let request = [
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "foo"),
        ("state", "s"),
    ];
    for repeated in [
        ("client_id", "oauth-client-implicit"),
        ("redirect_uri", REDIRECT_URI),
        ("state", "other"),
        ("scope", "bar"),
        ("response_type", "code"),
    ] {
        let mut params = request.to_vec();
        params.push(repeated);
        assert_error_page(&authorize(&params), &format!("repeating {}", repeated.0));
    }
    // without the repeat, the same request is fine
    authorize(&request).assert_status(200);
}

#[test]
fn r4_repeated_parameters_at_the_token_endpoint() {
    let code = get_code("foo", "alice");
    let reply = token_request(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("code", "another-code"),
        ("redirect_uri", REDIRECT_URI),
    ]);
    reply.assert_status(400);
    assert_eq!(error_code(&reply), "invalid_request");

    let reply = token_request(&[("grant_type", "client_credentials"), ("grant_type", "refresh_token")]);
    reply.assert_status(400);
    assert_eq!(error_code(&reply), "invalid_request");
}
