//! Chapter 5: the authorization server. These are regression tests: later
//! exercises must keep them passing.

use acceptance::*;

fn code_request(scope: &str) -> [(&'static str, &str); 5] {
    [
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", scope),
        ("state", "s1"),
    ]
}

#[test]
fn unknown_client_or_redirect_uri_is_never_redirected_to() {
    let unknown = authorize(&[("response_type", "code"), ("client_id", "nobody"), ("redirect_uri", "http://evil.example/")]);
    assert!(!unknown.is_redirect(), "must not redirect for an unknown client");

    let evil = authorize(&[("response_type", "code"), ("client_id", CLIENT_ID), ("redirect_uri", "http://evil.example/")]);
    assert!(!evil.is_redirect(), "must not redirect to an unregistered redirect URI");
}

#[test]
fn deny_sends_access_denied() {
    let reqid = approval_page(&code_request("foo"));
    let reply = deny(&reqid);
    let back = query_params(reply.location());
    assert_eq!(back.get("error").map(String::as_str), Some("access_denied"));
    assert!(!back.contains_key("code"));
}

#[test]
fn a_scope_the_client_may_not_have_gets_no_code() {
    let reply = authorize(&code_request("foo nuclear-launch"));
    if reply.is_redirect() {
        let back = query_params(reply.location());
        assert_eq!(back.get("error").map(String::as_str), Some("invalid_scope"));
        assert!(!back.contains_key("code"));
    } else {
        assert!(!reply.status.is_success() || !reply.body.contains("name=\"reqid\""), "must not show the approval page");
    }
}

#[test]
fn code_flow_issues_tokens() {
    let token = tokens("read write delete", "alice");
    assert!(token["access_token"].is_string());
    assert!(token["refresh_token"].is_string());
    assert!(token["token_type"].as_str().unwrap_or("").eq_ignore_ascii_case("bearer"));
    assert_eq!(scope_set(&token["scope"]), scope_set("read write delete"));
}

#[test]
fn the_token_scope_is_what_the_user_ticked() {
    let reqid = approval_page(&code_request("read write delete"));
    let code = query_params(approve(&reqid, "alice", &["read"]).location())["code"].clone();
    let reply = token_request(&[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT_URI)]);
    assert_eq!(scope_set(&reply.json()["scope"]), scope_set("read"));
}

#[test]
fn a_code_works_only_once() {
    let code = get_code("foo", "alice");
    let form = [("grant_type", "authorization_code"), ("code", code.as_str()), ("redirect_uri", REDIRECT_URI)];
    token_request(&form).assert_status(200);
    let again = token_request(&form);
    again.assert_status(400);
    assert_eq!(error_code(&again), "invalid_grant");
}

#[test]
fn client_authentication() {
    let wrong = token_request_as(CLIENT_ID, "wrong-secret", &[("grant_type", "authorization_code"), ("code", "x")]);
    wrong.assert_status(401);
    assert_eq!(error_code(&wrong), "invalid_client");

    let both = http()
        .post(format!("{AS_URL}/token"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .form(&[("grant_type", "authorization_code"), ("code", "x"), ("client_id", CLIENT_ID), ("client_secret", CLIENT_SECRET)])
        .call();
    both.assert_status(401);
    assert_eq!(error_code(&both), "invalid_client", "two authentication methods at once is an error");
}

#[test]
fn unknown_grant_type() {
    let reply = token_request(&[("grant_type", "magic")]);
    reply.assert_status(400);
    assert_eq!(error_code(&reply), "unsupported_grant_type");
}

#[test]
fn refresh_token_gets_a_working_access_token() {
    let first = tokens("foo bar", "alice");
    let refresh = first["refresh_token"].as_str().unwrap();

    let reply = token_request(&[("grant_type", "refresh_token"), ("refresh_token", refresh)]);
    reply.assert_status(200);
    let second = reply.json();
    assert_ne!(second["access_token"], first["access_token"]);
    assert_eq!(scope_set(&second["scope"]), scope_set("foo bar"));
    get_resource(second["access_token"].as_str().unwrap()).assert_status(200);
}
