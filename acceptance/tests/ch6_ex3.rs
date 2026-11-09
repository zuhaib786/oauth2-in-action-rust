//! Exercise 6-3: the resource owner password grant. Spec: `exercises/ch6-ex3.md`.

use acceptance::*;

const TRUSTED_ID: &str = "oauth-client-trusted";
const TRUSTED_SECRET: &str = "oauth-client-secret-trusted";

fn password_grant(username: &str, password: &str, scope: Option<&str>) -> Reply {
    let mut form = vec![("grant_type", "password"), ("username", username), ("password", password)];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }
    token_request_as(TRUSTED_ID, TRUSTED_SECRET, &form)
}

#[test]
fn r5_r6_the_right_password_gets_tokens() {
    let reply = password_grant("alice", "password", Some("read"));
    reply.assert_status(200);
    let token = reply.json();
    assert!(token["access_token"].is_string());
    assert!(token["refresh_token"].is_string(), "the client is registered for refresh_token, so it gets one");
    assert!(token["token_type"].as_str().unwrap_or("").eq_ignore_ascii_case("bearer"));
    assert_eq!(scope_set(&token["scope"]), scope_set("read"));
}

#[test]
fn r6_the_token_belongs_to_the_user() {
    let reply = password_grant("bob", "this is my secret password", None);
    reply.assert_status(200);
    let token = reply.json()["access_token"].as_str().unwrap().to_string();
    let favorites = http().get(format!("{RS_URL}/favorites")).bearer_auth(&token).call();
    assert_eq!(favorites.json()["user"], "Bob");
}

#[test]
fn r5_no_scope_means_every_registered_scope() {
    let reply = password_grant("alice", "password", None);
    reply.assert_status(200);
    assert_eq!(scope_set(&reply.json()["scope"]), scope_set("foo bar read write"));
}

#[test]
fn r5_a_scope_the_client_may_not_have_is_refused() {
    let reply = password_grant("alice", "password", Some("read delete"));
    reply.assert_status(400);
    assert_eq!(error_code(&reply), "invalid_scope");
}

#[test]
fn r6_the_refresh_token_works() {
    let refresh = password_grant("alice", "password", Some("foo")).json()["refresh_token"].as_str().unwrap().to_string();
    let reply = token_request_as(TRUSTED_ID, TRUSTED_SECRET, &[("grant_type", "refresh_token"), ("refresh_token", &refresh)]);
    reply.assert_status(200);
    get_resource(reply.json()["access_token"].as_str().unwrap()).assert_status(200);
}

#[test]
fn r7_wrong_password_and_unknown_user_look_the_same() {
    let wrong_password = password_grant("bob", "not bob's password", None);
    let unknown_user = password_grant(&unique("nobody"), "whatever", None);

    wrong_password.assert_status(400);
    assert_eq!(error_code(&wrong_password), "invalid_grant");
    assert_eq!(unknown_user.status, wrong_password.status);
    assert_eq!(unknown_user.json(), wrong_password.json(), "the bodies must not tell the two apart");

    // and a right password still works (this also resets bob's failure count)
    password_grant("bob", "this is my secret password", None).assert_status(200);
}

#[test]
fn r9_five_failures_lock_the_user_out() {
    for attempt in 1..=5 {
        let reply = password_grant("carol", "guess", None);
        assert_eq!(error_code(&reply), "invalid_grant", "attempt {attempt}");
    }
    let right_password = password_grant("carol", "correct horse battery staple", None);
    right_password.assert_status(400);
    assert_eq!(error_code(&right_password), "invalid_grant", "carol is locked out, even with the right password");

    // other users aren't affected
    password_grant("alice", "password", None).assert_status(200);
}

#[test]
fn r10_other_clients_are_not_registered_for_it() {
    let reply = token_request(&[("grant_type", "password"), ("username", "alice"), ("password", "password")]);
    reply.assert_status(400);
    assert_eq!(error_code(&reply), "unauthorized_client");
}
