//! Exercise 11-5: token revocation and refresh token rotation. Spec: `exercises/ch11-ex5.md`.

use acceptance::*;

fn revoke_as(id: &str, secret: &str, form: &[(&str, &str)]) -> Reply {
    http().post(format!("{AS_URL}/revoke")).basic_auth(id, Some(secret)).form(form).call()
}

fn revoke(token: &str) -> Reply {
    revoke_as(CLIENT_ID, CLIENT_SECRET, &[("token", token)])
}

fn refresh(refresh_token: &str) -> Reply {
    token_request(&[("grant_type", "refresh_token"), ("refresh_token", refresh_token)])
}

#[track_caller]
fn assert_dead_refresh_token(refresh_token: &str, what: &str) {
    let reply = refresh(refresh_token);
    assert_eq!(reply.status.as_u16(), 400, "{what}: the refresh token should be dead: {}", reply.body);
    assert_eq!(error_code(&reply), "invalid_grant", "{what}");
}

#[track_caller]
fn assert_dead_access_token(access_token: &str, what: &str) {
    let reply = get_resource(access_token);
    assert_eq!(reply.status.as_u16(), 401, "{what}: the access token should be dead: {}", reply.body);
}

fn field(tokens: &serde_json::Value, name: &str) -> String {
    tokens[name].as_str().unwrap_or_else(|| panic!("no {name} in {tokens}")).to_string()
}

#[test]
fn r1_only_clients_may_revoke() {
    let access_token = access_token("foo", "alice");
    let anonymous = http().post(format!("{AS_URL}/revoke")).form(&[("token", access_token.as_str())]).call();
    assert_eq!(anonymous.status.as_u16(), 401, "no credentials");
    let wrong = revoke_as(CLIENT_ID, "not-the-secret", &[("token", &access_token)]);
    assert_eq!(wrong.status.as_u16(), 401, "the wrong secret");
    assert_eq!(error_code(&wrong), "invalid_client");

    get_resource(&access_token).assert_status(200);
}

#[test]
fn r1_unknown_tokens_are_not_an_error() {
    revoke("not-a-token").assert_status(200);
    revoke(&unique("never-issued")).assert_status(200);
}

#[test]
fn r2_revoking_an_access_token() {
    let tokens = tokens("foo", "alice");
    let (access_token, refresh_token) = (field(&tokens, "access_token"), field(&tokens, "refresh_token"));

    revoke(&access_token).assert_status(200);
    assert_dead_access_token(&access_token, "after revoking it");
    refresh(&refresh_token).assert_status(200);
}

#[test]
fn r2_revoking_a_refresh_token_revokes_its_grant() {
    let tokens = tokens("foo", "alice");
    let (access_token, refresh_token) = (field(&tokens, "access_token"), field(&tokens, "refresh_token"));

    revoke_as(CLIENT_ID, CLIENT_SECRET, &[("token", &refresh_token), ("token_type_hint", "refresh_token")])
        .assert_status(200);
    assert_dead_refresh_token(&refresh_token, "after revoking it");
    assert_dead_access_token(&access_token, "its refresh token was revoked");
}

#[test]
fn r2_a_wrong_hint_is_only_a_hint() {
    let tokens = tokens("foo", "alice");
    let refresh_token = field(&tokens, "refresh_token");
    revoke_as(CLIENT_ID, CLIENT_SECRET, &[("token", &refresh_token), ("token_type_hint", "access_token")])
        .assert_status(200);
    assert_dead_refresh_token(&refresh_token, "revoked with the hint access_token");
}

#[test]
fn r2_only_your_own_tokens() {
    let tokens = tokens("foo", "alice");
    let (access_token, refresh_token) = (field(&tokens, "access_token"), field(&tokens, "refresh_token"));

    for token in [&access_token, &refresh_token] {
        let reply = revoke_as("oauth-client-service", "oauth-client-secret-service", &[("token", token)]);
        assert_eq!(reply.status.as_u16(), 400, "another client's token: {}", reply.body);
        assert_eq!(error_code(&reply), "invalid_grant");
    }
    get_resource(&access_token).assert_status(200);
    refresh(&refresh_token).assert_status(200);
}

#[test]
fn r3_refresh_tokens_rotate() {
    let first = tokens("foo", "alice");
    let first_refresh = field(&first, "refresh_token");

    let second = refresh(&first_refresh);
    second.assert_status(200);
    let second_refresh = field(&second.json(), "refresh_token");
    assert_ne!(second_refresh, first_refresh, "a refresh hands out a new refresh token");

    let third = refresh(&second_refresh);
    third.assert_status(200);
    assert_ne!(field(&third.json(), "refresh_token"), second_refresh);
}

#[test]
fn r3_a_reused_refresh_token_revokes_the_grant() {
    let first = tokens("foo", "alice");
    let first_refresh = field(&first, "refresh_token");
    let second = refresh(&first_refresh).json();
    let (second_access, second_refresh) = (field(&second, "access_token"), field(&second, "refresh_token"));

    // someone uses the old one: either the client is confused, or it was stolen
    assert_dead_refresh_token(&first_refresh, "a used refresh token");

    assert_dead_refresh_token(&second_refresh, "the reuse should have revoked the whole grant");
    assert_dead_access_token(&second_access, "the reuse should have revoked the whole grant");
    assert_dead_access_token(&field(&first, "access_token"), "the reuse should have revoked the whole grant");
}

#[test]
fn r4_the_client_can_revoke() {
    let _turn = client_app_lock();
    let alice = browser();
    client_login(&alice, "alice", None).assert_status(303);
    let access_token = client_shown_token(&alice).expect("the client should show a token after logging in");

    let reply = alice.post(format!("{CLIENT_URL}/revoke")).call();
    assert_eq!(reply.status.as_u16(), 303, "revoking should send the browser back home: {}", reply.body);
    assert_eq!(reply.location(), "/");
    assert_eq!(client_shown_token(&alice), None, "the client should forget its tokens");
    assert_dead_access_token(&access_token, "the client revoked it");
}

// r5_the_client_keeps_the_rotated_refresh_token lived here. From 12-1 on, the
// web client has its own registration, so a test can't revoke its tokens for
// it. r8 in ch12_ex1.rs checks the same thing through the client's Refresh
// button.
