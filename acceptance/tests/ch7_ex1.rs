//! Exercise 7-1: hardening the client. Spec: `exercises/ch7-ex1.md`.

use acceptance::*;

#[test]
fn r1_the_client_hands_out_a_safe_session_cookie() {
    let _turn = client_app_lock();
    let reply = browser().get(format!("{CLIENT_URL}/authorize")).call();
    let cookie = reply
        .header("set-cookie")
        .unwrap_or_else(|| panic!("/authorize should set a session cookie, headers: {:?}", reply.headers));

    let attributes: Vec<String> = cookie.split(';').map(|a| a.trim().to_ascii_lowercase()).collect();
    let (name, value) = cookie.split(';').next().unwrap_or("").split_once('=').unwrap_or(("", ""));
    assert_eq!(name.trim(), "session", "the cookie should be called session: {cookie}");
    assert!(value.len() >= 22, "the session id should have at least 128 bits of randomness: {cookie}");
    assert!(attributes.contains(&"httponly".to_string()), "HttpOnly is missing: {cookie}");
    assert!(attributes.contains(&"samesite=lax".to_string()), "SameSite=Lax is missing: {cookie}");
    assert!(attributes.contains(&"path=/".to_string()), "Path=/ is missing: {cookie}");
}

#[test]
fn r1_a_made_up_session_id_is_replaced() {
    let _turn = client_app_lock();
    let reply = http()
        .get(format!("{CLIENT_URL}/authorize"))
        .header("cookie", "session=chosen-by-the-attacker")
        .call();
    let cookie = reply.header("set-cookie").unwrap_or("");
    assert!(!cookie.is_empty(), "an unknown session id must be replaced with a new cookie");
    assert!(!cookie.contains("chosen-by-the-attacker"));
}

#[test]
fn r2_two_browsers_log_in_at_the_same_time() {
    let _turn = client_app_lock();
    let (alice, bob) = (browser(), browser());

    // both start, then both finish: with one global state, alice's would fail
    let alice_to_as = client_authorize_url(&alice);
    let bob_to_as = client_authorize_url(&bob);
    let alice_back = approve(&reqid(&alice.get(&alice_to_as).call().body), "alice", &["foo"]);
    let bob_back = approve(&reqid(&bob.get(&bob_to_as).call().body), "bob", &["foo"]);

    alice.get(alice_back.location()).call().assert_status(303);
    bob.get(bob_back.location()).call().assert_status(303);

    let alice_token = client_shown_token(&alice).expect("alice should be logged in");
    let bob_token = client_shown_token(&bob).expect("bob should be logged in");
    assert_ne!(alice_token, bob_token, "each browser has its own token");
}

#[test]
fn r2_a_new_browser_sees_nobody_elses_token() {
    let _turn = client_app_lock();
    let alice = browser();
    client_login(&alice, "alice", None);
    assert!(client_shown_token(&alice).is_some());

    let stranger = browser();
    assert_eq!(client_shown_token(&stranger), None, "a new browser must not see alice's token");
    let data = stranger.get(format!("{CLIENT_URL}/fetch_resource")).call();
    assert!(!data.body.contains("Protected Resource"), "a new browser must not get alice's data");
}

#[test]
fn r3_r5_a_replayed_callback_is_refused() {
    let _turn = client_app_lock();
    let alice = browser();
    let callback = client_start_login(&alice, "alice", None);
    alice.get(&callback).call().assert_status(303);
    let token = client_shown_token(&alice);

    alice.get(&callback).call().assert_status(400);
    assert_eq!(client_shown_token(&alice), token, "a refused callback must not change the tokens");
}

#[test]
fn r4_a_callback_with_no_login_pending_is_refused() {
    let _turn = client_app_lock();
    browser().get(format!("{CLIENT_URL}/callback?code=attackers-code")).call().assert_status(400);

    let alice = browser();
    client_login(&alice, "alice", None);
    alice.get(format!("{CLIENT_URL}/callback?code=attackers-code")).call().assert_status(400);
}

#[test]
fn r4_r5_another_browsers_callback_is_refused_and_its_code_left_alone() {
    let _turn = client_app_lock();
    let (attacker, victim) = (browser(), browser());

    // The attacker gets a real callback URL for their own login...
    let attackers_callback = client_start_login(&attacker, "bob", None);
    // ...and gets the victim's browser to load it while the victim is logging in.
    let _ = client_authorize_url(&victim);
    victim.get(&attackers_callback).call().assert_status(400);
    assert_eq!(client_shown_token(&victim), None);

    // The client must not have spent the code at the token endpoint: it still works for its owner.
    attacker.get(&attackers_callback).call().assert_status(303);
    assert!(client_shown_token(&attacker).is_some());
}

#[test]
fn r6_r7_a_successful_callback_redirects_home_without_a_referrer() {
    let _turn = client_app_lock();
    let alice = browser();
    let reply = client_login(&alice, "alice", None);
    reply.assert_status(303);
    assert_eq!(reply.location(), "/");
    assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
}

#[test]
fn r7_every_page_has_no_referrer() {
    let _turn = client_app_lock();
    let alice = browser();
    for path in ["/", "/callback?code=x&state=y", "/words"] {
        let reply = alice.get(format!("{CLIENT_URL}{path}")).call();
        assert_eq!(reply.header("referrer-policy"), Some("no-referrer"), "on {path}");
    }
}

#[test]
fn r8_an_error_callback_consumes_the_state() {
    let _turn = client_app_lock();
    let alice = browser();
    let to_as = client_authorize_url(&alice);
    let denied = deny(&reqid(&alice.get(&to_as).call().body));
    let state = query_params(denied.location())["state"].clone();

    alice.get(denied.location()).call().assert_status(400);
    // the state is gone now, so even a "good" callback with it fails
    alice
        .get(format!("{CLIENT_URL}/callback"))
        .query(&[("code", "x"), ("state", state.as_str())])
        .call()
        .assert_status(400);
}
