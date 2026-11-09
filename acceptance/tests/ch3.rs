//! Chapter 3: the client app gets a token with the authorization code grant
//! and uses it. These are regression tests: later exercises must keep them
//! passing.

use acceptance::*;

#[test]
fn client_logs_in_and_fetches_the_resource() {
    let _turn = client_app_lock();
    let alice = browser();

    client_login(&alice, "alice", None);
    assert!(client_shown_token(&alice).is_some(), "the client should show an access token after logging in");

    let data = alice.get(format!("{CLIENT_URL}/fetch_resource")).call();
    data.assert_status(200);
    assert!(data.body.contains("This data has been protected by OAuth 2.0"), "{}", data.body);
}

#[test]
fn client_ignores_a_callback_with_the_wrong_state() {
    let _turn = client_app_lock();
    let alice = browser();
    client_login(&alice, "alice", None);
    let before = client_shown_token(&alice);

    let forged = alice.get(format!("{CLIENT_URL}/callback?code=attacker-code&state=forged")).call();

    assert!(!forged.status.is_success() || forged.body.contains("rror"), "a forged callback must be refused");
    assert_eq!(client_shown_token(&alice), before, "a forged callback must not change the client's token");
}
