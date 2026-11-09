//! Exercise 9-1: authorization codes. Spec: `exercises/ch9-ex1.md`.

use acceptance::*;

fn redeem(code: &str, redirect_uri: Option<&str>) -> Reply {
    let mut form = vec![("grant_type", "authorization_code"), ("code", code)];
    if let Some(uri) = redirect_uri {
        form.push(("redirect_uri", uri));
    }
    token_request(&form)
}

fn refresh(refresh_token: &str) -> Reply {
    token_request(&[("grant_type", "refresh_token"), ("refresh_token", refresh_token)])
}

#[test]
fn r1_the_token_request_must_repeat_the_redirect_uri() {
    let missing = redeem(&get_code("foo", "alice"), None);
    missing.assert_status(400);
    assert_eq!(error_code(&missing), "invalid_grant", "redirect_uri missing at the token endpoint");

    let different = redeem(&get_code("foo", "alice"), Some("http://localhost:9000/somewhere-else"));
    different.assert_status(400);
    assert_eq!(error_code(&different), "invalid_grant", "a different redirect_uri at the token endpoint");

    redeem(&get_code("foo", "alice"), Some(REDIRECT_URI)).assert_status(200);
}

#[test]
fn r3_a_replayed_code_kills_the_tokens_it_produced() {
    let code = get_code("foo", "alice");
    let first = redeem(&code, Some(REDIRECT_URI));
    first.assert_status(200);
    let tokens = first.json();
    let access = tokens["access_token"].as_str().unwrap();
    let refresh_token = tokens["refresh_token"].as_str().unwrap();
    get_resource(access).assert_status(200);

    let replay = redeem(&code, Some(REDIRECT_URI));
    replay.assert_status(400);
    assert_eq!(error_code(&replay), "invalid_grant");

    get_resource(access).assert_status(401);
    let refreshed = refresh(refresh_token);
    refreshed.assert_status(400);
    assert_eq!(error_code(&refreshed), "invalid_grant", "the refresh token from the replayed code must be dead");
}

#[test]
fn r3_tokens_from_refreshing_die_too() {
    let code = get_code("foo", "alice");
    let tokens = redeem(&code, Some(REDIRECT_URI)).json();
    let refreshed = refresh(tokens["refresh_token"].as_str().unwrap()).json();
    let second_access = refreshed["access_token"].as_str().unwrap();
    get_resource(second_access).assert_status(200);

    redeem(&code, Some(REDIRECT_URI)).assert_status(400);
    get_resource(second_access).assert_status(401);
}

#[test]
fn r3_other_codes_tokens_survive() {
    let (stolen, innocent) = (get_code("foo", "alice"), get_code("foo", "alice"));
    redeem(&stolen, Some(REDIRECT_URI)).assert_status(200);
    let innocent_token = redeem(&innocent, Some(REDIRECT_URI)).json()["access_token"].as_str().unwrap().to_string();

    redeem(&stolen, Some(REDIRECT_URI)).assert_status(400);
    get_resource(&innocent_token).assert_status(200);
}

#[test]
fn r4_codes_and_request_ids_cannot_be_guessed() {
    let code = get_code("foo", "alice");
    assert!(code.len() >= 22, "a code of {} characters is too easy to guess: {code}", code.len());

    let reqid = approval_page(&[
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "foo"),
    ]);
    assert!(reqid.len() >= 22, "a reqid of {} characters is too easy to guess: {reqid}", reqid.len());
}

#[test]
fn r5_a_code_only_works_for_its_own_client() {
    let code = get_code("foo", "alice");
    let reply = token_request_form(&[
        ("client_id", "oauth-native-client"),
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
    ]);
    reply.assert_status(400);
    assert_eq!(error_code(&reply), "invalid_grant");
}
