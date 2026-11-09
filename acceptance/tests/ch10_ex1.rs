//! Exercise 10-1: PKCE. Spec: `exercises/ch10-ex1.md`.

use acceptance::*;

const NATIVE_ID: &str = "oauth-native-client";
const NATIVE_REDIRECT: &str = "http://127.0.0.1:54321/callback";

fn redeem(code: &str, verifier: Option<&str>) -> Reply {
    let mut form = vec![("grant_type", "authorization_code"), ("code", code), ("redirect_uri", REDIRECT_URI)];
    if let Some(verifier) = verifier {
        form.push(("code_verifier", verifier));
    }
    token_request(&form)
}

#[track_caller]
fn assert_invalid_grant(reply: &Reply, what: &str) {
    assert_eq!(reply.status.as_u16(), 400, "{what}: {}", reply.body);
    assert_eq!(error_code(reply), "invalid_grant", "{what}");
}

fn code_request<'a>(extra: &[(&'static str, &'a str)]) -> Vec<(&'static str, &'a str)> {
    let mut params = vec![
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "foo"),
        ("state", "st-pkce"),
    ];
    params.extend_from_slice(extra);
    params
}

#[track_caller]
fn assert_invalid_request(reply: &Reply, what: &str) {
    let back = query_params(reply.location());
    assert_eq!(back.get("error").map(String::as_str), Some("invalid_request"), "{what}");
    assert_eq!(back.get("state").map(String::as_str), Some("st-pkce"), "{what}: state comes back too");
}

#[test]
fn r1_r4_s256_works() {
    let (verifier, challenge) = pkce_pair();
    let code = get_code_with(&[("code_challenge", &challenge), ("code_challenge_method", "S256")], "foo", "alice");
    redeem(&code, Some(&verifier)).assert_status(200);
}

#[test]
fn r4_a_wrong_or_missing_verifier_is_refused() {
    let (_, challenge) = pkce_pair();
    let (other_verifier, _) = pkce_pair();
    let pkce = [("code_challenge", challenge.as_str()), ("code_challenge_method", "S256")];

    assert_invalid_grant(&redeem(&get_code_with(&pkce, "foo", "alice"), Some(&other_verifier)), "wrong verifier");
    assert_invalid_grant(&redeem(&get_code_with(&pkce, "foo", "alice"), None), "missing verifier");
}

#[test]
fn r1_only_s256() {
    let (_, challenge) = pkce_pair();
    for (what, extra) in [
        ("method plain", vec![("code_challenge", challenge.as_str()), ("code_challenge_method", "plain")]),
        ("no method (means plain)", vec![("code_challenge", challenge.as_str())]),
        ("a method but no challenge", vec![("code_challenge_method", "S256")]),
        ("an unknown method", vec![("code_challenge", challenge.as_str()), ("code_challenge_method", "S512")]),
    ] {
        assert_invalid_request(&authorize(&code_request(&extra)), what);
    }
}

#[test]
fn r2_the_challenge_must_look_like_s256() {
    for challenge in ["too-short", &"A".repeat(44), "abcdefghijklmnopqrstuvwxyz+/ABCDEFGHIJKLMNO"] {
        let reply = authorize(&code_request(&[("code_challenge", challenge), ("code_challenge_method", "S256")]));
        assert_invalid_request(&reply, &format!("challenge {challenge:?}"));
    }
}

#[test]
fn r3_public_clients_must_use_pkce() {
    let without = authorize(&[
        ("response_type", "code"),
        ("client_id", NATIVE_ID),
        ("redirect_uri", NATIVE_REDIRECT),
        ("scope", "foo"),
        ("state", "st-pkce"),
    ]);
    assert_eq!(without_query(without.location()), NATIVE_REDIRECT);
    assert_invalid_request(&without, "a public client without PKCE");

    // with PKCE, the native client goes all the way
    let (verifier, challenge) = pkce_pair();
    let reqid = approval_page(&[
        ("response_type", "code"),
        ("client_id", NATIVE_ID),
        ("redirect_uri", NATIVE_REDIRECT),
        ("scope", "foo"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]);
    let code = query_params(approve(&reqid, "alice", &["foo"]).location())["code"].clone();
    token_request_form(&[
        ("client_id", NATIVE_ID),
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", NATIVE_REDIRECT),
        ("code_verifier", &verifier),
    ])
    .assert_status(200);
}

#[test]
fn r5_the_verifier_must_be_well_formed() {
    // "short" hashes fine, but it's far too short to be a real verifier
    let short = "short";
    let challenge = {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest, Sha256};
        URL_SAFE_NO_PAD.encode(Sha256::digest(short.as_bytes()))
    };
    let code = get_code_with(&[("code_challenge", &challenge), ("code_challenge_method", "S256")], "foo", "alice");
    assert_invalid_grant(&redeem(&code, Some(short)), "a 5-character verifier");
}

#[test]
fn r6_no_verifier_for_a_code_without_a_challenge() {
    let (verifier, _) = pkce_pair();
    let code = get_code("foo", "alice");
    assert_invalid_grant(&redeem(&code, Some(&verifier)), "a verifier for a code issued without PKCE");
}

#[test]
fn r7_the_web_client_sends_an_s256_challenge() {
    let _turn = client_app_lock();
    let alice = browser();
    let first = query_params(&client_authorize_url(&alice));
    let second = query_params(&client_authorize_url(&alice));

    assert_eq!(first.get("code_challenge_method").map(String::as_str), Some("S256"));
    let challenge = first.get("code_challenge").expect("no code_challenge in the web client's request");
    assert_eq!(challenge.len(), 43, "an S256 challenge is 43 characters: {challenge}");
    assert_ne!(first.get("code_challenge"), second.get("code_challenge"), "a fresh verifier for every login");
}

#[test]
fn r7_the_web_client_proves_it_at_the_token_endpoint() {
    let _turn = client_app_lock();

    // untouched, the login works: so the client sent the right verifier
    let alice = browser();
    client_login(&alice, "alice", None).assert_status(303);
    assert!(client_shown_token(&alice).is_some());

    // swap the challenge on the way to the server: now the client's verifier can't match
    let bob = browser();
    let to_as = client_authorize_url(&bob);
    let (_, other_challenge) = pkce_pair();
    let mut url = url::Url::parse(&to_as).unwrap();
    let params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| {
            let v = if k == "code_challenge" { other_challenge.clone() } else { v.into_owned() };
            (k.into_owned(), v)
        })
        .collect();
    url.query_pairs_mut().clear().extend_pairs(&params);

    let page = bob.get(url.as_str()).call();
    let back = approve(&reqid(&page.body), "bob", &scopes_on_page(&page.body).iter().map(String::as_str).collect::<Vec<_>>());
    let callback = bob.get(back.location()).call();
    assert!(!callback.is_redirect(), "the token request should have failed");
    assert_eq!(client_shown_token(&bob), None);
}

#[test]
fn r8_native_client_uses_pkce() {
    let mut app = Running::start(&build_bin("native-client"), &[]);
    let url = app.wait_for_line("the authorization URL", |line| line.trim().starts_with(&format!("{AS_URL}/authorize?")));
    let asked = query_params(url.trim());
    assert_eq!(asked.get("code_challenge_method").map(String::as_str), Some("S256"));
    assert_eq!(asked.get("code_challenge").map(String::len), Some(43));
}
