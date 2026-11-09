//! Exercise 6-2: the client credentials grant. Spec: `exercises/ch6-ex2.md`.

use std::process::Command;

use acceptance::*;

const SERVICE_ID: &str = "oauth-client-service";
const SERVICE_SECRET: &str = "oauth-client-secret-service";

fn service_token(form: &[(&str, &str)]) -> Reply {
    let mut form = form.to_vec();
    form.push(("grant_type", "client_credentials"));
    token_request_as(SERVICE_ID, SERVICE_SECRET, &form)
}

#[test]
fn r2_r4_the_service_gets_a_token_without_a_user() {
    let reply = service_token(&[("scope", "read")]);
    reply.assert_status(200);
    let token = reply.json();
    assert!(token["access_token"].is_string());
    assert!(token["token_type"].as_str().unwrap_or("").eq_ignore_ascii_case("bearer"));
    assert_eq!(scope_set(&token["scope"]), scope_set("read"));
    assert!(token.get("refresh_token").is_none(), "no refresh token for client credentials");
}

#[test]
fn r3_no_scope_means_every_registered_scope() {
    let reply = service_token(&[]);
    reply.assert_status(200);
    assert_eq!(scope_set(&reply.json()["scope"]), scope_set("read write"));
}

#[test]
fn r3_a_scope_the_client_may_not_have_is_refused() {
    let reply = service_token(&[("scope", "read delete")]);
    reply.assert_status(400);
    assert_eq!(error_code(&reply), "invalid_scope");
}

#[test]
fn r4_the_token_works_within_its_scope() {
    let token = service_token(&[("scope", "read")]).json()["access_token"].as_str().unwrap().to_string();
    http().get(format!("{RS_URL}/words")).bearer_auth(&token).call().assert_status(200);
    http()
        .post(format!("{RS_URL}/words"))
        .bearer_auth(&token)
        .form(&[("word", "nope")])
        .call()
        .assert_status(403);
}

#[test]
fn r5_the_token_has_no_user() {
    let token = service_token(&[]).json()["access_token"].as_str().unwrap().to_string();
    let favorites = http().get(format!("{RS_URL}/favorites")).bearer_auth(&token).call();
    assert_eq!(favorites.json()["user"], "Unknown");
}

#[test]
fn r6_other_clients_are_not_registered_for_it() {
    let reply = token_request(&[("grant_type", "client_credentials")]);
    reply.assert_status(400);
    assert_eq!(error_code(&reply), "unauthorized_client");
}

#[test]
fn r1_the_service_client_cannot_use_other_grants() {
    let reply = token_request_as(SERVICE_ID, SERVICE_SECRET, &[("grant_type", "authorization_code"), ("code", "x")]);
    reply.assert_status(400);
    assert_eq!(error_code(&reply), "unauthorized_client");

    let wrong_secret = token_request_as(SERVICE_ID, "guess", &[("grant_type", "client_credentials")]);
    wrong_secret.assert_status(401);
}

#[test]
fn r7_r8_word_bot_adds_words_and_prints_them() {
    let bot = build_bin("word-bot");
    let (first, second) = (unique("bot"), unique("tob"));

    let run = Command::new(&bot).args([&first, &second]).output().expect("run word-bot");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(run.status.success(), "word-bot failed: {}\n{stdout}{}", run.status, String::from_utf8_lossy(&run.stderr));

    let last_line = stdout.lines().last().unwrap_or("");
    assert!(last_line.contains(&first) && last_line.contains(&second), "last line of stdout was {last_line:?}");

    let alice = access_token("read", "alice");
    let words = http().get(format!("{RS_URL}/words")).bearer_auth(&alice).call().json();
    assert!(words["words"].as_str().unwrap_or("").contains(&first), "the words should be on the server");
}

#[test]
fn r11_word_bot_without_words_explains_itself() {
    let bot = build_bin("word-bot");
    let run = Command::new(&bot).output().expect("run word-bot");
    assert_eq!(run.status.code(), Some(2), "exit status with no words");
    assert!(!run.stderr.is_empty(), "print a usage line to stderr");
}
