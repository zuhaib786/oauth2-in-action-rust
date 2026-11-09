//! Exercise 12-2: managing a registration. Spec: `exercises/ch12-ex2.md`.

use acceptance::*;
use serde_json::Value;

const APP_CALLBACK: &str = "https://app.example.com/callback";
const NEW_CALLBACK: &str = "https://app.example.com/new-callback";

#[track_caller]
fn register(metadata: &Value) -> Value {
    let reply = http().post(format!("{AS_URL}/register")).json(metadata).call();
    assert_eq!(reply.status.as_u16(), 201, "registering {metadata}: {}", reply.body);
    reply.json()
}

fn field(registration: &Value, name: &str) -> String {
    registration[name].as_str().unwrap_or_else(|| panic!("no {name} in {registration}")).to_string()
}

/// A registered client: its registration answer.
fn new_client() -> Value {
    register(&json!({
        "client_name": "Managed client",
        "redirect_uris": [APP_CALLBACK],
        "scope": "foo bar",
        "grant_types": ["authorization_code", "refresh_token"],
    }))
}

fn read(uri: &str, token: &str) -> Reply {
    http().get(uri).bearer_auth(token).call()
}

fn update(uri: &str, token: &str, metadata: &Value) -> Reply {
    http().put(uri).bearer_auth(token).json(metadata).call()
}

fn delete(uri: &str, token: &str) -> Reply {
    http().delete(uri).bearer_auth(token).call()
}

#[track_caller]
fn assert_unauthorized(reply: &Reply, what: &str) {
    assert_eq!(reply.status.as_u16(), 401, "{what}: {}", reply.body);
    let challenge = reply.header("www-authenticate").unwrap_or("");
    assert!(challenge.starts_with("Bearer"), "{what}: a Bearer challenge, got {challenge:?}");
}

fn authorize_to(client_id: &str, redirect_uri: &str) -> Reply {
    authorize(&[
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", "foo"),
        ("state", "st"),
    ])
}

#[test]
fn r1_registering_returns_management_credentials() {
    let client = new_client();
    let token = field(&client, "registration_access_token");
    assert!(token.len() >= 22, "a registration access token needs at least 128 bits of randomness: {token}");
    assert_eq!(
        field(&client, "registration_client_uri"),
        format!("{AS_URL}/register/{}", field(&client, "client_id"))
    );
}

#[test]
fn r2_a_client_can_read_its_registration() {
    let client = new_client();
    let reply = read(&field(&client, "registration_client_uri"), &field(&client, "registration_access_token"));
    reply.assert_status(200);
    let current = reply.json();
    for name in ["client_id", "client_secret", "client_name", "registration_client_uri"] {
        assert_eq!(current[name], client[name], "{name}");
    }
    assert_eq!(current["redirect_uris"], json!([APP_CALLBACK]));
    assert_eq!(reply.header("cache-control"), Some("no-store"), "the answer holds the secret");
}

#[test]
fn r2_only_with_its_own_token() {
    let client = new_client();
    let other = new_client();
    let uri = field(&client, "registration_client_uri");

    assert_unauthorized(&http().get(&uri).call(), "no token");
    assert_unauthorized(&read(&uri, "not-the-token"), "a made-up token");
    assert_unauthorized(&read(&uri, &field(&other, "registration_access_token")), "another client's token");
    assert_unauthorized(&read(&uri, &field(&client, "client_secret")), "the client secret");
    let access_token = access_token("foo", "alice");
    assert_unauthorized(&read(&uri, &access_token), "an access token");
    assert_unauthorized(
        &read(&format!("{AS_URL}/register/{CLIENT_ID}"), &field(&client, "registration_access_token")),
        "a built-in client, which has no registration to manage",
    );
}

#[test]
fn r3_a_client_can_update_its_registration() {
    let client = new_client();
    let (id, uri, token) =
        (field(&client, "client_id"), field(&client, "registration_client_uri"), field(&client, "registration_access_token"));

    let reply = update(&uri, &token, &json!({
        "client_id": id,
        "client_secret": client["client_secret"],
        "redirect_uris": [NEW_CALLBACK],
        "scope": "foo",
        "grant_types": ["authorization_code"],
    }));
    reply.assert_status(200);
    let updated = reply.json();
    assert_eq!(updated["client_id"], id.as_str());
    assert_eq!(updated["client_secret"], client["client_secret"], "the secret stays");
    assert_eq!(updated["redirect_uris"], json!([NEW_CALLBACK]));
    assert!(updated.get("client_name").is_none(), "a field left out of the update is deleted: {updated}");

    let current = read(&uri, &token).json();
    assert_eq!(current["redirect_uris"], json!([NEW_CALLBACK]));
    assert!(current.get("client_name").is_none());

    assert!(!authorize_to(&id, APP_CALLBACK).is_redirect(), "the old redirect URI must stop working");
    authorize_to(&id, NEW_CALLBACK).assert_status(200);
}

#[test]
fn r3_updates_are_checked_like_registrations() {
    let client = new_client();
    let (id, uri, token) =
        (field(&client, "client_id"), field(&client, "registration_client_uri"), field(&client, "registration_access_token"));

    for (what, metadata, error) in [
        ("a javascript: redirect URI", json!({ "client_id": id, "redirect_uris": ["javascript:alert(1)"] }), "invalid_redirect_uri"),
        ("the password grant", json!({ "client_id": id, "redirect_uris": [APP_CALLBACK], "grant_types": ["password"] }), "invalid_client_metadata"),
        ("another client_id", json!({ "client_id": CLIENT_ID, "redirect_uris": [APP_CALLBACK] }), "invalid_client_metadata"),
        ("no client_id", json!({ "redirect_uris": [APP_CALLBACK] }), "invalid_client_metadata"),
        (
            "a secret of its own choosing",
            json!({ "client_id": id, "client_secret": "my-own-secret", "redirect_uris": [APP_CALLBACK] }),
            "invalid_client_metadata",
        ),
    ] {
        let reply = update(&uri, &token, &metadata);
        assert_eq!(reply.status.as_u16(), 400, "{what}: {}", reply.body);
        assert_eq!(error_code(&reply), error, "{what}");
    }

    let current = read(&uri, &token).json();
    assert_eq!(current["client_secret"], client["client_secret"], "the secret must not have changed");
    assert_eq!(current["redirect_uris"], json!([APP_CALLBACK]), "a refused update changes nothing");
}

#[test]
fn r4_a_client_can_delete_its_registration() {
    let client = new_client();
    let (id, secret, uri, token) = (
        field(&client, "client_id"),
        field(&client, "client_secret"),
        field(&client, "registration_client_uri"),
        field(&client, "registration_access_token"),
    );

    let reqid = approval_page(&[
        ("response_type", "code"),
        ("client_id", &id),
        ("redirect_uri", APP_CALLBACK),
        ("scope", "foo"),
    ]);
    let code = query_params(approve(&reqid, "alice", &["foo"]).location())["code"].clone();
    let tokens = token_request_as(&id, &secret, &[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", APP_CALLBACK),
    ])
    .json();
    let access_token = field(&tokens, "access_token");
    get_resource(&access_token).assert_status(200);

    let reply = delete(&uri, &token);
    assert_eq!(reply.status.as_u16(), 204, "{}", reply.body);

    assert_unauthorized(&read(&uri, &token), "reading a deleted registration");
    let refresh = token_request_as(&id, &secret, &[("grant_type", "refresh_token"), ("refresh_token", &field(&tokens, "refresh_token"))]);
    assert_eq!(refresh.status.as_u16(), 401, "a deleted client can't authenticate");
    assert_eq!(error_code(&refresh), "invalid_client");
    assert_eq!(get_resource(&access_token).status.as_u16(), 401, "a deleted client's tokens die with it");
    assert!(!authorize_to(&id, APP_CALLBACK).is_redirect(), "a deleted client is unknown at /authorize");
}
