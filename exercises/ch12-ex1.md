# 12-1 · Dynamic client registration

|                |                                                                                       |
|----------------|---------------------------------------------------------------------------------------|
| **Book**       | chapter 12, "Dynamic client registration"                                             |
| **RFCs**       | [RFC 7591][7591] §2, §3 · [RFC 8252 §7.3][8252-7.3]                                   |
| **You change** | `authorization-server` and `client`                                                   |
| **Tests**      | `cargo test -p acceptance --test ch12_ex1`                                            |

## Why

Every client so far was typed into the authorization server's source. That's
fine for one company's own apps, and impossible for an open ecosystem. A
thousand apps that want to talk to any Mastodon server can't each email the
admin first. **Dynamic registration** ([RFC 7591][7591]) lets a client
introduce itself: it POSTs JSON metadata about itself and gets back a
`client_id`, and a `client_secret` if it can keep one.

The server is now storing, and later showing to users, data that anyone on
the internet wrote. Everything a client registers is attacker-controlled input:

- `redirect_uris` decide where codes and tokens get sent. A `javascript:` URI,
  or plain `http` to a host on the internet, has to be refused at the door.
- `client_name` is shown on the approval page. Unescaped, it's stored XSS on
  the most security-sensitive page you have.
- `client_uri` and `logo_uri` become links and images on that page.
- The grant types a client may use are the server's decision. An app that
  registers itself doesn't get the password grant.

## Requirements

### Authorization server, `POST /register`

**R1.** Accept a JSON body of client metadata ([RFC 7591 §2][7591-2]). On
success, answer **201** with `Cache-Control: no-store` and a JSON body holding:

- `client_id`: new and random
- `client_secret`: random, at least 128 bits, only if the auth method isn't `none`
- `client_id_issued_at` (seconds since 1970) and `client_secret_expires_at: 0` (never)
- every metadata field as registered, defaults filled in

The new client works at `/authorize`, `/token`, `/revoke` straight away.

**R2.** The metadata you support, and its defaults:

| field                        | allowed                                                        | default                  |
|------------------------------|----------------------------------------------------------------|--------------------------|
| `redirect_uris`              | see R3                                                         | none                     |
| `token_endpoint_auth_method` | `client_secret_basic`, `client_secret_post`, `none`            | `client_secret_basic`    |
| `grant_types`                | `authorization_code`, `refresh_token`, `client_credentials`    | `["authorization_code"]` |
| `response_types`             | `code`, exactly when `grant_types` has `authorization_code`    | to match `grant_types`   |
| `scope`                      | any of the scopes the server knows (oauth-client-1's list)     | none                     |
| `client_name`                | any text                                                       | none                     |
| `client_uri`, `logo_uri`     | `http` or `https` URLs                                         | none                     |

A public client (`none`) may not use `client_credentials`, and as in 10-1 it
must use PKCE. Anything outside the table → 400 `invalid_client_metadata`.
So does a body that isn't JSON, or a field of the wrong type. Unknown fields
may be ignored.

**R3.** Each redirect URI must be an absolute URL without a fragment, and
either `https`, or `http` to a loopback host (`localhost`, `127.0.0.1`,
`[::1]`) for development and native apps ([RFC 8252 §7.3][8252-7.3]).
`authorization_code` needs at least one. A bad one →
400 `invalid_redirect_uri`.

**R4.** Errors are JSON, `{"error": "...", "error_description": "..."}`
([RFC 7591 §3.2.2][7591-3.2.2]).

### Authorization server, everywhere else

**R5.** `token_endpoint_auth_method` is enforced at `/token` and `/revoke`: a
`client_secret_basic` client must authenticate with Basic, a
`client_secret_post` one with `client_id` and `client_secret` in the form.
The wrong method → 401 `invalid_client`, even with the right secret. The
built-in confidential clients are `client_secret_basic`.

**R6.** The approval page shows `client_name` (and `client_uri`, `logo_uri`)
escaped. The home page shows no client secrets any more, not even the
built-in clients'. Anyone can read it.

### Client

**R7.** The web client registers itself instead of using `oauth-client-1`. On
its first login it POSTs its metadata to `/register` (its redirect URI, its
scope, `authorization_code` and `refresh_token`) and keeps the answer. Every
later login, refresh and revocation uses that registration. It registers
**once**, even when two logins start at the same time.

**R8.** A "Refresh" button on the home page: a form that POSTs to `/refresh`.
The client refreshes its access token now, with its registration, and answers
303 to `/`. Until now the tests checked refreshing (11-5's R5) by revoking
the client's access token as `oauth-client-1`. The client has its own
registration now, so they can't do that, and they use this button instead.

## Try it

```sh
curl -si -H 'Content-Type: application/json' http://localhost:9001/register -d '{
  "client_name": "curl", "redirect_uris": ["http://localhost:5555/cb"], "scope": "foo"
}'
curl -s -H 'Content-Type: application/json' http://localhost:9001/register \
     -d '{"redirect_uris": ["javascript:alert(1)"]}'
```

## Hints

- The registry can't be a `static` list any more. Something like
  `RwLock<HashMap<String, Arc<Client>>>` lets every handler read it and
  `/register` add to it. Functions that returned `&'static Client` have to
  change. Let the compiler walk you through them.
- Parse the body yourself (`Bytes`, then `serde_json::from_slice`). axum's
  `Json` extractor answers bad JSON with its own error, not
  `invalid_client_metadata`.
- A `#[derive(Deserialize)]` struct with `Option` fields makes "missing" and
  "wrong type" two different things, which is what you want.
- `url::Url` parses redirect URIs. `Url::fragment` and `Url::host` do the rest.
- The client needs its registration behind a lock it holds while it
  registers. `tokio::sync::Mutex<Option<Registration>>` is enough.
- After restarting the authorization server, the client's registration is
  gone. Restart both.

## Going further (not tested)

Open registration means anyone can register anything. [RFC 7591 §3][7591-3]
lets the server require an *initial access token*, and §2.3 adds *software
statements*: metadata signed by a party the server trusts. 12-2 gives
each client a token to manage its own registration.

[7591]: https://www.rfc-editor.org/rfc/rfc7591
[7591-2]: https://www.rfc-editor.org/rfc/rfc7591#section-2
[7591-3]: https://www.rfc-editor.org/rfc/rfc7591#section-3
[7591-3.2.2]: https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2
[8252-7.3]: https://www.rfc-editor.org/rfc/rfc8252#section-7.3
