# 6-1 · The implicit grant

|                |                                                                     |
|----------------|---------------------------------------------------------------------|
| **Book**       | chapter 6, "Implicit grant type"                                    |
| **RFCs**       | [RFC 6749 §4.2][4.2], §4.1.2.1, §5.2 · [RFC 9700 §2.1.2][bcp]       |
| **You change** | `authorization-server/src/main.rs`                                  |
| **Tests**      | `cargo test -p acceptance --test ch6_ex1`                           |

## Why

Some clients have no server of their own: the whole app is JavaScript in a
browser tab. It can't keep a secret, because anyone can read the page's source.
Back when RFC 6749 was written, it also couldn't POST to a token endpoint on
another origin. So OAuth gave these clients the **implicit grant**: the
authorization server skips the code and puts the access token straight into
the redirect, in the URL **fragment** (`#access_token=...`). Browsers never
send the fragment to a server; only the page's script can read it.

It is deprecated now. [RFC 9700 §2.1.2][bcp] says clients SHOULD NOT use it,
and OAuth 2.1 drops it. The token sits in the browser's address bar and history,
and nothing ties it to the client that asked for it. Today a browser app uses
the code grant with PKCE (chapter 10). You build the implicit grant anyway: you
will meet it in older systems, and it shows what the code grant's back channel
buys you.

This exercise also adds two ideas the rest of the course builds on:

- **Public clients** have no secret. The authorization server knows their
  `client_id`, but it can't check that whoever sends that id really is that client.
- **Per-client grant types.** Each client is registered for the grants it uses
  and is refused the others ([RFC 7591 §2][7591] calls the field `grant_types`).

## What's already there

- The client app serves a browser-only client at
  <http://localhost:9000/implicit> (`client/templates/implicit.html`). Its
  JavaScript talks to the authorization server and the protected resource on
  its own; the client's Rust code only serves the page. The script is short.
  Read it, especially how it handles `state`.
- The protected resource already answers requests from other origins (CORS).
  Chapter 8 tightens that.

## Requirements

### Clients

**R1.** Register a second client:

| field           | value                                       |
|-----------------|---------------------------------------------|
| `client_id`     | `oauth-client-implicit`                     |
| `client_secret` | none: it's a public client                  |
| `redirect_uris` | `http://localhost:9000/implicit`            |
| `scope`         | `foo bar`                                   |
| `grant_types`   | `implicit`                                  |

**R2.** Every client has a list of grant types it may use. `oauth-client-1`
gets `authorization_code` and `refresh_token`.

### `GET /authorize`

Check in this order:

**R3.** Unknown `client_id`, or a `redirect_uri` that isn't registered for that
client: show the error page with status **400**. Never redirect, because you
don't know where the browser would end up.

**R4.** `response_type` must be `code` or `token`. Anything else, or none at all:
redirect back with `error=unsupported_response_type` in the query.

**R5.** `response_type=code` needs `authorization_code` in the client's grant
types, and `response_type=token` needs `implicit`. Otherwise redirect back with
`error=unauthorized_client`.

**R6.** Scopes the client may not have: `error=invalid_scope`, as before.

**R7.** Where errors go: when the request was `response_type=token`, the error
parameters go in the **fragment** (`#error=...`), not the query
([RFC 6749 §4.2.2.1][4.2.2.1]). For `response_type=code` they go in the query.

**R8.** Every error redirect carries the request's `state` back unchanged, if
the request had one ([RFC 6749 §4.1.2.1][4.1.2.1]). That includes the code flow,
and `access_denied` when the user clicks Deny.

### `POST /approve`, for `response_type=token`

**R9.** Issue an access token and save it the way the code flow does (client,
scope, user), so the protected resource accepts it and knows whose it is.

**R10.** Redirect to the redirect URI with the token response in the fragment,
form-encoded like a query string: `access_token`, `token_type=Bearer`, `scope`
(space-separated) and `state` if the request had one
([RFC 6749 §4.2.2][4.2.2]).

**R11.** Send no refresh token: RFC 6749 §4.2.2 says the server MUST NOT issue
one here. Send no `code`, and put nothing in the query.

### `POST /token`

**R12.** A public client identifies itself with just `client_id` in the form
body: no `client_secret`, no `Authorization` header. If a request for a public
client carries a secret anyway (in the body or in a Basic header), answer 401
`invalid_client`.

**R13.** After the client is identified, an unknown `grant_type` is still 400
`unsupported_grant_type`. A known grant type the client isn't registered for is
400 `unauthorized_client` ([RFC 6749 §5.2][5.2]). So `oauth-client-implicit`
gets `unauthorized_client` for every grant at the token endpoint.

## Try it

Open <http://localhost:9000/implicit>, click **Get OAuth Token**, approve, then
**Get Protected Resource**. The page wipes the fragment from the address bar as
soon as it loads. To see the raw redirect, ask for it with curl and approve in
the browser:

```sh
curl -i 'http://localhost:9001/authorize?response_type=token&client_id=oauth-client-implicit&redirect_uri=http://localhost:9000/implicit&scope=foo&state=abc'
```

Then try what should fail:

```sh
# the implicit client asks for a code: unauthorized_client, in the query
curl -si 'http://localhost:9001/authorize?response_type=code&client_id=oauth-client-implicit&redirect_uri=http://localhost:9000/implicit&state=abc' | grep -i location

# the public client at the token endpoint
curl -s -d 'client_id=oauth-client-implicit&grant_type=authorization_code&code=x' http://localhost:9001/token
```

## Hints

- How you model "has no secret" is your call. `Option<String>` is the obvious
  start. An enum says more, and chapter 12 adds a third kind of client
  authentication.
- `url::form_urlencoded::Serializer` builds `a=1&b=2` strings. The authorization
  server doesn't depend on `url` yet: add `url.workspace = true` to its
  `Cargo.toml`.
- `oauth_common::build_url_with_fragment` already exists.

## Going further (not tested)

Read [RFC 9700 §2.1.2][bcp] and §4.1–4.3. Which attacks on the implicit grant
does the code grant stop by itself, and which need PKCE as well?

[4.2]: https://www.rfc-editor.org/rfc/rfc6749#section-4.2
[4.2.2]: https://www.rfc-editor.org/rfc/rfc6749#section-4.2.2
[4.2.2.1]: https://www.rfc-editor.org/rfc/rfc6749#section-4.2.2.1
[4.1.2.1]: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1
[5.2]: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
[7591]: https://www.rfc-editor.org/rfc/rfc7591#section-2
[bcp]: https://www.rfc-editor.org/rfc/rfc9700#section-2.1.2
