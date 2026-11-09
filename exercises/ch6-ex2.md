# 6-2 · The client credentials grant

|                |                                                                         |
|----------------|-------------------------------------------------------------------------|
| **Book**       | chapter 6, "Client credentials grant type"                              |
| **RFCs**       | [RFC 6749 §4.4][4.4], §3.3                                              |
| **You change** | `authorization-server/src/main.rs`, and a new crate `word-bot`          |
| **Tests**      | `cargo test -p acceptance --test ch6_ex2`                               |

## Why

Every grant so far had a person in it: someone clicked Approve. A lot of
software has no person: a nightly job, a backend that syncs two systems, the
server half of a chat bot. With the **client credentials grant**, the client
gets a token for itself by showing its own id and secret at the token endpoint.
There's no redirect, no approval page and no user.

The token acts for the client, not for anyone. It's a different kind of
token from the ones you've issued so far, and the protected resource should be
able to tell the difference. That's why the grant is only for confidential
clients: if a public client could do this, anyone holding its `client_id` could
mint tokens.

You'll write both sides this time: the grant on the authorization server, and
a small program that uses it.

## Requirements

### Authorization server

**R1.** Register a third client:

| field           | value                            |
|-----------------|----------------------------------|
| `client_id`     | `oauth-client-service`           |
| `client_secret` | `oauth-client-secret-service`    |
| `redirect_uris` | none                             |
| `scope`         | `read write`                     |
| `grant_types`   | `client_credentials`             |

**R2.** The token endpoint supports `grant_type=client_credentials`. It refuses
public clients even if one were registered for it ([RFC 6749 §4.4][4.4]: "MUST
only be used by confidential clients"). No public client has this grant yet, so
that check isn't tested, but write it.

**R3.** `scope` is optional. Without it, the token gets every scope the client
is registered for. With it, the scopes must all be ones the client may have:
otherwise 400 `invalid_scope` ([RFC 6749 §3.3][3.3]).

**R4.** The response has `access_token`, `token_type` (`Bearer`) and `scope`,
and **no refresh token**. The client can always ask again ([RFC 6749
§4.4.3][4.4.3]).

**R5.** The token is saved with **no user**. The Favorites API answers
`"user": "Unknown"` for it.

**R6.** `oauth-client-1` isn't registered for this grant, so it gets
`unauthorized_client`. If 6-1 is right, this works already.

### `word-bot`

A command-line program that adds words to the Words API, with nobody logged in.

**R7.** It's a new binary crate called `word-bot` in this workspace, so that
`cargo run -p word-bot -- hello world` runs it.

**R8.** `word-bot <word>...` adds each word with `POST /words` (form field
`word`), then fetches `GET /words` and prints its `words` value as the **last
line** of stdout. Exit status 0.

**R9.** It gets its token with the client credentials grant as
`oauth-client-service`, credentials in an HTTP Basic header, asking for scope
`read write`.

**R10.** It asks for **one** token per run, not one per request. (Not tested.)

**R11.** With no words, it prints a usage line to stderr and exits with status
2. If the authorization server or the protected resource refuses it, it prints
what happened to stderr and exits with a non-zero status.

## Try it

```sh
curl -s -u oauth-client-service:oauth-client-secret-service \
     -d grant_type=client_credentials http://localhost:9001/token

cargo run -p word-bot -- hello robots
```

Then open the Words API from the web client: the bot's words are there.

## Hints

- `cargo new word-bot`, then add `"word-bot"` to `members` in the top-level
  `Cargo.toml`. Dependencies can come from the workspace
  (`reqwest.workspace = true`), like the other crates.
- `std::env::args().skip(1)` gives you the words. `std::process::ExitCode` lets
  `main` choose its exit status.
- The servers are async and use tokio. For a program like this,
  `reqwest::blocking` is fine too: add the `blocking` feature in the crate's own
  `Cargo.toml`.
- Think about what the error type of your inner function should be. There are
  three common choices: `Box<dyn std::error::Error>`, your own `enum`, or the
  `anyhow` crate. Any of them works here. Pick one and know why.

## Going further (not tested)

- Cache the token in a file between runs and only ask for a new one when the
  protected resource answers 401. How should that file be protected?
- [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) lets a client authenticate
  with a signed JWT instead of a shared secret (`private_key_jwt`). Why do large
  deployments prefer that for service clients?

[3.3]: https://www.rfc-editor.org/rfc/rfc6749#section-3.3
[4.4]: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
[4.4.3]: https://www.rfc-editor.org/rfc/rfc6749#section-4.4.3
