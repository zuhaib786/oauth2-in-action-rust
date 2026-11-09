# 6-3 · The resource owner password grant

|                |                                                                          |
|----------------|--------------------------------------------------------------------------|
| **Book**       | chapter 6, "Resource owner credentials grant type"                       |
| **RFCs**       | [RFC 6749 §4.3][4.3] · [RFC 9700 §2.4][bcp]                              |
| **You change** | `authorization-server/src/main.rs`                                       |
| **Tests**      | `cargo test -p acceptance --test ch6_ex3`                                |

## Why

Here the user types their username and password **into the client**, and the
client sends them to the token endpoint. That is exactly what OAuth was invented
to stop: the client sees the password, the user can't tell a real client from a
phishing one, and nothing like two-factor login fits in. [RFC 9700 §2.4][bcp]
says this grant MUST NOT be used, and OAuth 2.1 removes it.

It exists for one job: moving old clients that stored users' passwords onto
tokens, as a step on the way to something better. You build it here because it
makes you handle something new: **user passwords on the server**. RFC 6749
§4.3.2 says the authorization server "MUST protect the endpoint against brute
force attacks". Doing that properly takes more than an `if`.

## Requirements

### Users

**R1.** Users get passwords:

| user  | password                       |
|-------|--------------------------------|
| alice | `password`                     |
| bob   | `this is my secret password`   |
| carol | `correct horse battery staple` |

`carol` is a new user (`sub` `5UAL-CA03-60913C`, name `Carol`, email
`carol@example.org`, verified). The brute-force test locks her out, so the
tests use her and leave alice and bob alone.

**R2.** Store a slow, salted **hash** of each password, never the password
(Argon2id, with the `argon2` crate). (Not tested.)

**R3.** A password or hash never appears in a page, a log line or a JSON
response. Remember the `User` struct is serialized into the approval page's
template context. (Not tested.)

### Client

**R4.** Register a fourth client:

| field           | value                            |
|-----------------|----------------------------------|
| `client_id`     | `oauth-client-trusted`           |
| `client_secret` | `oauth-client-secret-trusted`    |
| `redirect_uris` | none                             |
| `scope`         | `foo bar read write`             |
| `grant_types`   | `password`, `refresh_token`      |

### `POST /token` with `grant_type=password`

**R5.** Takes `username`, `password` and an optional `scope`. A missing `scope`
means every scope the client is registered for, as in 6-2. A scope the client may
not have is 400 `invalid_scope`.

**R6.** On success, answer with `access_token`, `token_type`, `scope` and a
`refresh_token`. The token belongs to the user, so the Favorites API knows whose
favorites to show.

**R7.** An unknown username and a wrong password get the **same** answer: 400
`invalid_grant`, with the same body. Otherwise the endpoint tells attackers which
usernames exist.

**R8.** An unknown username takes as long to answer as a wrong password, which
means doing a hash check against a dummy hash. Without it, the response time
tells attackers which usernames exist. (Not tested.)

**R9.** After **5 failed attempts in a row** for a username, refuse that
username for **60 seconds**, even with the right password. The answer stays
400 `invalid_grant`. A successful login resets the count.

**R10.** `oauth-client-1` isn't registered for this grant: `unauthorized_client`.

## Try it

```sh
curl -s -u oauth-client-trusted:oauth-client-secret-trusted \
     -d grant_type=password -d username=alice -d password=password \
     http://localhost:9001/token

for i in 1 2 3 4 5 6; do
  curl -s -u oauth-client-trusted:oauth-client-secret-trusted \
       -d grant_type=password -d username=carol -d password=nope http://localhost:9001/token; echo
done
```

## Hints

- `argon2` (version 0.5) has a `PasswordHasher` / `PasswordVerifier` API that
  reads and writes PHC strings (`$argon2id$v=19$...`). The salt lives inside
  the string. You can compute the three hashes once and paste them into the
  source, which is what a database would hold.
- Argon2 is deliberately slow, and in a debug build it's *very* slow. Add
  `[profile.dev.package.argon2] opt-level = 3` (and the same for `blake2`) to
  the top-level `Cargo.toml`.
- Hashing blocks the thread for a while. In an async server that belongs in
  `tokio::task::spawn_blocking`.
- `#[serde(skip)]` keeps a field out of serialization.
- `std::time::Instant` is the clock for "60 seconds from now".

## Going further (not tested)

A per-username lockout lets anyone lock any user out (try it on alice). Real
systems combine per-IP and per-account limits, increasing delays, CAPTCHAs, and
checks against breached-password lists. Sketch what you'd do instead, and where
that state should live when there are several authorization server instances.

[4.3]: https://www.rfc-editor.org/rfc/rfc6749#section-4.3
[bcp]: https://www.rfc-editor.org/rfc/rfc9700#section-2.4
