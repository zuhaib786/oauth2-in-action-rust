# 11-5 · Token revocation and refresh token rotation

|                |                                                                                       |
|----------------|---------------------------------------------------------------------------------------|
| **Book**       | chapter 11, "Managing the token lifecycle with token revocation"                      |
| **RFCs**       | [RFC 7009][7009] · [RFC 9700 §4.14.2][9700-4.14.2] (refresh token rotation)            |
| **You change** | `authorization-server` and `client`                                                   |
| **Tests**      | `cargo test -p acceptance --test ch11_ex5`                                            |

## Why

So far only the authorization server decides when tokens die: on expiry, or
when it spots a replayed code. But the client often knows first. The user
clicked "log out", or uninstalled the app, or the client noticed it leaked
something. **Token revocation** ([RFC 7009][7009]) gives the client an
endpoint to say "I'm done with this token, kill it."

Refresh tokens are the ones worth killing: they live long and mint access
tokens. A stolen refresh token is good until someone notices. **Rotation**
makes theft noticeable ([RFC 9700 §4.14.2][9700-4.14.2]). Every refresh
returns a **new** refresh token, and the old one stops working. Now the thief
and the real client hold the same token, and whichever of them refreshes
second presents a token that was already used. The server can't tell which of
them is the thief, so it revokes the whole grant. The real client's user logs
in again; the thief is out.

## Requirements

### Authorization server, `POST /revoke`

**R1.** The endpoint takes a form with `token` and maybe `token_type_hint`.
Clients authenticate exactly as at `/token`: Basic or form for confidential
clients, `client_id` alone for public ones. A failed authentication → 401
`invalid_client`. An unknown, expired or malformed token is **not** an error:
answer 200 with an empty body ([RFC 7009 §2.2][7009-2.2]). The client wanted
it gone, and it is.

**R2.** What revocation does:

- An **access token**: it stops working at once (introspection says inactive).
  The rest of its grant is untouched.
- A **refresh token**: the whole grant goes, so every access and refresh token
  issued under it ([RFC 7009 §2.1][7009-2.1] says SHOULD).
- `token_type_hint` may be wrong. Look at the other kind too.
- A client may only revoke its **own** tokens. Another client's token → 400
  `invalid_grant`, and the token stays good. (RFC 6749 §5.2 lists "issued to
  another client" under `invalid_grant`.)

### Authorization server, rotation

**R3.** Every `refresh_token` grant returns a new refresh token, under the same
grant, and the one presented is used up. Presenting a used refresh token →
400 `invalid_grant`, **and** the whole grant is revoked.

Two requests may race with the same refresh token. Make sure only one of them
can win. (Not tested.)

### Client

**R4.** A "Revoke" button on the client's home page (a form that POSTs to
`/revoke`). The client revokes its refresh token and its access token at the
authorization server, forgets both, and answers 303 to `/`.

**R5.** When the client refreshes, it keeps the **new** refresh token. (It
probably already does. The test revokes the client's access token twice, so
the second refresh only works with the rotated refresh token.)

## Try it

```sh
curl -si -u oauth-client-1:oauth-client-secret-1 -d token=$REFRESH_TOKEN http://localhost:9001/revoke
curl -s -u oauth-client-1:oauth-client-secret-1 -d grant_type=refresh_token \
     -d refresh_token=$REFRESH_TOKEN http://localhost:9001/token
```

## Hints

- `/token` and `/revoke` authenticate clients the same way. Pull that code out
  of `token` into a function both can call.
- An access token is a JWT, so its record is found by `jti`, which means
  checking the signature first. 11-4's introspection already does that.
- A used refresh token has to stay in the database. Otherwise you can't tell
  reuse from a made-up token.
- `Db::update` returns how many documents it changed, under the database's
  write lock. "Mark it used if it isn't already" can be one call.
- The client's state lives in its session (7-1), and the form is a plain
  `<form method="post" action="/revoke">`. `SameSite=Lax` on the session
  cookie keeps other sites from submitting it for the user.

## Going further (not tested)

Rotation is one way to protect a refresh token. The other is to bind it to a
key only the real client holds, so a stolen copy is useless on its own.
That's DPoP, in 15-1.

[7009]: https://www.rfc-editor.org/rfc/rfc7009
[7009-2.1]: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
[7009-2.2]: https://www.rfc-editor.org/rfc/rfc7009#section-2.2
[9700-4.14.2]: https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2
