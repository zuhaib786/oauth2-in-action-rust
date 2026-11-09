# 11-4 · Token introspection

|                |                                                                                       |
|----------------|---------------------------------------------------------------------------------------|
| **Book**       | chapter 11, "Looking up a token's information online: token introspection"            |
| **RFCs**       | [RFC 7662][7662] §2, [§4][7662-4]                                                     |
| **You change** | `authorization-server` and `protected-resource`                                       |
| **Tests**      | `cargo test -p acceptance --test ch11_ex4`                                            |

## Why

A self-contained token can't be called back. 11-3 ended with a test that
revokes a grant and watches its access token keep working. The only party
that knows a grant was revoked is the authorization server, so the resource
has to ask it.

**Token introspection** ([RFC 7662][7662]) is the standard way to ask. The
resource POSTs the token to the server's introspection endpoint and gets
back JSON: `{"active": true, ...}` with what the server knows about the
token, or just `{"active": false}`.

The endpoint is a gift to attackers if anyone can call it: it would tell them
which of their guessed or stolen tokens are live, and what they're good for.
So the caller has to authenticate as a protected resource, and a resource only
hears about tokens meant for it ([RFC 7662 §4][7662-4]).

What it costs: a network round trip for every API call, and the authorization
server is in the path of every request. Real deployments cache answers for a
few seconds, or introspect only for sensitive operations and check JWTs
locally otherwise. Each choice trades revocation speed for load.

## Requirements

### Authorization server

**R1.** `POST /introspect` takes a form with `token` (and maybe
`token_type_hint`, which may be wrong and must not change the answer). The
caller authenticates with HTTP Basic as one of these protected resources:

| resource id            | secret                        | its tokens' `aud`         |
|------------------------|-------------------------------|---------------------------|
| `protected-resource-1` | `protected-resource-secret-1` | `http://localhost:9002/`  |
| `protected-resource-2` | `protected-resource-secret-2` | `http://localhost:9003/`  |

No credentials, wrong ones, or a client's credentials → 401, and nothing about
the token.

**R2.** For an access token that is active, answer 200 with `"active": true`
and the token's claims: at least `sub`, `client_id`, `scope`, `iss`, `exp`
([RFC 7662 §2.2][7662-2.2]). For anything else (garbage, a bad signature,
expired, unknown) answer 200 with exactly `{"active": false}` and nothing
else.

**R3.** A token is active only if its signature and claims check out **and**
its record is still in the database. Revoking a grant (9-1's code replay)
deletes its records, so its access tokens go inactive at once.

**R4.** A resource only hears about tokens whose `aud` is its own. Asked by
`protected-resource-2` about a token for `http://localhost:9002/` →
`{"active": false}`.

### Protected resource

**R5.** For every request, the resource introspects the token as
`protected-resource-1` and accepts it only if the answer is
`"active": true`. Scope and `sub` come from the answer. If the
authorization server can't be reached, refuse the token. Never fail open.

Whether the resource also checks the JWT itself first, as in 11-3, is up to
you. The tests can't tell. Write down why you chose what you chose.

## Try it

```sh
curl -s -u protected-resource-1:protected-resource-secret-1 \
     -d token=$TOKEN http://localhost:9001/introspect | python3 -m json.tool
```

## Hints

- To check a token's signature, the authorization server needs its own public
  key. It already publishes it: `jsonwebtoken::jwk::JwkSet` and
  `DecodingKey::from_jwk` work on the server side too.
- The access token records you've been saving since 11-1 carry the `jti`.
  That's the lookup.
- `decode_client_credentials` from `oauth_common` already reads a Basic header.
- Compare secrets the way you would a password. Do you want `==`? (Not tested;
  see `subtle` or `constant_time_eq` if you want to do better.)
- The resource's HTTP client and the authorization server's URL were already
  part of 11-3's resource. Its `Validation` and JWK Set code may go away.

## Going further (not tested)

[RFC 9701](https://www.rfc-editor.org/rfc/rfc9701) lets the server answer
introspection with a signed JWT, so the answer itself can be passed on and
checked later.

[7662]: https://www.rfc-editor.org/rfc/rfc7662
[7662-2.2]: https://www.rfc-editor.org/rfc/rfc7662#section-2.2
[7662-4]: https://www.rfc-editor.org/rfc/rfc7662#section-4
