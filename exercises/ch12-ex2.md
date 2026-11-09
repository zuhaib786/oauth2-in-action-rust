# 12-2 · Managing a registration

|                |                                                                                       |
|----------------|---------------------------------------------------------------------------------------|
| **Book**       | chapter 12, "Client registration management"                                          |
| **RFCs**       | [RFC 7592][7592] §2, §3                                                               |
| **You change** | `authorization-server`                                                                |
| **Tests**      | `cargo test -p acceptance --test ch12_ex2`                                            |

## Why

A client that registered itself will need to change its registration: a new
redirect URI, a new name, fewer scopes. And when it's uninstalled it should
say so, so its registration and tokens don't hang around forever. [RFC
7592][7592] gives each registration a URL, its **registration client URI**,
and a **registration access token** that lets the client, and only that
client, read, replace or delete it.

The registration access token is a bearer token for one purpose only. It
isn't the client secret, which is for the token endpoint, and it isn't an
access token, which is for resources. Keeping them apart means a leak of one
doesn't give away the others.

## Requirements

**R1.** A successful `POST /register` also returns:

- `registration_access_token`: random, at least 128 bits
- `registration_client_uri`: `http://localhost:9001/register/<client_id>`

Built-in clients have neither and can't be managed.

**R2.** `GET /register/{client_id}` with `Authorization: Bearer <registration
access token>` → 200 with the current registration, in the same shape as the
registration answer (with `client_secret` and `registration_client_uri`), and
`Cache-Control: no-store`.

No token, a token that isn't this client's registration access token (another
client's, its client secret, an access token), or a client that doesn't
exist → 401 with a `WWW-Authenticate: Bearer ...` challenge. Don't say which
of these it was.

**R3.** `PUT /register/{client_id}` replaces the registration with the JSON
body ([RFC 7592 §2.2][7592-2.2]):

- The body must include `client_id`, equal to the one in the URL.
- It may include `client_secret`, which must equal the current one. A client
  can't choose its own secret.
- It's a **replacement**, not a patch. A field left out goes back to its
  default, or away.
- It's validated exactly like a registration (12-1's R2 and R3), with the
  same errors. A refused update changes nothing.
- The client keeps its `client_id`, secret and registration access token.
  Answer 200 with the new registration.

**R4.** `DELETE /register/{client_id}` → 204. The client is gone: it can't
authenticate, `/authorize` doesn't know it, its registration URI answers 401,
and every token issued to it stops working.

## Try it

```sh
REG=$(curl -s -H 'Content-Type: application/json' http://localhost:9001/register \
      -d '{"redirect_uris": ["https://app.example.com/cb"], "scope": "foo"}')
URI=$(echo "$REG" | python3 -c 'import sys,json; print(json.load(sys.stdin)["registration_client_uri"])')
TOKEN=$(echo "$REG" | python3 -c 'import sys,json; print(json.load(sys.stdin)["registration_access_token"])')
curl -s -H "Authorization: Bearer $TOKEN" "$URI"
curl -si -X DELETE -H "Authorization: Bearer $TOKEN" "$URI" | head -1
```

## Hints

- One route, three methods: `.route("/register/{client_id}", get(..).put(..).delete(..))`.
  `Path<String>` gets you the `client_id`.
- All three start the same way: find the client, check the token. Write that
  once.
- 12-1's validation turns metadata into a `Client`. If it's a function that
  takes the metadata and returns `Result<Client, Response>`, `PUT` can reuse
  it and then copy over the parts that must not change.
- Deleting the client's tokens: `Db::remove` with a predicate on `client_id`.

## Going further (not tested)

Rotate the registration access token on every `PUT`. RFC 7592 §3 allows it,
and it limits how long a leaked one stays useful. Then make the web client
use management: an "Unregister" button that deletes its registration and
forgets it.

[7592]: https://www.rfc-editor.org/rfc/rfc7592
[7592-2.2]: https://www.rfc-editor.org/rfc/rfc7592#section-2.2
