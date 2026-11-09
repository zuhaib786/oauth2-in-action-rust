# 11-2 · Signed JWTs (HS256)

|                |                                                                                       |
|----------------|---------------------------------------------------------------------------------------|
| **Book**       | chapter 11, "Cryptographic protection of tokens: JOSE", the HS256 exercise            |
| **RFCs**       | [RFC 7515][7515] (JWS) · [RFC 7518 §3.2][7518-3.2] · [RFC 8725 §3.1][8725-3.1]        |
| **You change** | `authorization-server` and `protected-resource`                                       |
| **Tests**      | `cargo test -p acceptance --test ch11_ex2`                                            |

## Why

In 11-1 anyone could write a token and the protected resource believed it.
A **signature** fixes that: the authorization server computes a MAC over the
first two parts with a key, and the resource recomputes it with the same key.
Change a byte of the claims and the MACs no longer match. Make up a token from
scratch and you can't produce the MAC without the key.

**HS256** is HMAC-SHA256 with a secret that both sides know. It's the simplest
signature JOSE has, and it has two well-known traps:

1. **`alg: none` and algorithm switching.** The header says which algorithm
   to check with, and the header is written by whoever wrote the token. A
   resource that does what the header says can be told "there's no
   signature", or "check this with some other algorithm". So the resource
   decides which algorithm it accepts, and refuses everything else **before**
   looking at the claims ([RFC 8725 §3.1][8725-3.1]).
2. **Shared means shared.** Every resource server that can check an HS256
   token holds the secret, so every one of them can also mint tokens, for any
   user and any scope. One compromised resource server compromises them all.
   The last test in this exercise mints a token with the secret. 11-3 moves to
   public-key signatures, where only the authorization server can sign.

The book's secret, `shared OAuth token secret!`, is 26 bytes. [RFC 7518
§3.2][7518-3.2] says an HS256 key MUST be at least 256 bits, so this repository
uses a longer one.

## Requirements

**R1.** The authorization server signs every access token with **HS256**,
using the shared secret:

```text
shared OAuth token secret! (32 bytes or more)
```

The header becomes `{"alg":"HS256","typ":"at+jwt"}`. The claims stay as in 11-1.

**R2.** The protected resource checks the signature with the same secret.
Unsigned tokens (`alg: none`, or an empty signature), tokens signed with
another secret, and tokens whose header or claims were changed after signing
→ 401 `invalid_token`.

**R3.** It accepts **only HS256**. Any other `alg` → 401, even when the
signature is correct for that algorithm. (The tests sign a token with HS512
and the right secret.)

**R4.** Everything 11-1's R4 checked is still checked: `typ`, `iss`, `aud`,
`exp`, `nbf`. A valid signature only tells you who wrote the token, not that
it's for you or that it's still good.

**R5.** As in 11-1, the resource doesn't consult the database. So a token
signed with the secret is accepted whether or not the authorization server
issued it. That's the second trap above, and the test that shows it is
replaced in 11-3.

## Try it

```sh
# take a real token, raise its scope, keep its signature: refused
IFS=. read -r H C S <<<"$TOKEN"
C2=$(printf %s "$C" | tr '_-' '/+' | base64 -D 2>/dev/null | sed 's/"scope":"[^"]*"/"scope":"read write delete"/' | base64 | tr '+/' '-_' | tr -d '=\n')
curl -si -H "Authorization: Bearer $H.$C2.$S" http://localhost:9002/words | head -5
```

(`base64 -D` is macOS; on Linux it's `base64 -d`. Either may complain about
the missing padding and still decode.)

## Hints

- Use the [`jsonwebtoken`][jsonwebtoken] crate, version 9. Don't write HMAC
  checking yourself: comparing MACs with `==` leaks, through timing, how many
  leading bytes matched. Libraries compare in constant time.
- `jsonwebtoken::Validation` covers most of R3 and R4: the accepted
  algorithms, `iss`, `aud`, which claims are required, `nbf`, and clock
  leeway. Read its fields. It doesn't check `typ`; `decode_header` gets you
  the header for that.
- The claims can stay a `serde_json` value on both sides. You don't need a
  claims struct unless you want one.
- Both programs need the secret. Where would it live in a real deployment?
  (Not in the source. For the exercise, a constant on each side is fine.)

## Going further (not tested)

Read [RFC 8725 §2][8725-2], the list of attacks, again. Which ones does your
resource now stop, and which are left for 11-3?

[7515]: https://www.rfc-editor.org/rfc/rfc7515
[7518-3.2]: https://www.rfc-editor.org/rfc/rfc7518#section-3.2
[8725-2]: https://www.rfc-editor.org/rfc/rfc8725#section-2
[8725-3.1]: https://www.rfc-editor.org/rfc/rfc8725#section-3.1
[jsonwebtoken]: https://docs.rs/jsonwebtoken/9
