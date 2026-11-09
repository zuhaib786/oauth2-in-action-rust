# 8-2 · CORS, done on purpose

|                |                                                                            |
|----------------|----------------------------------------------------------------------------|
| **Book**       | chapter 8, "Adding CORS to a protected resource"                           |
| **Spec**       | [Fetch standard, CORS protocol][fetch]                                     |
| **You change** | `protected-resource/src/main.rs`                                           |
| **Tests**      | `cargo test -p acceptance --test ch8_ex2`                                  |

## Why

Browsers stop a page on one origin from reading responses from another, unless
that other origin says it's fine with **CORS** response headers. The browser-only
client from 6-1 lives on `http://localhost:9000` and calls the protected
resource on `http://localhost:9002`, so the protected resource has to opt in.

Since chapter 4 it has opted in with `CorsLayer::permissive()`: any origin,
any method, any header. Bearer tokens aren't cookies, so the browser won't
attach one to an attacker's request on its own, and permissive CORS isn't a
disaster here. But it is a decision nobody made. Every page on the internet may
now script calls to this API from a visitor's browser, including from inside
their network. An API should name the origins it serves.

Here that's one origin, the client app's.

## Requirements

**R1.** Only `http://localhost:9000` gets CORS access. For a request from that
origin, `Access-Control-Allow-Origin` is exactly `http://localhost:9000`.
Never `*`.

**R2.** A request (preflight or not) from any other origin gets **no**
`Access-Control-Allow-Origin` header at all.

**R3.** Preflights from the allowed origin may use the methods `GET`, `POST`
and `DELETE`, and the request headers `Authorization` and `Content-Type`.

**R4.** No `Access-Control-Allow-Credentials`. The token travels in a header
the script sets itself, not in a cookie.

**R5.** The browser may cache a preflight for 10 minutes:
`Access-Control-Max-Age: 600`.

**R6.** Responses vary by origin: `Vary` includes `Origin`, so a cache never
serves one origin's answer to another.

**R7.** The script can read `WWW-Authenticate` from errors, so it can tell why
it was refused (8-1). Browsers hide that header from scripts unless it's listed
in `Access-Control-Expose-Headers`.

## Try it

The browser-only client at <http://localhost:9000/implicit> must still work.
Then pretend to be another site:

```sh
curl -si -X OPTIONS http://localhost:9002/resource \
     -H 'Origin: http://evil.example' -H 'Access-Control-Request-Method: POST' \
     -H 'Access-Control-Request-Headers: authorization'
```

## Hints

- `tower_http::cors::CorsLayer` has a builder for all of this. Read the docs
  for `AllowOrigin` closely: `exact` and `list` don't behave the same way when
  the origin doesn't match.

## Going further (not tested)

Why is `Access-Control-Allow-Origin: *` together with
`Access-Control-Allow-Credentials: true` forbidden by browsers? And why is
reflecting whatever `Origin` arrives, with credentials allowed, a classic way to
leak data?

[fetch]: https://fetch.spec.whatwg.org/#http-cors-protocol
