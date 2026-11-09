# 8-3 · Security headers

|                |                                                                                  |
|----------------|----------------------------------------------------------------------------------|
| **Book**       | chapter 8, "Strict-Transport-Security"                                           |
| **RFCs**       | [RFC 6797][hsts] · [RFC 6749 §5.1][5.1], §5.2, [§10.13][10.13] · [RFC 9700 §4.2][4.2] |
| **You change** | `protected-resource/src/main.rs`, `authorization-server/src/main.rs`             |
| **Tests**      | `cargo test -p acceptance --test ch8_ex3`                                        |

## Why

Some protections aren't in your code at all. They're in a response header that
tells the browser, or a cache along the way, what it may do with the response.
Each one below closes a specific hole:

- **HSTS** (`Strict-Transport-Security`). Once a browser has seen it over HTTPS,
  it refuses to talk to that host over plain HTTP, so nobody can downgrade the
  connection and read the bearer tokens in transit. Browsers ignore it over
  plain HTTP, so on localhost it does nothing. Real deployments are HTTPS, and
  the header belongs in the code all the same.
- **`Cache-Control: no-store`** on token responses. A token response is a
  credential. No proxy or browser cache may keep a copy ([RFC 6749 §5.1][5.1]
  says MUST, for errors too).
- **Anti-framing** on the approval page. If a hostile site can load your
  approval page in an invisible `<iframe>`, it can trick the user into clicking
  Approve. That's clickjacking ([RFC 6749 §10.13][10.13]).
- **`Referrer-Policy`**. The approval page's URL holds the whole authorization
  request, including `state` (and, from chapter 10, more). The page loads
  Bootstrap from a CDN, so without this header the CDN gets that URL in every
  `Referer` ([RFC 9700 §4.2][4.2]).

## Requirements

### Protected resource

**R1.** Every response carries `Strict-Transport-Security: max-age=31536000`.

### Authorization server

**R2.** Every response from `/token`, successes and errors alike, carries
`Cache-Control: no-store` and `Pragma: no-cache`.

**R3.** Every response carries `X-Frame-Options: DENY` and
`Content-Security-Policy: frame-ancestors 'none'`. The first is for old
browsers, the second for new ones.

**R4.** Every response carries `X-Content-Type-Options: nosniff`.

**R5.** Every response carries `Referrer-Policy: no-referrer`, including the
redirects back to the client.

## Try it

```sh
curl -sI http://localhost:9002/
curl -si -X POST http://localhost:9001/token | head -12
curl -sI 'http://localhost:9001/authorize?response_type=code&client_id=oauth-client-1&redirect_uri=http://localhost:9000/callback'
```

## Hints

- You did this for one header in 8-1. For headers on some routes only, build
  those routes as a `Router` of their own, add the layers to it, and `.merge`
  it into the main one.
- Why does R5 matter on a *redirect*? Look up how browsers treat a
  `Referrer-Policy` header on a 302.

## Going further (not tested)

`frame-ancestors 'none'` is one directive of a Content Security Policy. Write a
full CSP for the approval page that allows exactly what it needs: its own
form, Bootstrap's stylesheet from the CDN, and nothing else. Then check in the
browser's console that nothing breaks.

[hsts]: https://www.rfc-editor.org/rfc/rfc6797
[5.1]: https://www.rfc-editor.org/rfc/rfc6749#section-5.1
[10.13]: https://www.rfc-editor.org/rfc/rfc6749#section-10.13
[4.2]: https://www.rfc-editor.org/rfc/rfc9700#section-4.2
