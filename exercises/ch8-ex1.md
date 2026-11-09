# 8-1 · Protected resource: answers that can't be used against you

|                |                                                                             |
|----------------|-----------------------------------------------------------------------------|
| **Book**       | chapter 8, "Common protected resource vulnerabilities"                      |
| **RFCs**       | [RFC 6750][6750] §2, §2.2, §2.3, §3, §3.1 · [RFC 9700 §4.3][bcp]             |
| **You change** | `protected-resource/src/main.rs`                                            |
| **Tests**      | `cargo test -p acceptance --test ch8_ex1`                                   |

## Why

This time you start from **broken code**. The protected resource has a new API,
`GET /helloWorld?language=en`, written the way the book first writes it: it
answers with `text/html` and copies the `language` parameter into the page. Ask
for `language=<script>...</script>` and the browser runs the script on the
protected resource's origin. That's a reflected XSS, behind an access token.

Fixing that one bug is the easy part. The real job is to go over **every way
the protected resource answers** and make each one correct:

- **Content type.** An API answers with JSON, labelled as JSON, and tells the
  browser not to guess (`X-Content-Type-Options: nosniff`).
- **Errors that say what went wrong.** [RFC 6750 §3][3] defines the
  `WWW-Authenticate: Bearer ...` challenge. A client should be able to tell
  "you sent no token" from "your token is no good" from "your token can't do
  that", and it can't do that from a bare 401.
- **Where tokens may come from.** Chapter 4 accepted a token in the URL's
  query string. URLs end up in server logs, proxies, browser history and
  `Referer` headers. [RFC 6750 §2.3][2.3] says not to do it, and
  [RFC 9700 §4.3][bcp] says "MUST NOT".

## What's already there

`GET /helloWorld` in `protected-resource/src/main.rs`, broken on purpose.

## Requirements

### `/helloWorld`

**R1.** `language` = `en`, `de`, `it`, `fr` or `es` → 200 with JSON
`{"greeting": "Hello World"}` (or `Hallo Welt`, `Ciao Mondo`, `Bonjour monde`,
`Hola mundo`), with `Content-Type: application/json`.

**R2.** Any other `language` → 400 with JSON `{"error": "invalid_language"}`.
What was sent is **never** echoed back.

### Every response

**R3.** Every response from the protected resource carries
`X-Content-Type-Options: nosniff`, errors included.

### Finding the token

**R4.** The token may come in the `Authorization: Bearer` header, or in a form
body (RFC 6750 §2.2), and **nowhere else**. A token in the query string is
ignored, as if there were none.

**R5.** A form body only counts if the request's `Content-Type` is
`application/x-www-form-urlencoded`, and never for a `GET`
([RFC 6750 §2.2][2.2]).

**R6.** A request that sends a token in **both** places is 400, with
`error="invalid_request"` in the challenge (R9). RFC 6750 §2: clients "MUST
NOT use more than one method".

### Challenges

All challenges name the realm as a quoted string: `realm="localhost:9002"`.
`localhost:9002` contains a `:`, so the unquoted form chapter 4 used isn't
valid ([RFC 6750 §3][3]).

**R7.** No token at all → 401 with `WWW-Authenticate: Bearer
realm="localhost:9002"`, and **no** error code. The RFC asks for none when the
client simply didn't try.

**R8.** A token that isn't valid → 401 with
`WWW-Authenticate: Bearer realm="localhost:9002", error="invalid_token"`.

**R9.** An invalid request (R6) → 400 with
`WWW-Authenticate: Bearer realm="localhost:9002", error="invalid_request"`.

**R10.** Missing scope → 403 with
`WWW-Authenticate: Bearer realm="localhost:9002", error="insufficient_scope", scope="<the scope>"`.
This was chapter 4's challenge, now with the realm quoted.

## Try it

```sh
TOKEN=...   # get one from the client app's home page

curl -si -H "Authorization: Bearer $TOKEN" 'http://localhost:9002/helloWorld?language=en'
curl -si -H "Authorization: Bearer $TOKEN" 'http://localhost:9002/helloWorld?language=%3Cscript%3Ealert(1)%3C/script%3E'
curl -si http://localhost:9002/resource -X POST
curl -si "http://localhost:9002/resource?access_token=$TOKEN" -X POST
```

## Hints

- Chapter 4's `AccessToken` extractor rejects with a bare `StatusCode`. Give
  it a rejection type of its own that implements `IntoResponse`, so each kind
  of failure answers the way it should.
- A header that goes on every response is a layer's job, not each handler's:
  `tower_http::set_header::SetResponseHeaderLayer` (tower-http's `set-header`
  feature).
- `axum::Json` sets `Content-Type: application/json` for you.

## Going further (not tested)

Your token lookup reads the whole request body before the handler runs, up to
64 KiB, even for requests that have no token. What does that cost under load,
and how would you avoid it?

[6750]: https://www.rfc-editor.org/rfc/rfc6750
[2.2]: https://www.rfc-editor.org/rfc/rfc6750#section-2.2
[2.3]: https://www.rfc-editor.org/rfc/rfc6750#section-2.3
[3]: https://www.rfc-editor.org/rfc/rfc6750#section-3
[bcp]: https://www.rfc-editor.org/rfc/rfc9700#section-4.3
