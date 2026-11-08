# OAuth 2 in Action — Rust edition

The exercises from [*OAuth 2 in Action*](https://github.com/oauthinaction/oauth-in-action-code)
(Justin Richer & Antonio Sanso, Apache 2.0), rebuilt in Rust as **one project
that grows chapter by chapter**.

The book gives every exercise its own separate copy of the code. Here there is
just one client, one protected resource and one authorization server. Each
exercise adds its feature to the same code, so by the end you have a single
authorization server with everything the book teaches.

## Running it

Open **three terminals** in this folder and run one program in each:

```sh
cargo run -p authorization-server   # http://localhost:9001
cargo run -p protected-resource     # http://localhost:9002
cargo run -p client                 # http://localhost:9000  ← open this in your browser
```

The first build downloads and compiles dependencies (about 20 s). After that,
builds are fast. Stop a program with Ctrl-C, and restart it after you change its code.

## Doing the exercises

Every exercise is two git tags:

- `chX-exY-start` is the code with the exercise's parts replaced by `TODO` comments.
- `chX-exY-done` is the solution.

The `main` branch is the latest finished code.

```sh
# 1. Start an exercise on your own branch
git switch -c my-ch3-ex1 ch3-ex1-start

# 2. Find the TODOs, write your code, run it, try it in the browser
grep -rn TODO client/src authorization-server/src protected-resource/src

# 3. Compare your work with the solution
git diff ch3-ex1-done

# 4. Save your work, then move on to the next exercise
git commit -am "my solution to 3-1"
git switch -c my-ch3-ex2 ch3-ex2-start
```

Each exercise starts from the official solution of the one before. If your
version came out different, that's fine: your branch still has it.

| Book exercise | Tag prefix | What you write | File |
|---|---|---|---|
| 3-1 | `ch3-ex1` | Client: get a token with the authorization code grant, use it | `client/src/main.rs` |
| 3-2 | `ch3-ex2` | Client: use a refresh token when the access token stops working | `client/src/main.rs` |
| 4-1 | `ch4-ex1` | Protected resource: find and check the incoming token | `protected-resource/src/main.rs` |
| 4-2 | `ch4-ex2` | Protected resource: require `read`/`write`/`delete` scopes | `protected-resource/src/main.rs` |
| 4-3 | `ch4-ex3` | Protected resource: return different data depending on scope | `protected-resource/src/main.rs` |
| 4-4 | `ch4-ex4` | Protected resource: return different data depending on the user | `protected-resource/src/main.rs` |
| 5-1 | `ch5-ex1` | Authorization server: `/authorize`, `/approve` and `/token` | `authorization-server/src/main.rs` |
| 5-2 | `ch5-ex2` | Authorization server: issue and accept refresh tokens | `authorization-server/src/main.rs` |
| 5-3 | `ch5-ex3` | Authorization server: scopes | `authorization-server/src/main.rs` |

Later chapters will be added the same way.

## Layout

```
client/                 the OAuth client (port 9000)
authorization-server/   the OAuth authorization server (port 9001)
protected-resource/     the protected API (port 9002)
  src/main.rs           the code
  templates/*.html      the web pages (from the book, using Jinja syntax)
common/                 small helpers shared by all three (see below)
database.jsonl          tokens issued by the authorization server and read by the
                        protected resource (created when the server starts)
```

## Reading the book's JavaScript as Rust

| Book (Node.js)                       | Rust                                           |
|--------------------------------------|------------------------------------------------|
| `node client.js`                     | `cargo run -p client`                          |
| `app.get('/x', function(req, res) {...})` | `async fn x(...) -> Response {...}` plus `.route("/x", get(x))` |
| `req.query.code`                     | `param(&query, "code")` (gives `""` if missing) or `query.get("code")` (an `Option`) |
| `req.body.code` (form POST)          | `Form(body)` in the arguments, then `param(&body, "code")` |
| `req.headers['authorization']`       | `headers.get("authorization")`                 |
| `res.render('index', {a: 1})`        | `render("index", context! { a => 1 })`         |
| `res.redirect(url)`                  | `Redirect::to(&url).into_response()`           |
| `res.status(401).json({...})`        | `(StatusCode::UNAUTHORIZED, Json(json!({...}))).into_response()` |
| `request('POST', url, {...})`        | `reqwest::Client::new().post(url)....send().await` |
| `randomstring.generate()`            | `random_string(32)`                            |
| `buildUrl(base, {...})`              | `build_url(base, &[("k", "v")])`               |
| `encodeClientCredentials(id, secret)`| `encode_client_credentials(id, secret)`        |
| global `var state = null`            | a field in the state struct, `Option<String>`, reached with `app.lock().await` |
| `nosql.insert({...})`                | `db.insert(json!({...}))`                      |
| `nosql.one()...where('x', v)`        | `db.find_one(\|doc\| doc["x"] == v)`           |
| `__.contains(list, x)`               | `list.contains(&x)` or `.iter().any(...)`      |
| `<%- x %>` in templates              | `{{ x }}`                                      |

## Rust things you'll bump into

- **`Option<T>`** is Rust's "value or null". You'll use `if let Some(x) = ...`
  or `let Some(x) = ... else { return ...; };` a lot.
- **`Result<T, E>`** is "value or error". HTTP calls return one, because the
  other server might be down.
- **`.await`** appears on anything that waits on the network. Every handler is an `async fn`.
- **`app.lock().await`** gives you access to the shared state. JS just uses
  globals for this. Rust needs a lock because many requests can run at once.
- **`String` vs `&str`**: `String` owns its text, and `&str` borrows someone else's.
  `.to_string()` or `String::from(...)` turns a `&str` into a `String`.
  `&my_string` or `.as_str()` goes the other way.
- The compiler's error messages are long but usually tell you exactly what to change. Read them.
