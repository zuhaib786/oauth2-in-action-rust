//! A bot that adds words to the Words API with nobody logged in.
//!
//! It gets a token for itself with the client credentials grant (RFC 6749
//! §4.4), then uses that one token for every request.
//!
//! Run it with:  cargo run -p word-bot -- hello world

use std::{env, error::Error, process::ExitCode};

use oauth_common::encode_client_credentials;
use reqwest::{Client, Response, header::WWW_AUTHENTICATE};
use serde_json::Value;

const TOKEN_ENDPOINT: &str = "http://localhost:9001/token";
const WORDS_API: &str = "http://localhost:9002/words";
const CLIENT_ID: &str = "oauth-client-service";
const CLIENT_SECRET: &str = "oauth-client-secret-service";

/// Any error, from a refused request to a connection failure. The bot only
/// prints them, so it never needs to tell them apart.
type BoxError = Box<dyn Error>;

/// Gets an access token for the bot itself, with the client's credentials in
/// an HTTP Basic header.
async fn get_token(http: &Client) -> Result<String, BoxError> {
    let credentials = encode_client_credentials(CLIENT_ID, CLIENT_SECRET);
    let response = http
        .post(TOKEN_ENDPOINT)
        .header("Authorization", format!("Basic {credentials}"))
        .form(&[("grant_type", "client_credentials"), ("scope", "read write")])
        .send()
        .await?;
    let body: Value = check(response, "the authorization server").await?.json().await?;
    body["access_token"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| format!("no access_token in {body}").into())
}

/// Adds one word with `POST /words`.
async fn insert_word(http: &Client, token: &str, word: &str) -> Result<(), BoxError> {
    let response = http
        .post(WORDS_API)
        .bearer_auth(token)
        .form(&[("word", word)])
        .send()
        .await?;
    check(response, "the protected resource").await?;
    Ok(())
}

/// Fetches the saved words with `GET /words`, which answers
/// `{"words": "hello world", ...}`.
async fn get_words(http: &Client, token: &str) -> Result<String, BoxError> {
    let response = http.get(WORDS_API).bearer_auth(token).send().await?;
    let body: Value = check(response, "the protected resource").await?.json().await?;
    body["words"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| format!("no words in {body}").into())
}

/// Passes a successful response through, and turns a refusal into an error
/// that says who refused and why. The protected resource gives its reason in
/// the `WWW-Authenticate` header (RFC 6750 §3), the authorization server in a
/// JSON body (RFC 6749 §5.2).
async fn check(response: Response, who: &str) -> Result<Response, BoxError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let challenge = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .map(String::from);
    let body = response.text().await.unwrap_or_default();
    let reason = challenge.unwrap_or(body);
    Err(format!("{who} refused the request: {status} {reason}").into())
}

/// Adds the words and returns what the Words API holds afterwards.
async fn run(words: &[String]) -> Result<String, BoxError> {
    let http = Client::new();
    // one token for the whole run, not one per request
    let token = get_token(&http).await?;
    for word in words {
        insert_word(&http, &token, word).await?;
        println!("Added {word}");
    }
    get_words(&http, &token).await
}

#[tokio::main]
async fn main() -> ExitCode {
    let words: Vec<String> = env::args().skip(1).collect();
    if words.is_empty() {
        eprintln!("usage: word-bot <word>...");
        return ExitCode::from(2);
    }

    match run(&words).await {
        Ok(saved) => {
            println!("{saved}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("word-bot: {error}");
            ExitCode::FAILURE
        }
    }
}
