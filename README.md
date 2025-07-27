# Authfix
> Authentication layer for Actix-Web

[![CI](https://github.com/hypnagokali/authfix/actions/workflows/ci.yml/badge.svg)](https://github.com/hypnagokali/authfix/actions/workflows/ci.yml)

This library offers an authentication middleware for [Actix Web](https://github.com/actix/actix-web). It's easy to use and quick to set up.

Currently it provides session-based authentication built on [actix-session](https://crates.io/crates/actix-session), but you can implement your own `AuthenticationProvider` if needed. A provider for OIDC is planned for *v0.2.0*.

It supports multi-factor authentication.
- TOTP (e.g., Google or Microsoft Authenticator) with the ability to generate a QR code for securely sharing the secret with the user.
- Code sender mechanism that can deliver the code to the user via SMS, E-Mail, or other channels.
- Easy to extend, just implement the `Factor` trait.

## Examples
### Example Repository

Check out the examples repo for detailed and working examples: [Authfix examples](https://github.com/Hypnagokali/authfix-examples)

### With default config (every route is secured)

```rust
use actix_web::{HttpResponse, HttpServer, Responder, cookie::Key, get};
use authfix::{
    AuthToken,
    login::{LoadUserByCredentials, LoadUserError, LoginToken},
    session::{AccountInfo, app_builder::SessionLoginAppBuilder},
};
use serde::{Deserialize, Serialize};

// A user intended for session authentication must derive Serialize, and Deserialize.
#[derive(Serialize, Deserialize)]
struct User {
    name: String,
}

// AccountInfo trait is used for disabling the user or to lock the account
// The user is enabled by default
impl AccountInfo for User {}

// Struct that handles the authentication
struct AuthenticationService;

// LoadUsersByCredentials uses async_trait, so its needed when implementing the trait for AuthenticationService
// async_trait is re-exported by authfix.
impl LoadUserByCredentials for AuthenticationService {
    type User = User;

    async fn load_user(&self, login_token: &LoginToken) -> Result<Self::User, LoadUserError> {
        // load user by email logic and check password
        // currently authfix does not provide hashing functions, you can use for example https://docs.rs/argon2/latest/argon2/
        if login_token.email == "test@example.org" && login_token.password == "password" {
            Ok(User {
                name: "Johnny".to_owned(),
            })
        } else {
            Err(LoadUserError::LoginFailed)
        }
    }
}

// You have access to the user via the AuthToken extractor in secured routes.
#[get("/secured")]
async fn secured(auth_token: AuthToken<User>) -> impl Responder {
    let user = auth_token.authenticated_user();
    HttpResponse::Ok().json(&*user)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let key = Key::generate();
    HttpServer::new(move || {
        // SessionLoginAppBuilder is the simplest way to create an App instance configured with session based authentication
        // This default config registers handlers for: /login, /logout and /login/mfa.
        SessionLoginAppBuilder::create(AuthenticationService, key.clone())
            .build()
            .service(secured)
    })
    .bind("127.0.0.1:7080")?
    .run()
    .await
}
```
### Add a public route

```rust
#[get("/public")]
async fn public() -> impl Responder {
    HttpResponse::Ok().json(r#"{ value: "everyone can see this" }"#)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let key = Key::generate();
    HttpServer::new(move || {
        SessionLoginAppBuilder::create(AuthenticationService, key.clone())
            .set_login_routes_and_public_paths(Routes::default(), vec!["/public"])
            .build()
            .service(secured)
            .service(public)
    })
    .bind("127.0.0.1:7080")?
    .run()
    .await
}
```






