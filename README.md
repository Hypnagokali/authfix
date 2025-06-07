# Authfix
> Authfix is an Actix Web Middleware for securing routes with session based authentication and mfa. Its currently based on Actix-Session

This library provides a middleware for [Actix Web](https://github.com/actix/actix-web) to secure routes based on [Actix-Session](https://github.com/actix/actix-extras/tree/master/actix-session). It provides an extractor to retrieve the logged in user and it provides mfa-functionality.

*Not yet published*

Progress of first version `0.1.0`:
- [x] Implementation on top of Actix-Session
    - [x] Login
    - [x] Secured routes
    - [x] Logout
    - [x] Mfa with an authenticator
    - [x] Mfa with random code that can be sent by mail or sms
    - [x] Login session timeout (for mfa) is configurable
    - [x] User has is_disabled and is_account_locked properties
    - [x] Docs and Readme with examples: 
    - [x] Reference project: login, logout and register an authenticator to use MFA: [MyActivities](https://github.com/Hypnagokali/my_activities)
    - [ ] Publish to crates.io

Planning for version `0.2.0`:
- [ ] OIDC
    - [ ] Example with Keycloak
    - [ ] Presets for Login with Google, GitHub, etc...?

Maybe later:
- WebAuthn / Passkeys?

## Examples
For more examples visit the examples repo: [Authfix examples](https://github.com/Hypnagokali/authfix-examples)

### With default config (every route is secured)
```rust
use actix_web::{HttpResponse, HttpServer, Responder, cookie::Key, get};
use authfix::{
    AccountInfo, AuthToken,
    async_trait::async_trait,
    login::{LoadUserByCredentials, LoadUserError, LoginToken},
    session::app_builder::SessionLoginAppBuilder,
};
use serde::{Deserialize, Serialize};

// A user intended for session authentication must derive or implement Clone, Serialize, and Deserialize.
#[derive(Clone, Serialize, Deserialize)]
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
#[async_trait]
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
    let user = auth_token.get_authenticated_user();
    HttpResponse::Ok().json(&*user)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let key = Key::generate();
    HttpServer::new(move || {
        // SessionLoginAppBuilder is the simplest way to create an App instance configured with session based authentication
        // This config registers: /login, /logout and /login/mfa (even if mfa is not configured)
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
            // Routes::default() registers: /login, /login/mfa, /logout
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






