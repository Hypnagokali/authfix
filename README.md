# auth-middleware-for-actix-web
> Actix Web Middleware for securing routes with session based authentication and mfa. Based on Actix-Session

This library provides a middleware for [Actix Web](https://github.com/actix/actix-web) to secure routes based on [Actix-Session](https://github.com/actix/actix-extras/tree/master/actix-session). It provides an extractor to retrieve the logged in user and it provides mfa-functionality.

*Not yet published*

First test version `0.1.0-alpha.1`:
- [x] Implementation on top of Actix-Session
    - [x] Login
    - [x] Secured routes
    - [x] Logout
    - [x] Mfa with an authenticator
    - [ ] Mfa with random code and E-Mail-/SMS-Sender
    - [ ] Publish to crates.io
    - [ ] Reference project
    - [ ] Docs and Readme with examples

Planning:
- [ ] Implementation for OIDC
    - [ ] Expecting a valid token from another service / front-end
    - [ ] Provide OIDC Login(?)

## Examples coming soon







