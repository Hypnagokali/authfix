# Authfix
> Authfix is an Actix Web Middleware for securing routes with session based authentication and mfa. Its currently based on Actix-Session

This library provides a middleware for [Actix Web](https://github.com/actix/actix-web) to secure routes based on [Actix-Session](https://github.com/actix/actix-extras/tree/master/actix-session). It provides an extractor to retrieve the logged in user and it provides mfa-functionality.

*Not yet published*

First test version `0.1.0`:
- [x] Implementation on top of Actix-Session
    - [x] Login
    - [x] Secured routes
    - [x] Logout
    - [x] Mfa with an authenticator
    - [x] Mfa with random code that can be sent by mail or sms
    - [ ] Login session timeout (for mfa) is configurable
    - [ ] User has is_disabled and is_account_locked properties
    - [ ] Publish to crates.io
    - [x] Reference project
    - [ ] Docs and Readme with examples


Planning:
- [ ] Implementation for OIDC
    - [ ] Login with Google, GitHub, etc...
- [ ] WebAuthn(?)

## Examples coming soon







