# auth-middleware-for-actix-web
> Actix Web Middleware for securing routes with session based authentication and mfa. Based on Actix-Session

This library provides a middleware for [Actix Web](https://github.com/actix/actix-web) to secure routes globally based on other authentication middleware like [Actix-Session](https://github.com/actix/actix-extras/tree/master/actix-session) and it provides an extractor to retrieve the logged in user.

*I have implemented this middleware for my personal use, but maybe it can help others to save time as well. Feel free to submit issues.*

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







