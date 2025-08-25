# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- `AuthTokenOption` can be used to access the logged in user in public routes.

### Changed

- Separated `AuthToken` from internal `LoginState`.

### Fixed

- Some types (`AuthToken`, `UnauthorizedError`, `UnauthorizedRedirect`, etc..) where private or had fields with crate or private visibility, therefore implementing the `AuthenticationProvider` wasn't really possible.

## 0.1.1

### Fixed

- Docs on docs.rs did not compile.

## 0.1.0

### Added

- Session based authentication
- Multifactor authentication
    - Authenticator
    - Random code flow (session only)
- Login flow via API or redirect based
- User account settings (user can be disabled)
- SessionLoginAppBuilder to create a session based authenticated `actix_web::App` easily