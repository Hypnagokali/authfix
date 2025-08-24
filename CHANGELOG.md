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
- `AuthToken` had fields with crate visibility, therefore implementing the `AuthenticationProvider` wasn't really possible.


## 0.1.1
### Fixed
- Docs on doc.rs did not compile.

## 0.1.0
### Added
- Session based authentication
- Multifactor authentication
    - Authenticator
    - Random code flow (session only)
- Login flow via API or redirect based
- User account settings (a user can be disabled)