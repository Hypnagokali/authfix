//! This module contains implementations of two multifactor authentication (MFA) factors

#[cfg(feature = "authenticator")]
pub mod authenticator;
#[cfg(feature = "mfa_send_code")]
pub mod random_code_auth;
