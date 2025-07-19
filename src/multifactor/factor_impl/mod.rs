//! This module contains implementations of two multifactor authentication (MFA) factors

#[cfg(feature = "authenticator")]
#[cfg_attr(docsrs, doc(cfg(feature = "authenticator")))]
pub mod authenticator;
#[cfg(feature = "mfa_send_code")]
#[cfg_attr(docsrs, doc(cfg(feature = "mfa_send_code")))]
pub mod random_code_auth;
