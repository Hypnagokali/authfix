pub mod app_builder;
pub mod config;
pub mod factor_impl;
pub mod auth_flow;
pub mod session_auth;

pub use actix_session;

use serde::{de::DeserializeOwned, Serialize};

pub(in crate::session) const SESSION_KEY_USER: &str = "authfix__user";
pub(in crate::session) const SESSION_KEY_NEED_MFA: &str = "authfix__needs_mfa";
pub(in crate::session) const SESSION_KEY_LOGIN_VALID_UNTIL: &str = "authfix__login_valid_until";

/// Contains the information about the user account.
///
/// There is only a semantic difference between disabling a user or locking the account.
/// In both cases, the user cannot log in.
/// `user_identification` is used for logging.
pub trait AccountInfo {
    fn user_identification(&self) -> String {
        "user_identification is not implemented".to_owned()
    }

    /// If user is disabled, login is not possible
    fn is_user_disabled(&self) -> bool {
        false
    }

    /// If account is locked, login is not possible
    fn is_account_locked(&self) -> bool {
        false
    }
}

/// This is a helper trait to bundle all necessary traits needed by a user
///
/// A SessionUser needs from serde: Serialize and Deserialize. And AccountInfo must be implemented.
pub trait SessionUser: AccountInfo + Serialize + DeserializeOwned {}
impl<T> SessionUser for T where T: AccountInfo + Serialize + DeserializeOwned {}
