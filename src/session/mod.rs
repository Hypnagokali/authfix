pub mod app_builder;
pub mod config;
pub mod handlers;
pub mod session_auth;

pub use actix_session;
use serde::{de::DeserializeOwned, Serialize};

/// Contains the information about the user account.
///
/// There is only a semantic difference between disabling a user or locking the account.
/// In both cases, the user cannot log in.
/// `get_user_identification` is used for logging.
pub trait AccountInfo {
    fn get_user_identification(&self) -> String {
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
/// Don't implement it, just derive Serialize, Deserialize from serde, Clone from std and implement AccountInfo
pub trait SessionUser: AccountInfo + Serialize + DeserializeOwned + Clone {}
impl<T> SessionUser for T where T: AccountInfo + Serialize + DeserializeOwned + Clone {}
