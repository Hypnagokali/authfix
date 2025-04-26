use async_trait::async_trait;
use authfix::login::{LoadUserError, LoadUserByCredentials, LoginToken};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// I am really not sure why cargo suddenly complains that TEST_OUT and test_out_path is not used. For now I mark it as allow(dead_code)
#[allow(dead_code)]
pub const TEST_OUT: &str = "test-out";

#[allow(dead_code)]
pub fn test_out_path(path: &str) -> String {
    format!("{TEST_OUT}/{path}")
}

// A standard error for tests
#[derive(Error, Debug)]
pub enum CustomError {
    #[allow(dead_code)]
    #[error("An error occured")]
    Error,
}

//
// For login and mfa tests:
//
#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub email: String,
    pub name: String,
}

pub struct HardCodedLoadUserService;

#[async_trait]
impl LoadUserByCredentials for HardCodedLoadUserService {
    type User = User;

    async fn load_user(&self, login_token: &LoginToken) -> Result<Self::User, LoadUserError> {
        if (login_token.email == "anna" || login_token.email == "bob")
            && login_token.password == "test123"
        {
            Ok(User {
                name: login_token.email.to_owned(),
                email: format!("{}@example.org", login_token.email),
            })
        } else {
            Err(LoadUserError::LoginFailed)
        }
    }
}
