use authfix::{
    login::{LoadUserByCredentials, LoadUserError, LoginToken},
    multifactor::factor_impl::{
        authenticator::{GetTotpSecretError, TotpSecretRepository},
        random_code_auth::{CodeSendError, CodeSender, RandomCode},
    },
    session::AccountInfo,
};
use chrono::{Local, TimeDelta};
use serde::{Deserialize, Serialize};

// I am really not sure why cargo suddenly complains that TEST_OUT and test_out_path is not used. For now I mark it as allow(dead_code)
#[allow(dead_code)]
pub const TEST_OUT: &str = "test-out";

#[allow(dead_code)]
pub const SECRET: &str = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";

#[allow(dead_code)]
pub fn test_out_path(path: &str) -> String {
    format!("{TEST_OUT}/{path}")
}

//
// For login and mfa tests:
//
#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub email: String,
    pub name: String,
}

impl AccountInfo for User {}

pub struct HardCodedLoadUserService;

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

pub struct TotpTestRepo;

impl TotpSecretRepository for TotpTestRepo {
    type User = User;
    async fn auth_secret(&self, _user: &Self::User) -> Result<String, GetTotpSecretError> {
        Ok(SECRET.to_owned())
    }
}

pub struct DoNotSendCode;

impl CodeSender for DoNotSendCode {
    async fn send_code(&self, _: RandomCode) -> Result<(), CodeSendError> {
        Ok(())
    }
}

#[allow(dead_code)]
pub fn single_code_generator() -> RandomCode {
    let valid_until = Local::now()
        .checked_add_signed(TimeDelta::minutes(5))
        .unwrap();
    RandomCode::new("123abc", valid_until.into())
}
