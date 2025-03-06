use std::future::ready;

use actix_web::HttpRequest;
use auth_middleware_for_actix_web::login::{HandlerError, LoadUserError, LoadUserService, LoginToken};
use futures::future::LocalBoxFuture;
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

pub struct HardCodedLoadUserService {}

impl LoadUserService for HardCodedLoadUserService {
    type User = User;

    fn load_user(
        &self,
        login_token: &LoginToken,
    ) -> LocalBoxFuture<'_, Result<Self::User, LoadUserError>> {
        if (login_token.username == "anna" || login_token.username == "bob")
            && login_token.password == "test123"
        {
            Box::pin(ready(Ok(User {
                name: login_token.username.to_owned(),
                email: format!("{}@example.org", login_token.username),
            })))
        } else {
            Box::pin(ready(Err(LoadUserError::LoginFailed)))
        }
    }

    fn on_success_handler(
        &self,
        _req: &HttpRequest,
        _user: &Self::User,
    ) -> LocalBoxFuture<'_, Result<(), HandlerError>> {
        Box::pin(ready(Ok(())))
    }

    fn on_error_handler(&self, _req: &HttpRequest) -> LocalBoxFuture<'_, Result<(), HandlerError>> {
        Box::pin(ready(Ok(())))
    }
}
