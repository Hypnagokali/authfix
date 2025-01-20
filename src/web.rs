use serde::{Deserialize, Serialize};

use crate::multifactor::CheckCodeError;


// hardcoded routes
pub const LOGIN_ROUTE: &str = "/login";
pub const MFA_ROUTE: &str = "/login/mfa*";

/// For a code request
#[derive(Deserialize)]
pub struct MfaRequestBody {
    code: String
}

impl MfaRequestBody {
    pub fn get_code(&self) -> &str {
        &self.code
    }
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub message: String,
    #[serde(rename = "finallyRejected")]
    pub finally_rejected: bool,
}

impl From<CheckCodeError> for ErrorResponse {
    fn from(value: CheckCodeError) -> Self {
        let msg = "invalid code";
        match value {
            CheckCodeError::InvalidCode => Self {
                message: msg.to_owned(),
                finally_rejected: false,
            },
            CheckCodeError::FinallyRejected => Self {
                message: msg.to_owned(),
                finally_rejected: true,
            },
            CheckCodeError::UnknownError(message) => Self {
                message,
                finally_rejected: true
            },
        }
    }
}