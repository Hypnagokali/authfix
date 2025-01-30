use actix_web::{
    post,
    web::{self},
    HttpRequest, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};

use crate::{
    multifactor::{CheckCodeError, OptionalFactor},
    session::session_auth::UserSession,
};

// hardcoded routes
pub const LOGIN_ROUTE: &str = "/login";
pub const MFA_ROUTE: &str = "/login/mfa";

/// For a code request
#[derive(Deserialize)]
pub struct MfaRequestBody {
    code: String,
}

impl MfaRequestBody {
    pub fn get_code(&self) -> &str {
        &self.code
    }
}
/// Route handler to check multifactor code
#[post("/login/mfa")]
async fn mfa_route(
    factor: OptionalFactor,
    body: web::Json<MfaRequestBody>,
    req: HttpRequest,
    session: UserSession,
) -> impl Responder {
    if let Some(f) = factor.get_value() {
        match f.check_code(body.get_code(), &req).await {
            Ok(_) => {
                session.mfa_challenge_done();
                HttpResponse::Ok().finish()
            }
            Err(e) => HttpResponse::BadRequest().json(ErrorResponse::from(e)),
        }
    } else {
        HttpResponse::BadRequest().finish()
    }
}

pub fn add_mfa_route(cfg: &mut web::ServiceConfig) {
    cfg.service(mfa_route);
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
                finally_rejected: true,
            },
        }
    }
}
