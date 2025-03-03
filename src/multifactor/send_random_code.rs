use std::future::Future;

use actix_session::SessionExt;
use actix_web::HttpRequest;

use super::{CheckCodeError, Factor, GenerateCodeError};

const MFA_RANDOM_CODE_KEY: &str = "mfa_random_code";

pub trait CodeSender {
    type Error: std::error::Error + 'static;
    fn send_code(&self, code: &str) -> Result<(), Self::Error>;
}

pub struct MfaRandomCode<T: CodeSender> {
    code_generator: fn() -> String,
    code_sender: T,
}

impl<T: CodeSender> Factor for MfaRandomCode<T> {
    fn generate_code(&self, req: &HttpRequest) -> Result<(), GenerateCodeError> {
        let code = (self.code_generator)();
        // Currently using session. Maybe 
        let session = req.get_session();
        match session.insert(MFA_RANDOM_CODE_KEY, code.clone()) {
            Ok(_) => {
                match self.code_sender.send_code(&code) {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        session.remove(MFA_RANDOM_CODE_KEY);
                        Err(GenerateCodeError::new_with_cause("Could not send code to user", e))
                    },
                }
            },
            Err(e) => Err(GenerateCodeError::new_with_cause("Could not insert random code for mfa into session", e)),
        }
    }

    fn get_unique_id(&self) -> String {
        "RNDCODE".to_owned()
    }

    fn check_code(
        &self,
        code: &str,
        req: &HttpRequest,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), CheckCodeError>>>> {
        let session = req.get_session();
        let owned_code = code.to_owned();
        match session.get::<String>(MFA_RANDOM_CODE_KEY) {
            Ok(Some(saved_code)) => {
                Box::pin(async move { 
                    if saved_code == owned_code {
                        Ok(())
                    } else {
                        Err(CheckCodeError::InvalidCode)
                    }
                })
            },
            _ => Box::pin(async {
                Err(CheckCodeError::UnknownError("Could not check code. There is no code saved in the session".to_owned()))
            }),
        }
    }
}