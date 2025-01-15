use actix_web::HttpRequest;
use thiserror::Error;

pub trait CodeFactor {
    fn generate_code(&self, req: &HttpRequest) -> Result<Option<String>, GenerateCodeError>;
    fn check_code(&self, code: &str) -> Result<(), CheckCodeError>;
}


#[derive(Error, Debug)]
pub enum GenerateCodeError {
    #[error("can't generate code: {0}")]
    CodeGenerationError(String)
}


#[derive(Error, Debug)]
pub enum CheckCodeError {
    #[error("invalid code")]
    InvalidCode,
    #[error("login rejected. unauthorized")]
    FinallyRejected,
}

