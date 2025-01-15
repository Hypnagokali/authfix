use crate::multifactor::{CheckCodeError, GenerateCodeError, CodeFactor};

pub trait HasSecret {
    fn get_auth_secret(&self) -> Option<String>;
}

pub struct GoogleAuth<HasSecret> {
    has_secret: HasSecret,
}

impl<HasSecret> CodeFactor for GoogleAuth<HasSecret> {
    fn generate_code(&self, _req: &actix_web::HttpRequest) -> Result<Option<String>, GenerateCodeError> {
        Ok(None)
    }

    fn check_code(&self, code: &str) -> Result<(), CheckCodeError> {
        // validate sended code agains secret
        todo!()
    }
}