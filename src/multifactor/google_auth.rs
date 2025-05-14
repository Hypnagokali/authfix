use std::{
    future::{ready, Future},
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
};

use actix_web::{HttpMessage, HttpRequest};
use google_authenticator::GoogleAuthenticator;
use rand::RngCore;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::{
    multifactor::{CheckCodeError, Factor, GenerateCodeError, TotpSecretRepository},
    AuthToken,
};

/// ID to reference authenticator mfa
pub const MFA_ID_AUTHENTICATOR_TOTP: &str = "TOTP_MFA";

/// Authenticator authentication
///
/// Uses [TotpSecretRepository<U>] to retrieve the shared secret
/// Set discrepancy (in seconds) to accept codes from another time slice, for example in the case of possible clock differences
///
/// # Examples
/// ```ignore
/// App::new()
///    //...
///   .wrap(AuthMiddleware::<_, User>::new_with_factor(
///     SessionAuthProvider,
///     PathMatcher::default(),
///     Box::new(GoogleAuthFactor::<_, User>::new(Arc::clone(&your_totp_repository))),
///   )
/// )
/// ```
pub struct GoogleAuthFactor<T, U>
where
    T: TotpSecretRepository<U>,
    U: DeserializeOwned,
{
    totp_secret_repo: Arc<T>,
    discrepancy: u64,
    phantom_data_user: PhantomData<U>,
}

impl<T, U> GoogleAuthFactor<T, U>
where
    T: TotpSecretRepository<U>,
    U: DeserializeOwned + Clone,
{
    pub fn new(totp_secret_repo: Arc<T>) -> Self {
        Self::with_discrepancy(totp_secret_repo, 0)
    }
    pub fn with_discrepancy(totp_secret_repo: Arc<T>, discrepancy: u64) -> Self {
        Self {
            totp_secret_repo,
            discrepancy,
            phantom_data_user: PhantomData,
        }
    }
}

impl<T, U> Factor for GoogleAuthFactor<T, U>
where
    T: TotpSecretRepository<U> + 'static,
    U: DeserializeOwned + Clone + 'static,
{
    fn generate_code(&self, _req: &actix_web::HttpRequest) -> Result<(), GenerateCodeError> {
        Ok(())
    }

    fn check_code(
        &self,
        code: &str,
        req: &HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), CheckCodeError>>>> {
        let extensions = req.extensions();
        let token = match extensions.get::<AuthToken<U>>() {
            Some(token) => token,
            None => {
                return Box::pin(ready(Err(CheckCodeError::UnknownError(
                    "Cannot load AuthToken".to_owned(),
                ))))
            }
        };

        let token_to_check = AuthToken::from_ref(token);
        let repo = Arc::clone(&self.totp_secret_repo);
        let code_to_check = code.to_owned();
        let discrepancy = self.discrepancy;
        Box::pin(async move {
            let u = token_to_check.get_authenticated_user().clone();
            repo.get_auth_secret(&u)
                .await
                .map(|secret| {
                    let authenticator = GoogleAuthenticator::new();
                    if authenticator.verify_code(&secret, &code_to_check, discrepancy, 0) {
                        Ok(())
                    } else {
                        Err(CheckCodeError::InvalidCode)
                    }
                })
                .unwrap_or_else(|e| {
                    Err(CheckCodeError::UnknownError(format!(
                        "Cannot check code: {}",
                        e
                    )))
                })
        })
    }

    fn get_unique_id(&self) -> String {
        MFA_ID_AUTHENTICATOR_TOTP.to_owned()
    }
}

/// Helper to generate a valid shared secret and QR Code
///
/// Currently it generates only a secret with a length of 20 bytes
pub struct TotpSecretGenerator {
    secret: String,
    app_name: String,
    users_email: String,
}

impl TotpSecretGenerator {
    pub fn new(app_name: &str, users_email: &str) -> Self {
        Self {
            secret: Self::create_secret(),
            app_name: app_name.to_owned(),
            users_email: users_email.to_owned(),
        }
    }

    /// Currently uses a fixed size of 20 bytes
    fn create_secret() -> String {
        let mut secret_bytes = [0u8; 20];
        rand::rng().fill_bytes(&mut secret_bytes);

        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret_bytes)
    }

    pub fn get_secret(&self) -> &str {
        &self.secret
    }

    /// Generate a QR-Code as SVG for 6 digit codes
    pub fn get_qr_code(&self) -> Result<String, SecretCodeGenerationError> {
        let otpauth_value = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&digits=6",
            self.app_name, self.users_email, self.secret, self.app_name
        );
        qrcode_generator::to_svg_to_string(
            otpauth_value,
            qrcode_generator::QrCodeEcc::Low,
            200,
            Some("QR-Code for authentcator app"),
        )
        .map_err(|_| SecretCodeGenerationError::QrCodeGenerationError)
    }
}

#[derive(Error, Debug)]
pub enum SecretCodeGenerationError {
    #[error("Unable to generate QR code")]
    QrCodeGenerationError,
}

#[cfg(test)]
pub mod tests {
    use super::TotpSecretGenerator;

    #[test]
    fn twenty_bytes_should_have_32_chars_in_base32() {
        let gen = TotpSecretGenerator::new("my_app", "johnson");
        let code = gen.get_secret();

        assert_eq!(code.len(), 32);
    }

    #[test]
    fn codes_should_not_be_equal() {
        let gen = TotpSecretGenerator::new("my_app", "eli");
        let code1 = gen.get_secret();

        let gen2 = TotpSecretGenerator::new("my_app", "eli");
        let code2 = gen2.get_secret();

        assert_ne!(code1, code2);
    }

    #[test]
    fn should_generate_svg_with_200px() {
        let gen = TotpSecretGenerator::new("TestApp", "john.doe@example.org");
        let qr_code = gen.get_qr_code().unwrap();

        let start_svg =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><svg width=\"200\" height=\"200\"";
        let qr_code_slice_without_lbr = &qr_code.replace("\n", "").replace("\r", "")[0..100];
        assert!(qr_code_slice_without_lbr.starts_with(start_svg))
    }
}
