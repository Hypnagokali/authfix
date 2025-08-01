use std::{
    future::{ready, Future},
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
};

use actix_web::{HttpMessage, HttpRequest};
use google_authenticator::GoogleAuthenticator;
use rand::RngCore;
use thiserror::Error;

use crate::{
    multifactor::factor::{CheckCodeError, Factor, GenerateCodeError},
    AuthToken,
};

/// ID to reference authenticator mfa
pub const MFA_ID_AUTHENTICATOR_TOTP: &str = "TOTP_MFA";

pub trait TotpSecretRepository {
    type User;
    fn auth_secret(
        &self,
        user: &Self::User,
    ) -> impl Future<Output = Result<String, GetTotpSecretError>>;
}

#[derive(Error, Debug)]
#[error("Retrieving TOTP secret failed: {msg}")]
pub struct GetTotpSecretError {
    msg: String,
}

impl GetTotpSecretError {
    pub fn new(msg: &str) -> Self {
        Self {
            msg: msg.to_owned(),
        }
    }
}

impl Default for GetTotpSecretError {
    fn default() -> Self {
        Self {
            msg: "Cannot get secret".to_owned(),
        }
    }
}

/// Authenticator factor.
///
/// Uses [TotpSecretRepository] to retrieve the shared secret.
///
/// You can use [AuthenticatorFactor::with_discrepancy] to set the discrepancy in seconds, to accept codes from another time slice (for example in the case of possible clock differences).
pub struct AuthenticatorFactor<T, U> {
    totp_secret_repo: Arc<T>,
    discrepancy: u64,
    phantom_data_user: PhantomData<U>,
}

impl<T, U> AuthenticatorFactor<T, U>
where
    T: TotpSecretRepository<User = U>,
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

impl AuthenticatorFactor<(), ()> {
    pub fn id() -> String {
        MFA_ID_AUTHENTICATOR_TOTP.to_owned()
    }
}

impl<T, U> Factor for AuthenticatorFactor<T, U>
where
    T: TotpSecretRepository<User = U> + 'static,
    U: 'static,
{
    fn generate_code(
        &self,
        _req: &actix_web::HttpRequest,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), GenerateCodeError>>>> {
        Box::pin(ready(Ok(())))
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
        let code_to_check = code.trim().to_owned();
        let discrepancy = self.discrepancy;
        Box::pin(async move {
            repo.auth_secret(&token_to_check.authenticated_user())
                .await
                .map(|secret| {
                    if Authenticator::verify(&secret, &code_to_check, discrepancy) {
                        Ok(())
                    } else {
                        Err(CheckCodeError::InvalidCode)
                    }
                })
                .unwrap_or_else(|e| {
                    Err(CheckCodeError::UnknownError(format!(
                        "Cannot check code: {e}"
                    )))
                })
        })
    }

    fn unique_id(&self) -> String {
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

    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Generate a QR-Code as SVG for 6 digit codes
    pub fn qr_code(&self) -> Result<String, SecretCodeGenerationError> {
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

/// Handles verification of a TOTP
pub struct Authenticator;

impl Authenticator {
    /// Verifies the provided code for a given secret.
    ///
    /// Discrepancy adds a tolerance in seconds, indicating how long ago the code could have been generated.
    ///
    /// To verify the secret via a code before saving it, you should set the discrepancy to the same value
    /// as used in [AuthenticatorFactor].
    pub fn verify(secret: &str, code: &str, discrepancy: u64) -> bool {
        let authenticator = GoogleAuthenticator::new();

        authenticator.verify_code(secret, code, discrepancy, 0)
    }
}

#[cfg(test)]
pub mod tests {
    use google_authenticator::GoogleAuthenticator;

    use crate::multifactor::factor_impl::authenticator::{
        Authenticator, AuthenticatorFactor, MFA_ID_AUTHENTICATOR_TOTP,
    };

    use super::TotpSecretGenerator;

    #[test]
    fn test_static_id() {
        assert_eq!(AuthenticatorFactor::id(), MFA_ID_AUTHENTICATOR_TOTP);
    }

    #[test]
    fn authenticator_should_verify_code() {
        let google_authenticator = GoogleAuthenticator::new();
        let secret = google_authenticator.create_secret(20);
        let code = google_authenticator.get_code(&secret, 0).unwrap();

        assert!(Authenticator::verify(&secret, &code, 0))
    }

    #[test]
    fn twenty_bytes_should_have_32_chars_in_base32() {
        let generator = TotpSecretGenerator::new("my_app", "johnson");
        let secret = generator.secret();

        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn codes_should_not_be_equal() {
        let generator = TotpSecretGenerator::new("my_app", "eli");
        let secret1 = generator.secret();

        let gen2 = TotpSecretGenerator::new("my_app", "eli");
        let secret2 = gen2.secret();

        assert_ne!(secret1, secret2);
    }

    #[test]
    fn should_generate_svg_with_200px() {
        let generator = TotpSecretGenerator::new("TestApp", "john.doe@example.org");
        let qr_code = generator.qr_code().unwrap();

        let start_svg =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><svg width=\"200\" height=\"200\"";
        let qr_code_slice_without_lbr = &qr_code.replace("\n", "").replace("\r", "")[0..100];
        assert!(qr_code_slice_without_lbr.starts_with(start_svg))
    }
}
