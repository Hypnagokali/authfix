use std::sync::Arc;

use actix_web::{
    dev::{AppService, HttpServiceFactory},
    guard::{Get, Post},
    web::{Data, Json, ServiceConfig},
    Error, HttpRequest, HttpResponse, Resource, Responder,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    login::{LoadUserService, LoginToken},
    multifactor::{CheckCodeError, MfaRegistry},
    web::{LOGIN_ROUTE, LOGOUT_ROUTE, MFA_ROUTE},
    AuthToken,
};

use super::session_auth::UserSession;

#[allow(clippy::type_complexity)]
pub struct SessionLoginHandler<T: LoadUserService, U> {
    user_service: Arc<T>,
    mfa_condition: Arc<Option<fn(&U, &HttpRequest) -> bool>>,
    is_with_mfa: bool,
}

impl<T, U> SessionLoginHandler<T, U>
where
    T: LoadUserService,
{
    pub fn new(user_service: T) -> Self {
        Self {
            user_service: Arc::new(user_service),
            mfa_condition: Arc::new(None),
            is_with_mfa: false,
        }
    }

    pub fn with_mfa_condition(
        user_service: T,
        mfa_condition: fn(&U, &HttpRequest) -> bool,
    ) -> Self {
        Self {
            user_service: Arc::new(user_service),
            mfa_condition: Arc::new(Some(mfa_condition)),
            is_with_mfa: true,
        }
    }

    pub fn is_with_mfa(&self) -> bool {
        self.is_with_mfa
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
                finally_rejected: true,
            },
        }
    }
}
#[derive(Deserialize)]
pub struct MfaRequestBody {
    code: String,
}

impl MfaRequestBody {
    pub fn get_code(&self) -> &str {
        &self.code
    }
}

async fn mfa_route(
    factor: MfaRegistry,
    body: Json<MfaRequestBody>,
    req: HttpRequest,
    session: UserSession,
) -> impl Responder {
    if let Some(f) = factor.get_value() {
        match f.check_code(body.get_code(), &req).await {
            Ok(_) => {
                session.mfa_challenge_done();
                HttpResponse::Ok().finish()
            }
            Err(e) => HttpResponse::Unauthorized().json(ErrorResponse::from(e)),
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

/// Triggers the code generation and sets the login state to mfa needed
/// Returns true if mfa needed
fn generate_code_if_mfa_necessary<U: Serialize>(
    // U will need a trait bound like 'HasFactor' -> user.get_factor() -> String
    user: &U,
    mfa_registry: &MfaRegistry,
    condition: &Option<fn(&U, &HttpRequest) -> bool>,
    req: &HttpRequest,
    session: &UserSession,
) -> Result<bool, Error> {
    let mut mfa_needed = false;

    if let Some(factor) = mfa_registry.get_value() {
        let is_condition_met = if let Some(condition) = condition {
            (condition)(user, req)
        } else {
            // if no condition is registered, mfa is necessary for every login
            true
        };

        if is_condition_met {
            factor.generate_code(req)?;
            session.needs_mfa(&factor.get_unique_id())?;
            mfa_needed = true;
        }
    }

    session.set_user(user)?;

    Ok(mfa_needed)
}

#[allow(clippy::type_complexity)]
async fn login<T: LoadUserService<User = U>, U: Serialize>(
    login_token: Json<LoginToken>,
    user_service: Data<Arc<T>>,
    mfa_condition: Data<Arc<Option<fn(&U, &HttpRequest) -> bool>>>,
    mfa_registry: MfaRegistry,
    session: UserSession,
    req: HttpRequest,
) -> Result<impl Responder, Error> {
    match user_service.load_user(&login_token).await {
        Ok(user) => {
            if !generate_code_if_mfa_necessary(
                &user,
                &mfa_registry,
                &mfa_condition,
                &req,
                &session,
            )? {
                // only call success handler if no mfa is required
                user_service.on_success_handler(&req, &user).await?;
            }

            session.set_user(user)?;
            Ok(HttpResponse::Ok())
        }
        Err(e) => {
            user_service.on_error_handler(&req).await?;
            Err(e.into())
        }
    }
}

impl<T, U> HttpServiceFactory for SessionLoginHandler<T, U>
where
    T: LoadUserService<User = U> + 'static,
    U: Serialize + DeserializeOwned + Clone + 'static,
{
    fn register(self, __config: &mut AppService) {
        let login_resource = Resource::new(LOGIN_ROUTE)
            .name("login")
            .guard(Post())
            .app_data(Data::new(Arc::clone(&self.user_service)))
            .app_data(Data::new(Arc::clone(&self.mfa_condition)))
            .to(login::<T, U>);
        HttpServiceFactory::register(login_resource, __config);

        let logout_resource = Resource::new(LOGOUT_ROUTE)
            .name("logout")
            .guard(Get())
            .to(logout::<U>);
        HttpServiceFactory::register(logout_resource, __config);

        if self.is_with_mfa() {
            let mfa_resource = Resource::new(MFA_ROUTE)
                .name("mfa")
                .guard(Post())
                .to(mfa_route);
            HttpServiceFactory::register(mfa_resource, __config);
        }
    }
}

async fn logout<U: DeserializeOwned + Clone>(token: AuthToken<U>) -> impl Responder {
    token.invalidate();
    HttpResponse::Ok()
}

pub fn login_config<
    L: LoadUserService<User = U> + 'static,
    U: Serialize + DeserializeOwned + Clone + 'static,
>(
    login_handler: SessionLoginHandler<L, U>,
) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config.service(login_handler);
    }
}
