use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use actix_web::{
    dev::{AppService, HttpServiceFactory},
    guard::Post,
    web::{self, Data, Json, ServiceConfig},
    Error, HttpRequest, HttpResponse, Resource, Responder,
};
use log::{error, warn};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    config::Routes,
    login::{LoadUserByCredentials, LoginToken},
    multifactor::{CheckCodeError, MfaRegistry},
    AuthToken,
};

use super::session_auth::LoginSession;

#[derive(Serialize)]
enum LoginSessionStatus {
    Success,
    MfaNeeded,
}

/// The response informs for example the SPA if the login was successfull or if an mfa challenge is needed
///
/// To render the correct form, the frontend will need the mfa_id, that has to be globally unique
#[derive(Serialize)]
struct LoginSessionResponse {
    status: LoginSessionStatus,
    #[serde(rename = "mfaId")]
    mfa_id: Option<String>,
}

impl LoginSessionResponse {
    pub fn success() -> Self {
        Self {
            status: LoginSessionStatus::Success,
            mfa_id: None,
        }
    }

    pub fn needs_mfa(mfa_id: &str) -> Self {
        Self {
            status: LoginSessionStatus::MfaNeeded,
            mfa_id: Some(mfa_id.to_owned()),
        }
    }
}

/// An [Actix Web handler](https://actix.rs/docs/handlers/) for login, logout and multi factor auth validation
#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct SessionApiHandlers<T: LoadUserByCredentials<User = U>, U> {
    user_service: Arc<T>,
    mfa_condition: Option<fn(&U, &HttpRequest) -> bool>,
    with_mfa: bool,
    routes: Routes,
}

impl<T, U> SessionApiHandlers<T, U>
where
    U: DeserializeOwned + Serialize + Clone + 'static,
    T: LoadUserByCredentials<User = U> + 'static,
{
    /// Creates a handler that owns the [LoadUserService]
    ///
    /// It can be used, if the [LoadUserService] is only needed for login handling.
    pub fn new(user_service: T) -> Self {
        Self {
            user_service: Arc::new(user_service),
            mfa_condition: None,
            with_mfa: false,
            routes: Routes::default(),
        }
    }

    /// Creates a handler with a shared [LoadUserService]
    ///
    /// This method can be used, if the [LoadUserService] is a shared service.
    pub fn new_from_shared(user_service: Arc<T>) -> Self {
        Self {
            user_service: Arc::clone(&user_service),
            mfa_condition: None,
            with_mfa: false,
            routes: Routes::default(),
        }
    }

    // Creates a login handler with mfa and validation of the factor at each login
    pub fn with_mfa(self, mfa: bool) -> Self {
        Self {
            user_service: self.user_service,
            mfa_condition: self.mfa_condition,
            with_mfa: mfa,
            routes: self.routes,
        }
    }

    // Creates a login handler with mfa that will be triggered when the given condition is met
    pub fn with_mfa_condition(self, mfa_condition: fn(&U, &HttpRequest) -> bool) -> Self {
        Self {
            user_service: self.user_service,
            mfa_condition: Some(mfa_condition),
            with_mfa: self.with_mfa,
            routes: self.routes,
        }
    }

    pub fn with_routes(self, routes: Routes) -> Self {
        Self {
            user_service: self.user_service,
            mfa_condition: self.mfa_condition,
            with_mfa: self.with_mfa,
            routes,
        }
    }

    pub fn is_with_mfa(&self) -> bool {
        self.with_mfa
    }

    /// Configuration function to setup a [SessionLoginHandler]
    pub fn get_config(self) -> impl FnOnce(&mut ServiceConfig) {
        let routes = web::Data::new(self.routes.clone());

        |config: &mut ServiceConfig| {
            config.service(self);
            config.app_data(routes);
        }
    }
}

/// Request for validating the code
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
    session: LoginSession,
) -> Result<impl Responder, CheckCodeError> {
    if !session.is_mfa_needed() {
        warn!("Mfa route called although no mfa check is needed");
        return Ok(HttpResponse::BadRequest().finish());
    }

    if session.no_longer_valid() {
        session.destroy();
        return Err(CheckCodeError::FinallyRejected);
    }

    if let Some(f) = factor.get_value() {
        f.check_code(body.get_code(), &req).await?;
        session.mfa_challenge_done();
        Ok(HttpResponse::Ok().finish())
    } else {
        Ok(HttpResponse::Unauthorized().finish())
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
    session: &LoginSession,
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

    Ok(mfa_needed)
}

#[allow(clippy::type_complexity)]
async fn login<T: LoadUserByCredentials<User = U>, U: Serialize>(
    login_token: Json<LoginToken>,
    user_service: Data<Arc<T>>,
    mfa_condition: Data<Option<fn(&U, &HttpRequest) -> bool>>,
    mfa_registry: MfaRegistry,
    session: LoginSession,
    req: HttpRequest,
) -> Result<impl Responder, Error> {
    session.reset();

    match user_service.load_user(&login_token).await {
        Ok(user) => {
            let mut login_res = LoginSessionResponse::success();

            if !generate_code_if_mfa_necessary(
                &user,
                &mfa_registry,
                &mfa_condition,
                &req,
                &session,
            )? {
                // MFA not needed, call success handler
                user_service.on_success_handler(&req, &user).await?;
            } else {
                // set timeout for login session
                if let Some(validity) = SystemTime::now().checked_add(Duration::from_secs(60 * 5)) {
                    session.valid_until(validity)?;
                    if let Some(mfa_id) = session.get_mfa_id() {
                        login_res = LoginSessionResponse::needs_mfa(&mfa_id);
                    } else {
                        error!("Generate MFA challenge error: No mfa_id in session found");
                    }
                } else {
                    error!("Generate MFA challenge error: Cannot create validity");
                    return Ok(HttpResponse::InternalServerError().finish());
                }
            }

            session.set_user(user)?;
            Ok(HttpResponse::Ok().json(login_res))
        }
        Err(e) => {
            user_service.on_error_handler(&req).await?;
            session.destroy();
            Err(e.into())
        }
    }
}

impl<T, U> HttpServiceFactory for SessionApiHandlers<T, U>
where
    T: LoadUserByCredentials<User = U> + 'static,
    U: Serialize + DeserializeOwned + Clone + 'static,
{
    fn register(self, __config: &mut AppService) {
        if self.is_with_mfa() {
            let mfa_resource = Resource::new(self.routes.get_mfa())
                .name("mfa")
                .guard(Post())
                .to(mfa_route);
            HttpServiceFactory::register(mfa_resource, __config);
        }

        let login_resource = Resource::new(self.routes.get_login())
            .name("login")
            .guard(Post())
            .app_data(Data::new(self.user_service))
            .app_data(Data::new(self.mfa_condition))
            .to(login::<T, U>);
        HttpServiceFactory::register(login_resource, __config);

        let logout_resource = Resource::new(self.routes.get_logout())
            .name("logout")
            .guard(Post())
            .to(logout::<U>);
        HttpServiceFactory::register(logout_resource, __config);
    }
}

async fn logout<U: DeserializeOwned + Clone>(token: AuthToken<U>) -> impl Responder {
    token.invalidate();
    HttpResponse::Ok()
}
