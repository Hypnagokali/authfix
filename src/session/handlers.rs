use std::{
    marker::PhantomData,
    sync::Arc,
    time::{Duration, SystemTime},
};

use crate::{
    config::Routes,
    login::{LoadUserByCredentials, LoginToken},
    mfa::MfaConfig,
    multifactor::CheckCodeError,
    AuthToken,
};
use actix_web::{
    dev::{AppService, HttpServiceFactory},
    guard::Post,
    web::{self, Json, ReqData, ServiceConfig},
    Error, HttpRequest, HttpResponse, Resource, Responder,
};
use log::{error, warn};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

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
    routes: Routes,
    phantom_data: PhantomData<T>,
}

impl<T, U> SessionApiHandlers<T, U>
where
    U: DeserializeOwned + Serialize + Clone + 'static,
    T: LoadUserByCredentials<User = U> + 'static,
{
    pub fn new(routes: Routes) -> Self {
        Self {
            routes,
            phantom_data: PhantomData,
        }
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

impl<T, U> Default for SessionApiHandlers<T, U>
where
    U: DeserializeOwned + Serialize + Clone + 'static,
    T: LoadUserByCredentials<User = U> + 'static,
{
    fn default() -> Self {
        Self {
            routes: Routes::default(),
            phantom_data: PhantomData,
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

async fn mfa_route<U: Serialize + DeserializeOwned + Clone>(
    mfa_config: MfaConfig<U>,
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

    if session.get_user::<U>().is_none() {
        error!("Mfa route called but no user was present in LoginSession");
        return Ok(HttpResponse::BadRequest().finish());
    }

    let user: U = session.get_user().unwrap();

    if let Some(f) = mfa_config.get_factor_by_user(&user).await {
        f.check_code(body.get_code(), &req).await?;
        session.mfa_challenge_done();
        Ok(mfa_config
            .handle_success(&user, HttpResponse::Ok().finish())
            .await)
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}

/// Triggers the code generation and sets the login state to mfa needed
/// Returns true if mfa needed
async fn generate_code_if_mfa_necessary<U: Serialize + DeserializeOwned + Clone>(
    // U will need a trait bound like 'HasFactor' -> user.get_factor() -> String
    user: &U,
    mfa_config: MfaConfig<U>,
    req: &HttpRequest,
    session: &LoginSession,
) -> Result<bool, Error> {
    if !mfa_config.is_configured() {
        return Ok(false);
    }

    let mut mfa_needed = false;

    if let Some(factor) = mfa_config.get_factor_by_user(user).await {
        if mfa_config.is_condition_met(user, req.clone()).await {
            factor.generate_code(req).await?;
            session.needs_mfa(&factor.get_unique_id())?;
            mfa_needed = true;
        }
    }

    Ok(mfa_needed)
}

#[allow(clippy::type_complexity)]
async fn login<T: LoadUserByCredentials<User = U>, U: Serialize + DeserializeOwned + Clone>(
    login_token: Json<LoginToken>,
    user_service: ReqData<Arc<T>>,
    mfa_config: MfaConfig<U>,
    session: LoginSession,
    req: HttpRequest,
) -> Result<impl Responder, Error> {
    session.reset();
    match user_service.load_user(&login_token).await {
        Ok(user) => {
            let mut login_res = LoginSessionResponse::success();

            if !generate_code_if_mfa_necessary(&user, mfa_config.clone(), &req, &session).await? {
                // MFA not needed, call success handler
                user_service.on_success_handler(&req, &user).await?;
            } else {
                // set timeout for login session
                if let Some(validity) = SystemTime::now().checked_add(Duration::from_secs(mfa_config.get_timeout_in_seconds())) {
                    session.valid_until(validity)?;
                    if let Some(mfa_id) = session.get_mfa_id() {
                        login_res = LoginSessionResponse::needs_mfa(&mfa_id);
                    } else {
                        error!("Generate MFA challenge error: No mfa_id in session found");
                    }
                } else {
                    error!("Generate MFA challenge error: Cannot create login session timeout");
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
    fn register(self, config: &mut AppService) {
        let mfa_resource = Resource::new(self.routes.get_mfa())
            .name("mfa")
            .guard(Post())
            .to(mfa_route::<U>);
        HttpServiceFactory::register(mfa_resource, config);

        let login_resource = Resource::new(self.routes.get_login())
            .name("login")
            .guard(Post())
            .to(login::<T, U>);
        HttpServiceFactory::register(login_resource, config);

        let logout_resource = Resource::new(self.routes.get_logout())
            .name("logout")
            .guard(Post())
            .to(logout::<U>);
        HttpServiceFactory::register(logout_resource, config);
    }
}

async fn logout<U: DeserializeOwned + Clone>(token: AuthToken<U>) -> impl Responder {
    token.invalidate();
    HttpResponse::Ok()
}
