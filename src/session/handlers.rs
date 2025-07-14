use std::{
    marker::PhantomData,
    sync::Arc,
    time::{Duration, SystemTime},
};

use crate::{
    errors::{HttpQuery, UnauthorizedError, UnauthorizedRedirect},
    helper::redirect_response_builder,
    login::{HandlerError, LoadUserByCredentials, LoadUserError, LoginToken},
    mfa::MfaConfig,
    middleware::PathMatcher,
    multifactor::{CheckCodeError, GenerateCodeError},
    session::SessionUser,
    AuthToken,
};
use actix_session::SessionInsertError;
use actix_web::{
    dev::{AppService, HttpServiceFactory},
    error::{ErrorBadRequest, ErrorInternalServerError, ErrorUnauthorized},
    guard::Post,
    http::header::LOCATION,
    web::{self, Data, Form, Json, ReqData, ServiceConfig},
    Error, HttpRequest, HttpResponse, HttpResponseBuilder, Resource, Responder,
};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{config::Routes, session_auth::LoginSession};

#[derive(Error, Debug)]
enum SessionApiMfaError {
    #[error("SessionApiMfaError error: `CheckCodeError: {0}`")]
    CodeError(CheckCodeError),
    #[error("SessionApiMfaError error: `BadRequest: {0}`")]
    BadRequest(String),
    #[error("SessionApiMfaError error: `InternalServerError: {0}`")]
    ServerError(String),
}

impl From<CheckCodeError> for SessionApiMfaError {
    fn from(value: CheckCodeError) -> Self {
        Self::CodeError(value)
    }
}

#[derive(Error, Debug)]
enum SessionApiLoginError {
    #[error("SessionApiLoginError error: `Unauthorized: {0}`")]
    Unauthorized(String),
    #[error("SessionApiLoginError error: `InternalServerError: {0}`")]
    ServerError(String),
}

impl From<HandlerError> for SessionApiLoginError {
    fn from(value: HandlerError) -> Self {
        SessionApiLoginError::ServerError(format!("HandlerError: {}", value))
    }
}

impl From<SessionInsertError> for SessionApiLoginError {
    fn from(value: SessionInsertError) -> Self {
        SessionApiLoginError::ServerError(format!("SessionInsertError: {}", value))
    }
}

impl From<LoadUserError> for SessionApiLoginError {
    fn from(value: LoadUserError) -> Self {
        // happens, if user not found or password wrong
        SessionApiLoginError::Unauthorized(format!("LoadUserError: {}", value))
    }
}

impl From<GenerateCodeError> for SessionApiLoginError {
    fn from(value: GenerateCodeError) -> Self {
        SessionApiLoginError::ServerError(format!("GenerateCodeError: {}", value))
    }
}

#[derive(Serialize, PartialEq)]
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
    routes: Arc<Routes>,
    redirect_flow: bool,
    phantom_data: PhantomData<T>,
}

impl<T, U> SessionApiHandlers<T, U>
where
    U: SessionUser + 'static,
    T: LoadUserByCredentials<User = U> + 'static,
{
    pub fn new(routes: Arc<Routes>, redirect_flow: bool) -> Self {
        Self {
            routes,
            redirect_flow,
            phantom_data: PhantomData,
        }
    }

    /// Returns the config that can be used by Actix Web to register the handlers
    pub fn get_config(self) -> impl FnOnce(&mut ServiceConfig) {
        let routes = web::Data::new(Arc::clone(&self.routes));

        |config: &mut ServiceConfig| {
            config.service(self);
            config.app_data(routes);
        }
    }
}

impl<T, U> Default for SessionApiHandlers<T, U>
where
    U: SessionUser + 'static,
    T: LoadUserByCredentials<User = U> + 'static,
{
    fn default() -> Self {
        Self {
            routes: Arc::new(Routes::default()),
            redirect_flow: false,
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

async fn logout_json<U: SessionUser>(token: AuthToken<U>) -> impl Responder {
    token.invalidate();

    HttpResponse::Ok()
}

async fn logout_form<U: SessionUser>(
    routes: Data<Arc<Routes>>,
    token: AuthToken<U>,
) -> impl Responder {
    token.invalidate();

    redirect_response_builder()
        .insert_header((LOCATION, routes.get_login()))
        .finish()
}

async fn mfa_route_json<U: SessionUser>(
    mfa_config: MfaConfig<U>,
    body: Json<MfaRequestBody>,
    req: HttpRequest,
    session: LoginSession,
) -> Result<impl Responder, Error> {
    mfa_internal(
        mfa_config,
        body.into_inner(),
        req,
        session,
        HttpResponse::Ok(),
    )
    .await
    .map_err(|err| match err {
        SessionApiMfaError::CodeError(check_code_error) => check_code_error.into(),
        SessionApiMfaError::BadRequest(msg) => ErrorBadRequest(msg),
        SessionApiMfaError::ServerError(msg) => ErrorInternalServerError(msg),
    })
}

async fn mfa_route_form<U: SessionUser>(
    mfa_config: MfaConfig<U>,
    body: Form<MfaRequestBody>,
    req: HttpRequest,
    routes: Data<Arc<Routes>>,
    session: LoginSession,
) -> Result<impl Responder, Error> {
    let user_ident = match session.get_user::<U>() {
        Some(u) => u.get_user_identification(),
        None => "Unknown user".to_owned(),
    };

    match mfa_internal(
        mfa_config,
        body.into_inner(),
        req.clone(),
        session,
        redirect_response_builder(),
    )
    .await
    {
        Ok(mut res) => {
            let mut query: HttpQuery = req.query_string().into();
            query.remove("error");

            let redirect = build_login_success_redirect(query, routes);

            Ok(res.insert_header((LOCATION, redirect)).finish())
        }
        Err(err) => match err {
            SessionApiMfaError::CodeError(check_code_error) => {
                debug!("{}: {}", user_ident, check_code_error);

                let mut query: HttpQuery = req.query_string().into();
                query.insert_without_value("error");

                Ok(redirect_response_builder()
                    .insert_header((
                        LOCATION,
                        format!("{}?{}", routes.get_mfa(), query.to_string()),
                    ))
                    .finish())
            }
            SessionApiMfaError::BadRequest(msg) => Err(ErrorBadRequest(msg)),
            SessionApiMfaError::ServerError(msg) => Err(ErrorInternalServerError(msg)),
        },
    }
}

async fn mfa_internal<U: SessionUser>(
    mfa_config: MfaConfig<U>,
    body: MfaRequestBody,
    req: HttpRequest,
    session: LoginSession,
    // we need the response here, which we want to return to the user
    res: HttpResponseBuilder,
) -> Result<HttpResponseBuilder, SessionApiMfaError> {
    if !session.is_mfa_needed() {
        return Err(SessionApiMfaError::BadRequest(
            "Mfa route called although no mfa check is needed".to_owned(),
        ));
    }

    if session.no_longer_valid() {
        session.destroy();
        return Err(CheckCodeError::FinallyRejected.into());
    }

    if session.get_user::<U>().is_none() {
        return Err(SessionApiMfaError::BadRequest(
            "Mfa route called but no user was present in LoginSession".to_owned(),
        ));
    }

    let user: U = session.get_user().unwrap();

    if let Some(f) = mfa_config.get_factor_by_user(&user).await {
        f.check_code(body.get_code(), &req).await?;
        session.mfa_challenge_done();
        Ok(mfa_config.handle_success(&user, res).await)
    } else {
        session.destroy();
        Err(SessionApiMfaError::ServerError(
            "No factor returned for user".to_owned(),
        ))
    }
}

/// Triggers the code generation and sets the login state to mfa needed
/// Returns true if mfa needed
async fn generate_code_if_mfa_necessary<U: SessionUser>(
    // U will need a trait bound like 'HasFactor' -> user.get_factor() -> String
    user: &U,
    mfa_config: MfaConfig<U>,
    req: &HttpRequest,
    session: &LoginSession,
) -> Result<bool, SessionApiLoginError> {
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

async fn login_internal<T: LoadUserByCredentials<User = U>, U: SessionUser>(
    login_token: LoginToken,
    user_service: Arc<T>,
    mfa_config: MfaConfig<U>,
    session: LoginSession,
    req: HttpRequest,
) -> Result<LoginSessionResponse, SessionApiLoginError> {
    session.reset();
    match user_service.load_user(&login_token).await {
        Ok(user) => {
            if user.is_user_disabled() {
                return Err(SessionApiLoginError::Unauthorized(format!(
                    "User '{}' attempt to login but the user is disabled",
                    user.get_user_identification()
                )));
            }

            if user.is_account_locked() {
                return Err(SessionApiLoginError::Unauthorized(format!(
                    "User '{}' attempt to login but the account is locked",
                    user.get_user_identification()
                )));
            }

            let mut login_res = LoginSessionResponse::success();

            if !generate_code_if_mfa_necessary(&user, mfa_config.clone(), &req, &session).await? {
                // MFA not needed, call success handler
                user_service.on_success_handler(&req, &user).await?;
            } else {
                // set timeout for login session
                if let Some(validity) = SystemTime::now()
                    .checked_add(Duration::from_secs(mfa_config.get_timeout_in_seconds()))
                {
                    session.valid_until(validity)?;
                    if let Some(mfa_id) = session.get_mfa_id() {
                        login_res = LoginSessionResponse::needs_mfa(&mfa_id);
                    } else {
                        return Err(SessionApiLoginError::ServerError(
                            "Generate MFA challenge error: No mfa_id in session found".to_owned(),
                        ));
                    }
                } else {
                    return Err(SessionApiLoginError::ServerError(
                        "Generate MFA challenge error: Cannot create login session timeout"
                            .to_owned(),
                    ));
                }
            }

            session.set_user(user)?;
            Ok(login_res)
        }
        Err(e) => {
            user_service.on_error_handler(&req).await?;
            session.destroy();
            Err(e.into())
        }
    }
}

#[allow(clippy::type_complexity)]
async fn login_form<T: LoadUserByCredentials<User = U>, U: SessionUser>(
    login_token: Form<LoginToken>,
    user_service: ReqData<Arc<T>>,
    mfa_config: MfaConfig<U>,
    session: LoginSession,
    req: HttpRequest,
    routes: Data<Arc<Routes>>,
) -> Result<impl Responder, Error> {
    let login_res = login_internal(
        login_token.into_inner(),
        user_service.into_inner(),
        mfa_config,
        session,
        req.clone(),
    )
    .await
    .map_err(|err| match err {
        SessionApiLoginError::Unauthorized(err) => {
            debug!("{err}");
            let mut query: HttpQuery = req.query_string().into();
            query.insert_without_value("error");
            UnauthorizedError::new_redirect(UnauthorizedRedirect::new_with_query_string(
                routes.get_login(),
                query,
            ))
            .into()
        }
        SessionApiLoginError::ServerError(err) => {
            error!("{err}");
            ErrorInternalServerError("")
        }
    })?;

    if login_res.status == LoginSessionStatus::MfaNeeded {
        let mut query: HttpQuery = req.query_string().into();
        query.remove("error");

        Ok(redirect_response_builder()
            .insert_header((
                LOCATION,
                format!("{}?{}", routes.get_mfa(), query.to_string()),
            ))
            .finish())
    } else {
        let mut query: HttpQuery = req.query_string().into();
        query.remove("error");

        let redirect = build_login_success_redirect(query, routes);

        Ok(redirect_response_builder()
            .insert_header((LOCATION, redirect))
            .finish())
    }
}

#[allow(clippy::type_complexity)]
async fn login_json<T: LoadUserByCredentials<User = U>, U: SessionUser>(
    login_token: Json<LoginToken>,
    user_service: ReqData<Arc<T>>,
    mfa_config: MfaConfig<U>,
    session: LoginSession,
    req: HttpRequest,
) -> Result<impl Responder, Error> {
    let login_res = login_internal(
        login_token.into_inner(),
        user_service.into_inner(),
        mfa_config,
        session,
        req,
    )
    .await
    .map_err(|err| match err {
        SessionApiLoginError::Unauthorized(err) => {
            error!("{err}");
            ErrorUnauthorized("")
        }
        SessionApiLoginError::ServerError(err) => {
            error!("{err}");
            ErrorInternalServerError("")
        }
    })?;

    Ok(HttpResponse::Ok().json(login_res))
}

impl<T, U> HttpServiceFactory for SessionApiHandlers<T, U>
where
    T: LoadUserByCredentials<User = U> + 'static,
    U: SessionUser + 'static,
{
    fn register(self, config: &mut AppService) {
        let mut mfa_resource = Resource::new(self.routes.get_mfa())
            .name("mfa")
            .guard(Post());

        let mut login_resource = Resource::new(self.routes.get_login())
            .name("login")
            .guard(Post());

        let mut logout_resource = Resource::new(self.routes.get_logout())
            .name("logout")
            .guard(Post());

        if self.redirect_flow {
            login_resource = login_resource.to(login_form::<T, U>);
            mfa_resource = mfa_resource.to(mfa_route_form::<U>);
            logout_resource = logout_resource.to(logout_form::<U>);
        } else {
            login_resource = login_resource.to(login_json::<T, U>);
            mfa_resource = mfa_resource.to(mfa_route_json::<U>);
            logout_resource = logout_resource.to(logout_json::<U>);
        }

        HttpServiceFactory::register(mfa_resource, config);
        HttpServiceFactory::register(login_resource, config);
        HttpServiceFactory::register(logout_resource, config);
    }
}

fn build_login_success_redirect(mut query: HttpQuery, routes: Data<Arc<Routes>>) -> String {
    query
        .remove("redirect_uri")
        .and_then(|uri| urlencoding::decode(&uri).ok().map(|s| s.into_owned()))
        .map(|uri| {
            if PathMatcher::are_equal(&uri, routes.get_login())
                || PathMatcher::are_equal(&uri, routes.get_mfa())
                || PathMatcher::are_equal(&uri, routes.get_logout())
            {
                "/".to_owned()
            } else {
                uri
            }
        })
        .unwrap_or(routes.get_default_redirect().to_owned())
}
