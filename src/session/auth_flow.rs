//! Authentication flow for [SessionAuthProvider](crate::session::session_auth::SessionAuthProvider)
//!
//! Its main component is [SessionAuthFlow] which configures the authentication related handlers like: login, logout, mfa.
//! If you use the `redirect_flow`, you can use [LoginError] to check whether an error has occurred.
//!
//! *It should not be necessary to construct the [SessionAuthFlow] by hand, instead you should really use
//! [SessionLoginAppBuilder](crate::session::app_builder::SessionLoginAppBuilder) to construct an [App](actix_web::App) with session authentication.*
//!
//! # Example
//! ```ignore
//! App::new()
//!     .configure(
//!         SessionAuthFlow::<YourLoadUserByCredentialsType, User>::default().config())
//!     .wrap(/* AuthMiddleware with AuthProvider */)
//!     .wrap(/* SessionMiddleware (actix) */);
//! ```
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::Arc,
    time::{Duration, SystemTime},
};

use crate::{
    errors::{HttpQuery, UnauthorizedError, UnauthorizedRedirect},
    helper::redirect_response_builder,
    login::{
        FailureHandler, HandlerError, LoadUserByCredentials, LoadUserError, LoginToken,
        SuccessHandler,
    },
    middleware::PathMatcher,
    multifactor::{
        config::MfaConfig,
        factor::{CheckCodeError, GenerateCodeError},
    },
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

/// This struct can be used in combination with [Query](actix_web::web::Query) to capture the error parameter
/// The error parameter is set, if the login fails or the user provides an invalid MFA code.
///
/// # Example
/// ```no_run
/// use actix_web::{get, web::Query, Responder, HttpResponse};
/// use authfix::session::auth_flow::LoginError;
///
/// #[get("/login")]
/// async fn login(query: Query<LoginError>) -> impl Responder {
///     if query.is_error() {
///        println!("Login failed");
///     }
///
///     HttpResponse::Ok().body("...")
/// }
/// ```
#[derive(Deserialize)]
pub struct LoginError {
    error: Option<String>,
}

impl LoginError {
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

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

impl From<HandlerError> for SessionApiMfaError {
    fn from(value: HandlerError) -> Self {
        SessionApiMfaError::ServerError(format!("HandlerError: {value}"))
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
        SessionApiLoginError::ServerError(format!("HandlerError: {value}"))
    }
}

impl From<SessionInsertError> for SessionApiLoginError {
    fn from(value: SessionInsertError) -> Self {
        SessionApiLoginError::ServerError(format!("SessionInsertError: {value}"))
    }
}

impl From<LoadUserError> for SessionApiLoginError {
    fn from(value: LoadUserError) -> Self {
        // happens, if user not found or password wrong
        SessionApiLoginError::Unauthorized(format!("LoadUserError: {value}"))
    }
}

impl From<GenerateCodeError> for SessionApiLoginError {
    fn from(value: GenerateCodeError) -> Self {
        SessionApiLoginError::ServerError(format!("GenerateCodeError: {value}"))
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

/// Registers [Actix Web handler](https://actix.rs/docs/handlers/) for login, logout and mfa.
#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct SessionAuthFlow<T: LoadUserByCredentials<User = U>, U> {
    routes: Routes,
    redirect_flow: bool,
    phantom_data: PhantomData<T>,
}

impl<T, U> SessionAuthFlow<T, U>
where
    U: SessionUser + 'static,
    T: LoadUserByCredentials<User = U> + 'static,
{
    pub fn new(routes: Routes, redirect_flow: bool) -> Self {
        Self {
            routes,
            redirect_flow,
            phantom_data: PhantomData,
        }
    }

    /// Returns the config that can be used by Actix Web to register the handlers
    pub fn config(self) -> impl FnOnce(&mut ServiceConfig) {
        let routes = web::Data::new(self.routes.clone());

        |config: &mut ServiceConfig| {
            config.service(self);
            config.app_data(routes);
        }
    }
}

impl<T, U> Default for SessionAuthFlow<T, U>
where
    U: SessionUser + 'static,
    T: LoadUserByCredentials<User = U> + 'static,
{
    fn default() -> Self {
        Self {
            routes: Routes::default(),
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
    pub fn code(&self) -> &str {
        &self.code
    }
}

async fn logout_json<U: SessionUser>(token: AuthToken<U>) -> impl Responder {
    token.invalidate();

    HttpResponse::Ok()
}

async fn logout_form<U: SessionUser>(routes: Data<Routes>, token: AuthToken<U>) -> impl Responder {
    token.invalidate();

    redirect_response_builder()
        .insert_header((LOCATION, routes.login()))
        .finish()
}

async fn mfa_route_json<U: SessionUser>(
    mfa_config: MfaConfig<U>,
    error_handler: ReqData<Rc<Option<Box<dyn FailureHandler>>>>,
    success_handler: ReqData<Rc<Option<Box<dyn SuccessHandler<User = U>>>>>,
    body: Json<MfaRequestBody>,
    req: HttpRequest,
    session: LoginSession,
) -> Result<impl Responder, Error> {
    mfa_internal(
        mfa_config,
        error_handler.into_inner(),
        success_handler.into_inner(),
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
    error_handler: ReqData<Rc<Option<Box<dyn FailureHandler>>>>,
    success_handler: ReqData<Rc<Option<Box<dyn SuccessHandler<User = U>>>>>,
    body: Form<MfaRequestBody>,
    req: HttpRequest,
    routes: Data<Routes>,
    session: LoginSession,
) -> Result<impl Responder, Error> {
    let user_ident = match session.user::<U>() {
        Some(u) => u.user_identification(),
        None => "Unknown user".to_owned(),
    };

    match mfa_internal(
        mfa_config,
        error_handler.into_inner(),
        success_handler.into_inner(),
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
                debug!("{user_ident}: {check_code_error}");

                let mut query: HttpQuery = req.query_string().into();
                query.insert_without_value("error");

                Ok(redirect_response_builder()
                    .insert_header((LOCATION, format!("{}?{}", routes.mfa(), query.to_string())))
                    .finish())
            }
            SessionApiMfaError::BadRequest(msg) => Err(ErrorBadRequest(msg)),
            SessionApiMfaError::ServerError(msg) => Err(ErrorInternalServerError(msg)),
        },
    }
}

async fn mfa_internal<U: SessionUser>(
    mfa_config: MfaConfig<U>,
    error_handler: Rc<Option<Box<dyn FailureHandler>>>,
    success_handler: Rc<Option<Box<dyn SuccessHandler<User = U>>>>,
    body: MfaRequestBody,
    req: HttpRequest,
    session: LoginSession,
    res: HttpResponseBuilder,
) -> Result<HttpResponseBuilder, SessionApiMfaError> {
    if !session.is_mfa_needed() {
        return Err(SessionApiMfaError::BadRequest(
            "Mfa route called although no mfa check is needed".to_owned(),
        ));
    }

    if session.no_longer_valid() {
        session.destroy();
        handle_error(error_handler, req).await?;
        return Err(CheckCodeError::FinallyRejected.into());
    }

    if session.user::<U>().is_none() {
        handle_error(error_handler, req).await?;
        return Err(SessionApiMfaError::BadRequest(
            "Mfa route called but no user was present in LoginSession".to_owned(),
        ));
    }

    let user: U = session.user().unwrap();

    if let Some(f) = mfa_config.factor_by_user(&user).await {
        match f.check_code(body.code(), &req).await {
            Ok(_) => {}
            Err(e) => {
                handle_error(error_handler, req).await?;
                return Err(e.into());
            }
        }
        session.mfa_challenge_done();
        handle_success(success_handler, req, &user).await?;
        Ok(mfa_config.handle_success(&user, res).await)
    } else {
        session.destroy();
        handle_error(error_handler, req).await?;
        Err(SessionApiMfaError::ServerError(
            "No factor returned for user".to_owned(),
        ))
    }
}

/// Triggers the code generation and sets the login state to mfa needed
/// Returns true if mfa needed
async fn generate_code_if_mfa_necessary<U: SessionUser>(
    user: &U,
    mfa_config: MfaConfig<U>,
    req: &HttpRequest,
    session: &LoginSession,
) -> Result<(), SessionApiLoginError> {
    if let Some(factor) = mfa_config.factor_by_user(user).await {
        factor.generate_code(req).await?;
        session.set_needs_mfa(&factor.unique_id())?;
    } else {
        session.destroy();
        return Err(SessionApiLoginError::ServerError(format!(
            "MFA challenge error: No factor found for user: {}",
            user.user_identification()
        )));
    }

    Ok(())
}

async fn login_internal<T: LoadUserByCredentials<User = U>, U: SessionUser>(
    login_token: LoginToken,
    user_service: Arc<T>,
    mfa_config: MfaConfig<U>,
    error_handler: Rc<Option<Box<dyn FailureHandler>>>,
    success_handler: Rc<Option<Box<dyn SuccessHandler<User = U>>>>,
    session: LoginSession,
    req: HttpRequest,
) -> Result<LoginSessionResponse, SessionApiLoginError> {
    session.reset();
    match user_service.load_user(&login_token).await {
        Ok(user) => {
            if user.is_user_disabled() {
                return Err(SessionApiLoginError::Unauthorized(format!(
                    "User '{}' attempt to login but the user is disabled",
                    user.user_identification()
                )));
            }

            if user.is_account_locked() {
                return Err(SessionApiLoginError::Unauthorized(format!(
                    "User '{}' attempt to login but the account is locked",
                    user.user_identification()
                )));
            }

            let mut login_res = LoginSessionResponse::success();

            if mfa_config.is_configured() && mfa_config.is_condition_met(&user, req.clone()).await {
                // Set session validity
                if let Some(validity) = SystemTime::now()
                    .checked_add(Duration::from_secs(mfa_config.timeout_in_seconds()))
                {
                    session.valid_until(validity)?;
                } else {
                    return Err(SessionApiLoginError::ServerError(
                        "Generate MFA challenge error: Cannot create login session timeout"
                            .to_owned(),
                    ));
                }

                session.set_user(&user).inspect_err(|_| {
                    session.destroy();
                })?;

                generate_code_if_mfa_necessary(&user, mfa_config.clone(), &req, &session)
                    .await
                    .inspect_err(|_| {
                        session.destroy();
                    })?;

                if let Some(mfa_id) = session.mfa_id() {
                    login_res = LoginSessionResponse::needs_mfa(&mfa_id);
                } else {
                    return Err(SessionApiLoginError::ServerError(
                        "Generate MFA challenge error: No mfa_id in session found".to_owned(),
                    ));
                }
            } else {
                handle_success(success_handler, req, &user).await?;
            }

            session.set_user(&user)?;
            Ok(login_res)
        }
        Err(e) => {
            handle_error(error_handler, req).await?;

            session.destroy();
            Err(e.into())
        }
    }
}

#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
async fn login_form<T: LoadUserByCredentials<User = U>, U: SessionUser>(
    login_token: Form<LoginToken>,
    user_service: ReqData<Arc<T>>,
    error_handler: ReqData<Rc<Option<Box<dyn FailureHandler>>>>,
    success_handler: ReqData<Rc<Option<Box<dyn SuccessHandler<User = U>>>>>,
    mfa_config: MfaConfig<U>,
    session: LoginSession,
    req: HttpRequest,
    routes: Data<Routes>,
) -> Result<impl Responder, Error> {
    let login_res = login_internal(
        login_token.into_inner(),
        user_service.into_inner(),
        mfa_config,
        error_handler.into_inner(),
        success_handler.into_inner(),
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
                routes.login(),
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
            .insert_header((LOCATION, format!("{}?{}", routes.mfa(), query.to_string())))
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
    error_handler: ReqData<Rc<Option<Box<dyn FailureHandler>>>>,
    success_handler: ReqData<Rc<Option<Box<dyn SuccessHandler<User = U>>>>>,
    mfa_config: MfaConfig<U>,
    session: LoginSession,
    req: HttpRequest,
) -> Result<impl Responder, Error> {
    let login_res = login_internal(
        login_token.into_inner(),
        user_service.into_inner(),
        mfa_config,
        error_handler.into_inner(),
        success_handler.into_inner(),
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

impl<T, U> HttpServiceFactory for SessionAuthFlow<T, U>
where
    T: LoadUserByCredentials<User = U> + 'static,
    U: SessionUser + 'static,
{
    fn register(self, config: &mut AppService) {
        let mut mfa_resource = Resource::new(self.routes.mfa()).name("mfa").guard(Post());

        let mut login_resource = Resource::new(self.routes.login())
            .name("login")
            .guard(Post());

        let mut logout_resource = Resource::new(self.routes.logout())
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

fn build_login_success_redirect(mut query: HttpQuery, routes: Data<Routes>) -> String {
    query
        .remove("redirect_uri")
        .and_then(|uri| urlencoding::decode(&uri).ok().map(|s| s.into_owned()))
        .map(|uri| {
            if PathMatcher::are_equal(&uri, routes.login())
                || PathMatcher::are_equal(&uri, routes.mfa())
                || PathMatcher::are_equal(&uri, routes.logout())
            {
                "/".to_owned()
            } else {
                uri
            }
        })
        .unwrap_or(routes.default_redirect().to_owned())
}

async fn handle_success<U>(
    success_handler: Rc<Option<Box<dyn SuccessHandler<User = U>>>>,
    req: HttpRequest,
    user: &U,
) -> Result<(), HandlerError> {
    if let Some(handler) = success_handler.as_ref() {
        handler.on_success(user, req).await?
    }

    Ok(())
}

async fn handle_error(
    error_handler: Rc<Option<Box<dyn FailureHandler>>>,
    req: HttpRequest,
) -> Result<(), HandlerError> {
    if let Some(handler) = error_handler.as_ref() {
        handler.on_failure(req).await?
    }

    Ok(())
}
