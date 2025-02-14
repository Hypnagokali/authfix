use std::sync::Arc;

use actix_web::{
    dev::{AppService, HttpServiceFactory}, guard::Post, web::{Data, Json, ServiceConfig}, Error, HttpRequest, HttpResponse, Resource, Responder
};
use serde::Serialize;

use crate::{
    login::{LoadUserService, LoginToken},
    multifactor::MfaRegistry,
};

use super::session_auth::UserSession;

#[allow(clippy::type_complexity)]
pub struct SessionLoginHandler<T: LoadUserService, U> {
    user_service: Arc<T>,
    mfa_condition: Arc<Option<fn(&U, &HttpRequest) -> bool>>,
}

impl<T, U> SessionLoginHandler<T, U>
where
    T: LoadUserService,
{
    pub fn new(user_service: T) -> Self {
        Self {
            user_service: Arc::new(user_service),
            mfa_condition: Arc::new(None),
        }
    }

    pub fn with_mfa_condition(
        user_service: T,
        mfa_condition: fn(&U, &HttpRequest) -> bool,
    ) -> Self {
        Self {
            user_service: Arc::new(user_service),
            mfa_condition: Arc::new(Some(mfa_condition)),
        }
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
    U: Serialize + 'static,
{
    fn register(self, __config: &mut AppService) {
        let __resource = Resource::new("/login")
            .name("login")
            .guard(Post())
            .app_data(Data::new(Arc::clone(&self.user_service)))
            .app_data(Data::new(Arc::clone(&self.mfa_condition)))
            .to(login::<T, U>);
        HttpServiceFactory::register(__resource, __config);
    }
}

pub fn login_config<L: LoadUserService<User = U> + 'static, U: Serialize + 'static>(login_handler: SessionLoginHandler<L, U>) -> impl FnOnce(&mut ServiceConfig) { 
    |config: &mut ServiceConfig| { 
        config.service(login_handler);
    }
}