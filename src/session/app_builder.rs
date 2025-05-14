use std::sync::Arc;

use actix_session::{
    storage::{CookieSessionStore, SessionStore},
    SessionMiddleware,
};
use actix_web::{
    body::MessageBody,
    cookie::Key,
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    App, Error,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    config::Routes,
    login::LoadUserByCredentials,
    mfa::MfaConfig,
    middleware::{AuthMiddleware, PathMatcher},
};

use super::{handlers::SessionApiHandlers, session_auth::SessionAuthProvider};

pub struct SessionLoginAppBuilder<U, S, ST>
where
    U: Serialize + DeserializeOwned + Clone + 'static,
    S: LoadUserByCredentials<User = U> + 'static,
    ST: SessionStore,
{
    session_middleware: SessionMiddleware<ST>,
    path_matcher: PathMatcher,
    load_user_service: Arc<S>,
    mfa_config: MfaConfig<U>,
    routes: Routes,
}

impl<U, S, ST> SessionLoginAppBuilder<U, S, ST>
where
    U: Serialize + DeserializeOwned + Clone + 'static,
    S: LoadUserByCredentials<User = U> + 'static,
    ST: SessionStore,
{
    pub fn set_mfa(self, mfa_config: MfaConfig<U>) -> SessionLoginAppBuilder<U, S, ST> {
        Self {
            path_matcher: self.path_matcher,
            mfa_config,
            routes: self.routes,
            load_user_service: self.load_user_service,
            session_middleware: self.session_middleware,
        }
    }

    pub fn set_login_routes_and_secured_paths(
        self,
        login_routes: Routes,
        secured_paths: Vec<&str>,
    ) -> SessionLoginAppBuilder<U, S, ST> {
        let mut path_matcher: PathMatcher = PathMatcher::new(
            vec![
                login_routes.get_logout(),
                login_routes.get_mfa(),
                login_routes.get_logout(),
            ],
            false,
        );
        path_matcher.add(secured_paths);

        Self {
            path_matcher,
            session_middleware: self.session_middleware,
            mfa_config: self.mfa_config,
            routes: login_routes,
            load_user_service: self.load_user_service,
        }
    }

    pub fn set_login_routes_and_unsecured_paths(
        self,
        login_routes: Routes,
        unsecured_paths: Vec<&str>,
    ) -> SessionLoginAppBuilder<U, S, ST> {
        let mut path_matcher: PathMatcher = login_routes.clone().into();
        path_matcher.add(unsecured_paths);

        Self {
            path_matcher,
            session_middleware: self.session_middleware,
            mfa_config: self.mfa_config,
            routes: login_routes,
            load_user_service: self.load_user_service,
        }
    }

    pub fn set_session_middleware(
        self,
        session_middleware: SessionMiddleware<ST>,
    ) -> SessionLoginAppBuilder<U, S, ST> {
        Self {
            path_matcher: self.path_matcher,
            session_middleware,
            mfa_config: self.mfa_config,
            routes: self.routes,
            load_user_service: self.load_user_service,
        }
    }
}

impl<U, S, ST> SessionLoginAppBuilder<U, S, ST>
where
    U: Serialize + DeserializeOwned + Clone + 'static,
    S: LoadUserByCredentials<User = U> + 'static,
    ST: SessionStore + 'static,
{
    pub fn build(
        self,
    ) -> App<
        impl ServiceFactory<
            ServiceRequest,
            Response = ServiceResponse<impl MessageBody>,
            Config = (),
            InitError = (),
            Error = Error,
        >,
    > {
        let handler = SessionApiHandlers::new_from_shared(Arc::clone(&self.load_user_service))
            .with_routes(self.routes);

        let mut provider = SessionAuthProvider::new(Arc::clone(&self.load_user_service));

        if self.mfa_config.is_configured() {
            provider = SessionAuthProvider::new_with_mfa(self.load_user_service, self.mfa_config);
        }

        let middleware = AuthMiddleware::<_, U>::new(provider, self.path_matcher);

        App::new()
            .configure(handler.get_config())
            .wrap(middleware)
            .wrap(self.session_middleware)
    }
}

impl<U, S> SessionLoginAppBuilder<U, S, CookieSessionStore>
where
    U: Serialize + DeserializeOwned + Clone + 'static,
    S: LoadUserByCredentials<User = U> + 'static,
{
    pub fn create(load_user_service: S) -> Self {
        Self::create_from_shared(Arc::new(load_user_service))
    }

    pub fn create_from_shared(load_user_service: Arc<S>) -> Self {
        Self {
            path_matcher: Routes::default().into(),
            session_middleware: SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ),
            load_user_service,
            mfa_config: MfaConfig::empty(),
            routes: Routes::default(),
        }
    }
}
