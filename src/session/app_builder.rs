use std::sync::Arc;

use actix_session::{
    storage::{CookieSessionStore, SessionStore},
    SessionMiddleware,
};
use actix_web::{
    body::MessageBody,
    cookie::Key,
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    App, Error, HttpRequest,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    config::Routes,
    login::LoadUserByCredentials,
    middleware::{AuthMiddleware, PathMatcher},
    multifactor::Factor,
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
    factor: Option<Box<dyn Factor>>,
    mfa_condition: Option<fn(&U, &HttpRequest) -> bool>,
    routes: Routes,
}

impl<U, S, ST> SessionLoginAppBuilder<U, S, ST>
where
    U: Serialize + DeserializeOwned + Clone + 'static,
    S: LoadUserByCredentials<User = U> + 'static,
    ST: SessionStore,
{
    pub fn set_mfa_with_condition(
        self,
        factor: Box<dyn Factor>,
        condition: fn(&U, &HttpRequest) -> bool,
    ) -> SessionLoginAppBuilder<U, S, ST> {
        Self {
            path_matcher: self.path_matcher,
            factor: Some(factor),
            mfa_condition: Some(condition),
            routes: self.routes,
            load_user_service: self.load_user_service,
            session_middleware: self.session_middleware,
        }
    }

    pub fn set_mfa(self, factor: Box<dyn Factor>) -> SessionLoginAppBuilder<U, S, ST> {
        Self {
            path_matcher: self.path_matcher,
            factor: Some(factor),
            mfa_condition: None,
            routes: self.routes,
            load_user_service: self.load_user_service,
            session_middleware: self.session_middleware,
        }
    }

    pub fn set_routes_and_secured_paths(
        self,
        login_routes: Routes,
        secured_paths: Vec<&str>,
    ) -> SessionLoginAppBuilder<U, S, ST> {
        let mut path_matcher: PathMatcher = PathMatcher::new(
            vec![login_routes.get_logout(), login_routes.get_mfa()],
            false,
        );
        path_matcher.add(secured_paths);

        Self {
            path_matcher,
            session_middleware: self.session_middleware,
            mfa_condition: None,
            factor: None,
            routes: login_routes,
            load_user_service: self.load_user_service,
        }
    }

    pub fn set_routes_and_unsecured_paths(
        self,
        login_routes: Routes,
        unsecured_paths: Vec<&str>,
    ) -> SessionLoginAppBuilder<U, S, ST> {
        let mut path_matcher: PathMatcher = login_routes.clone().into();
        path_matcher.add(unsecured_paths);

        Self {
            path_matcher,
            session_middleware: self.session_middleware,
            mfa_condition: None,
            factor: None,
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
            mfa_condition: None,
            factor: None,
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
        let mut handler =
            SessionApiHandlers::new_from_shared(self.load_user_service).with_routes(self.routes);

        let provider = match self.factor {
            Some(factor) => {
                let provider = SessionAuthProvider::new(factor);
                match self.mfa_condition {
                    Some(condition) => {
                        handler = handler.with_mfa(true).with_mfa_condition(condition);
                    }
                    None => {
                        handler = handler.with_mfa(true);
                    }
                };

                provider
            }
            None => SessionAuthProvider::default(),
        };

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
    pub fn create_from_owned(load_user_service: S) -> Self {
        Self::create_from_shared(Arc::new(load_user_service))
    }

    pub fn create_from_shared(load_user_service: Arc<S>) -> Self {
        Self {
            path_matcher: Routes::default().into(),
            session_middleware: SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ),
            load_user_service: Arc::clone(&load_user_service),
            mfa_condition: None,
            factor: None,
            routes: Routes::default(),
        }
    }
}
