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
    login::LoadUserService,
    middleware::{AuthMiddleware, PathMatcher},
    multifactor::Factor,
};

use super::{handlers::SessionLoginHandler, session_auth::SessionAuthProvider};

pub struct SessionLoginAppBuilder<U, S, ST>
where
    U: Serialize + DeserializeOwned + Clone + 'static,
    S: LoadUserService<User = U> + 'static,
    ST: SessionStore,
{
    session_middleware: SessionMiddleware<ST>,
    path_matcher: PathMatcher,
    load_user_service: S,
    factor: Option<Box<dyn Factor>>,
    mfa_condition: Option<fn(&U, &HttpRequest) -> bool>,
    routes: Routes,
}

impl<U, S, ST> SessionLoginAppBuilder<U, S, ST>
where
    U: Serialize + DeserializeOwned + Clone + 'static,
    S: LoadUserService<User = U> + 'static,
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
    S: LoadUserService<User = U> + 'static,
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
        let mut login_handler_and_provider = match self.factor {
            Some(factor) => {
                let provider = SessionAuthProvider::new(factor);
                let handler = match self.mfa_condition {
                    Some(condition) => {
                        SessionLoginHandler::with_mfa_condition(self.load_user_service, condition)
                    }
                    None => SessionLoginHandler::with_mfa(self.load_user_service),
                };

                (handler, provider)
            }
            None => (
                SessionLoginHandler::new(self.load_user_service),
                SessionAuthProvider::default(),
            ),
        };

        login_handler_and_provider.0.set_routes(self.routes);

        let middleware =
            AuthMiddleware::<_, U>::new(login_handler_and_provider.1, self.path_matcher);
        App::new()
            .configure(login_handler_and_provider.0.get_config())
            .wrap(middleware)
            .wrap(self.session_middleware)
    }
}

impl<U, S> SessionLoginAppBuilder<U, S, CookieSessionStore>
where
    U: Serialize + DeserializeOwned + Clone + 'static,
    S: LoadUserService<User = U> + 'static,
{
    pub fn default(load_user_service: S) -> Self {
        Self {
            path_matcher: Routes::default().into(),
            session_middleware: SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ),
            load_user_service,
            mfa_condition: None,
            factor: None,
            routes: Routes::default(),
        }
    }
}
