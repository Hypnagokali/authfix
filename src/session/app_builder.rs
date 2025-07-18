use std::{rc::Rc, sync::Arc};

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

use crate::{
    login::{FailureHandler, LoadUserByCredentials, SuccessHandler}, middleware::{AuthMiddleware, PathMatcher}, multifactor::config::MfaConfig, session::SessionUser
};

use super::{config::Routes, handlers::SessionApiHandlers, session_auth::SessionAuthProvider};

/// A builder that build an [actix_web::App] configured with session authentication
pub struct SessionLoginAppBuilder<U, S, ST>
where
    U: SessionUser + 'static,
    S: LoadUserByCredentials<User = U> + 'static,
    ST: SessionStore,
{
    session_middleware: SessionMiddleware<ST>,
    path_matcher: PathMatcher,
    load_user_service: Arc<S>,
    error_handler: Rc<Option<Box<dyn FailureHandler>>>,
    success_handler: Rc<Option<Box<dyn SuccessHandler<User = U>>>>,
    mfa_config: MfaConfig<U>,
    routes: Routes,
    redirect_flow: bool,
}

impl<U, S, ST> SessionLoginAppBuilder<U, S, ST>
where
    U: SessionUser + 'static,
    S: LoadUserByCredentials<User = U> + 'static,
    ST: SessionStore,
{
    pub fn set_mfa(self, mfa_config: MfaConfig<U>) -> SessionLoginAppBuilder<U, S, ST> {
        Self {
            path_matcher: self.path_matcher,
            mfa_config,
            routes: self.routes,
            load_user_service: self.load_user_service,
            error_handler: self.error_handler,
            success_handler: self.success_handler,
            session_middleware: self.session_middleware,
            redirect_flow: self.redirect_flow,
        }
    }

    pub fn set_login_failure_handler<H>(
        self,
        login_failure_handler: H,
    ) -> SessionLoginAppBuilder<U, S, ST>
    where
        H: FailureHandler + 'static,
    {
        Self {
            path_matcher: self.path_matcher,
            mfa_config: self.mfa_config,
            routes: self.routes,
            load_user_service: self.load_user_service,
            error_handler: Rc::new(Some(Box::new(login_failure_handler))),
            success_handler: self.success_handler,
            session_middleware: self.session_middleware,
            redirect_flow: self.redirect_flow,
        }
    }

    pub fn set_login_success_handler<H>(
        self,
        login_success_handler: H,
    ) -> SessionLoginAppBuilder<U, S, ST>
    where
        H: SuccessHandler<User = U> + 'static,
    {
        Self {
            path_matcher: self.path_matcher,
            mfa_config: self.mfa_config,
            routes: self.routes,
            load_user_service: self.load_user_service,
            error_handler: self.error_handler,
            success_handler: Rc::new(Some(Box::new(login_success_handler))),
            session_middleware: self.session_middleware,
            redirect_flow: self.redirect_flow,
        }
    }

    pub fn with_redirect_flow(self) -> SessionLoginAppBuilder<U, S, ST> {
        Self {
            path_matcher: self.path_matcher,
            mfa_config: self.mfa_config,
            routes: self.routes,
            load_user_service: self.load_user_service,
            error_handler: self.error_handler,
            success_handler: self.success_handler,
            session_middleware: self.session_middleware,
            redirect_flow: true,
        }
    }

    /// Sets the login routes and adds additional paths that are secured
    ///
    /// If this method is used, **all paths are public** by default and only the given additional paths will be secured.
    /// In most cases [SessionLoginAppBuilder::set_login_routes_and_public_paths] is the way to go, because it will secure all paths by default.
    /// This call overrides [SessionLoginAppBuilder::set_login_routes_and_public_paths]
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
            error_handler: self.error_handler,
            success_handler: self.success_handler,
            redirect_flow: self.redirect_flow,
        }
    }

    /// Sets the login routes and adds additional paths that are public
    ///
    /// Only the additional paths are public if this method is used
    /// This call overrides [SessionLoginAppBuilder::set_login_routes_and_secured_paths]
    pub fn set_login_routes_and_public_paths(
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
            error_handler: self.error_handler,
            success_handler: self.success_handler,
            redirect_flow: self.redirect_flow,
        }
    }
}

impl<U, S, ST> SessionLoginAppBuilder<U, S, ST>
where
    U: SessionUser + 'static,
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
        let shared_routes = Arc::new(self.routes);
        let handler: SessionApiHandlers<S, U> =
            SessionApiHandlers::new(Arc::clone(&shared_routes), self.redirect_flow);

        let mut provider = if self.mfa_config.is_configured() {
            SessionAuthProvider::new_with_mfa(
                self.load_user_service,
                self.mfa_config,
                shared_routes,
            )
        } else {
            SessionAuthProvider::new(Arc::clone(&self.load_user_service), shared_routes)
        };

        provider.set_redirect_flow(self.redirect_flow);
        provider.set_error_handler_from_rc(self.error_handler);
        provider.set_success_handler_from_rc(self.success_handler);

        let middleware = AuthMiddleware::<_, U>::new(provider, self.path_matcher);

        App::new()
            .configure(handler.get_config())
            .wrap(middleware)
            .wrap(self.session_middleware)
    }
}

impl<U, S> SessionLoginAppBuilder<U, S, CookieSessionStore>
where
    U: SessionUser + 'static,
    S: LoadUserByCredentials<User = U> + 'static,
{
    /// Creates an app builder with defaults
    ///
    /// If you need to use the instance of the type that implements LoadUserByCredentials later, you can use [SessionLoginAppBuilder::create_from_shared] instead.
    pub fn create(load_user_service: S, key: Key) -> Self {
        Self::create_from_shared(Arc::new(load_user_service), key)
    }

    /// Creates an app builder with defaults
    pub fn create_from_shared(load_user_service: Arc<S>, key: Key) -> Self {
        Self::create_from_shared_with_session_middleware(
            load_user_service,
            SessionMiddleware::new(CookieSessionStore::default(), key),
        )
    }
}

impl<U, S, ST> SessionLoginAppBuilder<U, S, ST>
where
    U: SessionUser + 'static,
    S: LoadUserByCredentials<User = U> + 'static,
    ST: SessionStore,
{
    // Creates an app builder with a specific session configuration
    pub fn create_with_session_middleware(
        load_user_service: S,
        session_middleware: SessionMiddleware<ST>,
    ) -> Self {
        Self::create_from_shared_with_session_middleware(
            Arc::new(load_user_service),
            session_middleware,
        )
    }

    pub fn create_from_shared_with_session_middleware(
        load_user_service: Arc<S>,
        session_middleware: SessionMiddleware<ST>,
    ) -> Self {
        Self {
            path_matcher: Routes::default().into(),
            session_middleware,
            load_user_service,
            error_handler: Rc::new(None),
            success_handler: Rc::new(None),
            mfa_config: MfaConfig::empty(),
            routes: Routes::default(),
            redirect_flow: false,
        }
    }
}
