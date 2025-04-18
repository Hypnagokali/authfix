use std::{
    future::{ready, Ready},
    marker::PhantomData,
    rc::Rc,
};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures::future::LocalBoxFuture;
use log::{debug, trace};
use regex::Regex;
use serde::de::DeserializeOwned;
use urlencoding::encode;

use crate::{
    config::Routes, AuthToken, AuthenticationProvider
};

const PATH_MATCHER_ANY_ENCODED: &str = "%2A"; // to match *

/// It is used to specify secured paths
///
/// [`PathMatcher`] stores the paths that should be excluded or included for authentication.
/// In the most cases it is desired to exclude paths from authentication, so that every path is secured but e.g. /login, /register are reachable for
/// the user. For this default configuration where all paths are secured except `/login` and `/register` use [`PathMatcher::default`]
///
/// But if you have more public pages and you would like to secure just a few paths, you can set the `is_exclusion_list` flag to `false` to specify only the secured paths.
/// ```ignore
/// PathMatcher::new(vec!["/my-secure-route", "another-secure-route"], false)
/// ```
///
/// You can use wildcards for path matching like
/// ```ignore
/// PathMatcher::new(vec!["/private/*"], false)
/// ```
#[derive(Clone)]
pub struct PathMatcher {
    is_exclusion_list: bool,
    path_regex_list: Vec<(String, Regex)>,
}

fn add_path_to_list(path_list: &Vec<&str>, list: &mut Vec<(String, Regex)>) {
    for &pattern in path_list.iter() {
        let regex_pattern = format!("^{}$", transform_to_encoded_regex(pattern));
        list.push((pattern.to_owned(), Regex::new(&regex_pattern).unwrap()));
    }
}

impl PathMatcher {
    pub fn new(path_list: Vec<&str>, is_exclusion_list: bool) -> Self {
        let mut path_regex_list = Vec::new();

        add_path_to_list(&path_list, &mut path_regex_list);
        
        Self {
            is_exclusion_list,
            path_regex_list,
        }
    }

    pub fn add(&mut self, path_list: Vec<&str>) {
        add_path_to_list(&path_list, &mut self.path_regex_list);
    }

    pub(crate) fn matches(&self, path: &str) -> bool {
        let encoded_path = transform_to_encoded_regex(path);
        let mut path_regex_iter = self.path_regex_list.iter();

        if self.is_exclusion_list {
            path_regex_iter.all(|p| !p.1.is_match(&encoded_path))
        } else {
            path_regex_iter.any(|p| p.1.is_match(&encoded_path))
        }
    }
}

impl From<Routes> for PathMatcher {
    fn from(value: Routes) -> Self {
        PathMatcher::new(vec![value.get_login()], true)
    }
}

impl Default for PathMatcher {
    /// All routes are secured by default except "/login" and "/register"
    fn default() -> Self {
        Self::new(vec!["/login", "/register"], true)
    }
}

fn transform_to_encoded_regex(input: &str) -> String {
    let encoded = encode(input);

    encoded.replace(PATH_MATCHER_ANY_ENCODED, ".*")
}

/// A middleware that can simplify handling of authentication in [Actix Web](https://actix.rs/)
///
/// [`AuthMiddleware`] checks if a user is logged in and if not, it responses with 401. If a user is present it gets injected into the `Actix Web`-pipeline and
/// you can then retrieve it in request handlers by using the [AuthToken] extractor.
/// Furthermore [`AuthMiddleware`] checks, if the `AuthToken` is still valid, if not it invalidates the underlying authentication.
///
/// To decide, if a user is logged in or not, [`AuthMiddleware`] uses the [AuthenticationProvider] trait to get the user from the underlying mechanism/store.
///
/// Currently only [SessionAuthProvider](crate::session::session_auth::SessionAuthProvider) implements [AuthenticationProvider]. Internally it uses
/// [Actix Session](https://crates.io/crates/actix-session). For session authentication it is important to wrap the `SessionMiddleware`
/// after the `AuthMiddleware`, so that the session is created/handled before the `AuthMiddleware`.
///  
/// # Examples
/// coming soon after applying lib in a reference project
///
///
#[derive(Clone)]
pub struct AuthMiddleware<AuthProvider, U>
where
    AuthProvider: AuthenticationProvider<U>,
    U: DeserializeOwned + Clone + 'static,
{
    auth_provider: Rc<AuthProvider>,
    path_matcher: Rc<PathMatcher>,
    user_type: PhantomData<U>,
}

impl<AuthProvider, U> AuthMiddleware<AuthProvider, U>
where
    AuthProvider: AuthenticationProvider<U>,
    U: DeserializeOwned + Clone + 'static,
{
    pub fn new(auth_provider: AuthProvider, path_matcher: PathMatcher) -> Self {
        AuthMiddleware {
            auth_provider: Rc::new(auth_provider),
            path_matcher: Rc::new(path_matcher),
            user_type: PhantomData,
        }
    }
}

pub struct AuthMiddlewareInner<S, AuthProvider, U>
where
    AuthProvider: AuthenticationProvider<U>,
    U: DeserializeOwned + Clone + 'static,
{
    service: Rc<S>,
    auth_provider: Rc<AuthProvider>,
    path_matcher: Rc<PathMatcher>,
    user_type: PhantomData<U>,
}

impl<S, B, AuthProvider, U> Service<ServiceRequest> for AuthMiddlewareInner<S, AuthProvider, U>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    U: DeserializeOwned + Clone + 'static,
    AuthProvider: AuthenticationProvider<U> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let request_path = req.request().path().to_owned();

        let debug_path = req.path().to_owned();
        let service = Rc::clone(&self.service);
        let auth_provider = Rc::clone(&self.auth_provider);

        {
            let mut extensions = req.extensions_mut();
            auth_provider.configure_provider(&mut extensions);
        }
        
        if self.path_matcher.matches(&request_path) {
            debug!("Secured route: '{}'", debug_path);

            Box::pin(async move {
                // Before Request
                let processed_request = auth_provider.is_user_authorized_for_request(req).await?;

                let res = service.call(processed_request).await?;

                // Process logout logic after request
                let token_valid = {
                    let extensions = res.request().extensions();
                    if let Some(token) = extensions.get::<AuthToken<U>>() {
                        token.is_valid()
                    } else {
                        // If there is no AuthToken, authentication is no longer valid
                        false
                    }
                };

                if !token_valid {
                    debug!("AuthToken no longer valid (maybe logged out). Invalidate Authentication. (Triggered by: {})", debug_path);
                    let req = res.request().clone();
                    auth_provider.invalidate(req).await;
                }

                Ok(res)
            })
        } else {
            trace!("Route is not secured: {}", debug_path);
            Box::pin(async move { service.call(req).await })
        }
    }
}

impl<S, B, AuthProvider, U> Transform<S, ServiceRequest> for AuthMiddleware<AuthProvider, U>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    AuthProvider: AuthenticationProvider<U> + Clone + 'static,
    U: DeserializeOwned + Clone + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareInner<S, AuthProvider, U>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareInner {
            service: Rc::new(service),
            path_matcher: Rc::clone(&self.path_matcher),
            auth_provider: Rc::clone(&self.auth_provider),
            user_type: PhantomData,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Routes;

    use super::PathMatcher;

    #[test]
    fn should_be_able_to_add_routes_to_path_matcher()  {
        let routes = Routes::new("", "/custom-login", "/custom-mfa", "/logout");

        let mut path_matcher: PathMatcher = routes.into();
        path_matcher.add(vec!["/public"]);

        assert!(!path_matcher.matches("/custom-login"));
        assert!(!path_matcher.matches("/public"));
    }

    #[test]
    fn path_matcher_can_be_created_from_routes()  {
        let routes = Routes::new("", "/custom-login", "/custom-mfa", "/logout");

        let path_matcher: PathMatcher = routes.into();

        assert!(!path_matcher.matches("/custom-login"));
        assert!(path_matcher.matches("/custom-mfa"));
        assert!(path_matcher.matches("/logout"));
    }

    #[test]
    fn path_matcher_should_match_wildcard() {
        let matcher = PathMatcher::new(vec!["/api/users/*", "/some-other/route"], false);

        assert!(matcher.matches("/api/users/231/edit"));
    }

    #[test]
    fn path_matcher_should_match_any_path_that_is_not_in_list_when_excluded() {
        let matcher = PathMatcher::new(vec!["/some-other/route"], true);

        assert!(matcher.matches("/api/users/231/edit"));
    }

    #[test]
    fn path_matcher_default_should_secure_any_but_login() {
        let matcher = PathMatcher::default();

        assert!(matcher.matches("/api/users/231/edit"));
        assert!(!matcher.matches("/login"));
        // As long as there is no wildcard, only the exact string should be matched
        assert!(matcher.matches("/login/something"))
    }
}
