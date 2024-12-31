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
use regex::Regex;
use serde::de::DeserializeOwned;
use urlencoding::encode;

use crate::{AuthToken, GetAuthenticatedUserFromRequest, UnauthorizedError};

const PATH_MATCHER_ANY_ENCODED: &str = "%2A"; // to match *

/// PathMatcher is used to match specific paths or to exclude paths from matching
/// is_exclusion_list: if true, the entries of path_list will not match otherwise only the entries will match.
/// path_list: List of paths you wish to exclude or include (see: is_exclusion_list). The path_list may include wildcards like "/api/user/*"
pub struct PathMatcher {
    is_exclusion_list: bool,
    path_regex_list: Vec<(&'static str, Regex)>,
}

impl PathMatcher {
    /// All routes are secured except everything starting with /login or register (e.g.: /login?error=true, /login-anything, /register, /register-error)
    /// **Warning:** currently it would left a routes like /register-private-thing/user/123 unsecure
    pub fn default() -> Self {
        Self::new(vec!["/login*", "/register*"], true)
    }

    pub fn new(path_list: Vec<&'static str>, is_exclusion_list: bool) -> Self {
        let mut path_regex_list = Vec::new();
        for pattern in path_list.into_iter() {
            path_regex_list.push((
                pattern,
                Regex::new(&transform_to_encoded_regex(pattern)).unwrap(),
            ));
        }
        Self {
            is_exclusion_list,
            path_regex_list,
        }
    }

    pub fn matches(&self, path: &str) -> bool {
        let encoded_path = transform_to_encoded_regex(path);
        let mut path_regex_iter = self.path_regex_list.iter();
        if self.is_exclusion_list {
            return path_regex_iter.all(|p| !p.1.is_match(&encoded_path));
        } else {
            return path_regex_iter.any(|p| {
                println!("check: {} against: {}", path, p.1.as_str());

                p.1.is_match(&encoded_path)
            })
        }
    }
}

fn transform_to_encoded_regex(input: &str) -> String {
    let encoded = encode(input);
    let valid_regex = encoded.replace(PATH_MATCHER_ANY_ENCODED, ".*");
    valid_regex
}

pub struct AuthMiddleware<AuthProvider, U>
where
    AuthProvider: GetAuthenticatedUserFromRequest<U>,
    U: DeserializeOwned,
{
    auth_provider: Rc<AuthProvider>,
    path_matcher: Rc<PathMatcher>,
    user_type: PhantomData<U>,
}

impl<AuthProvider, U> AuthMiddleware<AuthProvider, U>
where
    AuthProvider: GetAuthenticatedUserFromRequest<U>,
    U: DeserializeOwned,
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
    AuthProvider: GetAuthenticatedUserFromRequest<U>,
    U: DeserializeOwned,
{
    service: S,
    auth_provider: Rc<AuthProvider>,
    path_matcher: Rc<PathMatcher>,
    user_type: PhantomData<U>,
}

impl<S, B, AuthProvider, U> Service<ServiceRequest> for AuthMiddlewareInner<S, AuthProvider, U>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    U: DeserializeOwned + 'static,
    AuthProvider: GetAuthenticatedUserFromRequest<U>,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        println!("Check authentication {}", req.path());

        let request_path = req.request().path();
        if self.path_matcher.matches(request_path) {
            match self.auth_provider.get_authenticated_user(&req.request()) {
                Ok(user) => {
                    let token = AuthToken::new(user);
                    let mut extensions = req.extensions_mut();
                    extensions.insert(token);
                }
                Err(_) => {
                    // TODO: should use appropriate logging
                    println!("Authenticated route but no authenticated user found..");
                    return Box::pin(async { Err(UnauthorizedError::default().into()) });
                }
            }
        } else {
            println!("Path is not secured");
        }

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

impl<S, B, AuthProvider, U> Transform<S, ServiceRequest> for AuthMiddleware<AuthProvider, U>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    AuthProvider: GetAuthenticatedUserFromRequest<U> + Clone,
    U: DeserializeOwned + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareInner<S, AuthProvider, U>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareInner {
            service,
            path_matcher: Rc::clone(&self.path_matcher),
            auth_provider: Rc::clone(&self.auth_provider),
            user_type: PhantomData,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::PathMatcher;

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
    }
}
