//! Error types for all kinds of authentication

use std::{collections::HashMap, fmt};

use actix_web::{http::header, HttpResponse, ResponseError};

#[derive(Debug)]
pub(crate) struct UnauthorizedRedirect {
    location: String,
    query_string: Option<String>,
}

// helper for redirects to handle the query string
pub(crate) struct HttpQuery {
    map: HashMap<String, Option<String>>,
}

#[allow(unused)]
impl HttpQuery {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: &str, val: &str) {
        self.map.insert(key.to_owned(), Some(val.to_owned()));
    }

    pub fn insert_without_value(&mut self, key: &str) {
        self.map.insert(key.to_owned(), None);
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.map.remove(key).flatten()
    }
}

impl ToString for HttpQuery {
    fn to_string(&self) -> String {
        let query_string = if !self.map.is_empty() {
            let mut query_str = String::new();
            let number_of_queries = self.map.len();
            for (index, (key, val)) in self.map.iter().enumerate() {
                query_str.push_str(&key);

                if let Some(val) = val {
                    query_str.push_str("=");
                    query_str.push_str(&val);
                }

                if number_of_queries > 1 && index < number_of_queries - 1 {
                    query_str.push_str("&");
                }
            }

            query_str
        } else {
            "".to_owned()
        };

        query_string
    }
}

impl From<&str> for HttpQuery {
    fn from(value: &str) -> Self {
        let map: HashMap<String, Option<String>> = value
            .split('&')
            .into_iter()
            .map(|kv: &str| {
                let kv: Vec<&str> = kv.split('=').collect();
                if kv.len() > 1 {
                    (kv[0].to_owned(), Some(kv[1].to_owned()))
                } else {
                    (kv[0].to_owned(), None)
                }
            })
            .collect();

        Self { map }
    }
}

#[allow(unused)]
impl UnauthorizedRedirect {
    pub fn new(location: &str) -> Self {
        Self {
            location: location.to_owned(),
            query_string: None,
        }
    }

    /// Constructor to build a redirect query string
    /// For example it creates: /login?redirect_uri=%2Fcalled-first
    ///
    /// `location`: the location the redirect should point to
    /// `redirect_path`: the value for the query redirect_uri
    /// `query_string`: the query string for redirect_path
    pub fn new_with_redirect_uri(location: &str, redirect_path: &str, query_string: &str) -> Self {
        let mut redirect_uri = String::new();
        redirect_uri.push_str("redirect_uri=");
        redirect_uri.push_str(&urlencoding::encode(redirect_path));
        if !query_string.trim().is_empty() {
            redirect_uri.push_str("%3F");
            redirect_uri.push_str(&urlencoding::encode(query_string));
        }

        Self {
            location: location.to_owned(),
            query_string: Some(redirect_uri),
        }
    }

    /// Constructor to build a UnauthorizedRedirect with an arbitrary query string
    pub fn new_with_query_string(location: &str, query: HttpQuery) -> Self {
        let query_string = query.to_string();
        let query_optional = if query_string.is_empty() {
            None
        } else {
            Some(query_string)
        };

        Self {
            location: location.to_owned(),
            query_string: query_optional,
        }
    }
}

#[derive(Debug)]
pub struct UnauthorizedError {
    message: String,
    redirect: Option<UnauthorizedRedirect>,
}

impl UnauthorizedError {
    #[allow(unused)]
    pub(crate) fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
            redirect: None,
        }
    }

    pub(crate) fn new_redirect(redirect: UnauthorizedRedirect) -> Self {
        Self {
            message: "Not authorized".to_owned(),
            redirect: Some(redirect),
        }
    }
}

impl Default for UnauthorizedError {
    fn default() -> Self {
        Self {
            message: "Not authorized".to_owned(),
            redirect: None,
        }
    }
}

impl fmt::Display for UnauthorizedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Debug unauth error")
    }
}

impl ResponseError for UnauthorizedError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        if let Some(_) = &self.redirect {
            actix_web::http::StatusCode::FOUND
        } else {
            actix_web::http::StatusCode::UNAUTHORIZED
        }
    }

    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        if let Some(redirect) = &self.redirect {
            let location = &redirect.location;
            let location_header = match &redirect.query_string {
                Some(redirect_query) => &format!("{}?{}", location, redirect_query),
                None => location,
            };
            HttpResponse::Found()
                .insert_header((header::LOCATION, location_header.to_owned()))
                .finish()
        } else {
            HttpResponse::Unauthorized().json(self.message.clone())
        }
    }
}

#[cfg(test)]
mod tests {

    use actix_web::{http::header::LOCATION, ResponseError};

    use crate::errors::{HttpQuery, UnauthorizedError, UnauthorizedRedirect};

    #[test]
    fn redirect_with_query_test() {
        let mut query = HttpQuery::new();
        query.insert_without_value("error");
        query.insert("key2", "value");

        let unauth_redirect = UnauthorizedRedirect::new_with_query_string("/login", query);
        let res = UnauthorizedError::new_redirect(unauth_redirect).error_response();

        let location_header_val = res.headers().get(LOCATION).unwrap().to_str().unwrap();

        assert!(location_header_val.contains("/login?"));
        assert!(location_header_val.contains("error"));
        assert!(!location_header_val.contains("error=")); // does not contain "error="
        assert!(location_header_val.contains("key2=value"));
        assert!(location_header_val.contains("key2=value"));
        assert_eq!(location_header_val.chars().filter(|s| *s == '&').count(), 1);
    }

    #[test]
    fn should_have_redirect_uri_without_query() {
        let unauth_redirect =
            UnauthorizedRedirect::new_with_redirect_uri("/login", "/called-first", "");
        let res = UnauthorizedError::new_redirect(unauth_redirect).error_response();

        let location_header_val = res.headers().get(LOCATION).unwrap().to_str().unwrap();

        assert_eq!(location_header_val, "/login?redirect_uri=%2Fcalled-first");
    }

    #[test]
    fn should_have_redirect_uri_with_query() {
        let unauth_redirect = UnauthorizedRedirect::new_with_redirect_uri(
            "/login",
            "/called-first",
            "key1=val1&key2=val2",
        );
        let res = UnauthorizedError::new_redirect(unauth_redirect).error_response();

        let location_header_val = res.headers().get(LOCATION).unwrap().to_str().unwrap();

        assert_eq!(
            location_header_val,
            "/login?redirect_uri=%2Fcalled-first%3Fkey1%3Dval1%26key2%3Dval2"
        );
    }

    #[test]
    fn http_query_should_be_constructable_from_empty_str() {
        let query: HttpQuery = "".into();
        assert_eq!(query.to_string(), "");
    }

    #[test]
    fn http_query_should_be_constructable_from_str() {
        let mut query: HttpQuery = "error&key=value".into();
        query.insert("schnick", "schnack");
        let query_string = query.to_string();
        assert!(query_string.contains("error"));
        assert!(!query_string.contains("error="));
        assert!(query_string.contains("key=value"));
        assert!(query_string.contains("schnick=schnack"));
    }
}
