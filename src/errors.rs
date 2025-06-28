//! Error types for all kinds of authentication

use std::fmt;

use actix_web::{http::header, HttpRequest, HttpResponse, ResponseError};

#[derive(Debug)]
pub struct UnauthorizedRedirect {
    location: String,
    query_string: Option<String>,
}

impl UnauthorizedRedirect {
    pub fn new(location: &str) -> Self {
        Self { 
            location: location.to_owned(),
            query_string: None,
        }
    }

    /// Constructor to build a redirect query string
    pub fn new_with_redirect_query(location: &str, req: &HttpRequest) -> Self {
        let redirect_path = if !req.query_string().trim().is_empty() {
            format!("redirect_uri={}%3F{}", urlencoding::encode(req.path()), urlencoding::encode(req.query_string()))
        } else {
            req.path().to_owned()
        };

        Self {
            location: location.to_owned(),
            query_string: Some(redirect_path),
        }
    }
}

#[derive(Debug)]
pub struct UnauthorizedError {
    message: String,
    redirect: Option<UnauthorizedRedirect>,
}

impl UnauthorizedError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
            redirect: None,
        }
    }

    pub fn new_redirect(redirect: UnauthorizedRedirect) -> Self {
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
