use std::{future::ready, net::SocketAddr, sync::Arc, thread};

use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, get, App, HttpRequest, HttpResponse, HttpServer, Responder};
use auth_middleware_for_actix_web::{
    login::{HandlerError, LoadUserError, LoadUserService, LoginToken},
    middleware::{AuthMiddleware, PathMatcher},
    multifactor::{google_auth::GoogleAuthFactor, TotpSecretRepository},
    session::{
        handlers::{login_config, SessionLoginHandler},
        session_auth::SessionAuthProvider,
    },
    AuthToken,
};

use futures::future::LocalBoxFuture;
use google_authenticator::GoogleAuthenticator;
use reqwest::{Client, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

const SECRET: &str = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub email: String,
    pub name: String,
}

fn mfa_condition(user: &User, _req: &HttpRequest) -> bool {
    user.name == "anna"
}

pub struct HardCodedLoadUserService {}

impl LoadUserService for HardCodedLoadUserService {
    type User = User;

    fn load_user(
        &self,
        login_token: &LoginToken,
    ) -> LocalBoxFuture<'_, Result<Self::User, LoadUserError>> {
        if (login_token.username == "anna" || login_token.username == "bob")
            && login_token.password == "test123"
        {
            Box::pin(ready(Ok(User {
                name: login_token.username.to_owned(),
                email: format!("{}@example.org", login_token.username),
            })))
        } else {
            Box::pin(ready(Err(LoadUserError::LoginFailed)))
        }
    }

    fn on_success_handler(
        &self,
        _req: &HttpRequest,
        _user: &Self::User,
    ) -> LocalBoxFuture<'_, Result<(), HandlerError>> {
        Box::pin(ready(Ok(())))
    }

    fn on_error_handler(&self, _req: &HttpRequest) -> LocalBoxFuture<'_, Result<(), HandlerError>> {
        Box::pin(ready(Ok(())))
    }
}

struct TotpTestRepo;

#[derive(Error, Debug)]
#[error("No secret found in repo")]
struct NoSecretFoundError;

impl<U> TotpSecretRepository<U> for TotpTestRepo
where
    U: DeserializeOwned,
{
    type Error = NoSecretFoundError;

    fn get_auth_secret(
        &self,
        _user: &U,
    ) -> impl std::future::Future<Output = Result<String, Self::Error>> {
        Box::pin(ready(Ok(SECRET.to_owned())))
    }
}

#[get("/secured-route")]
pub async fn secured_route(token: AuthToken<User>) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Request from user: {}",
        token.get_authenticated_user().email
    ))
}

fn create_actix_session_middleware() -> SessionMiddleware<CookieSessionStore> {
    let key = Key::generate();

    SessionMiddleware::new(CookieSessionStore::default(), key.clone())
}

#[actix_rt::test]
async fn should_not_be_logged_in_without_mfa() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    let mut res = client
        .post(format!("http://{addr}/login"))
        .body("{ \"username\": \"anna\", \"password\": \"test123\" }")
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn should_return_401_if_calling_mfa_without_login() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();
    let authenticator = GoogleAuthenticator::new();
    let code = authenticator
        .get_code(SECRET, 0)
        .expect("Code should be created");

    let res = client
        .post(format!("http://{addr}/login/mfa"))
        .body(format!("{{ \"code\": \"{}\" }}", code))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn should_be_logged_in_after_mfa() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();
    let authenticator = GoogleAuthenticator::new();
    let code = authenticator
        .get_code(SECRET, 0)
        .expect("Code should be created");

    client
        .post(format!("http://{addr}/login"))
        .body("{ \"username\": \"anna\", \"password\": \"test123\" }")
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let mut res = client
        .post(format!("http://{addr}/login/mfa"))
        .body(format!("{{ \"code\": \"{}\" }}", code))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

#[actix_rt::test]
async fn should_be_not_logged_in_if_mfa_fails() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body("{ \"username\": \"anna\", \"password\": \"test123\" }")
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let mut res = client
        .post(format!("http://{addr}/login/mfa"))
        .body(format!("{{ \"code\": \"{}\" }}", "\"WRONGCODE\""))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

fn start_test_server(addr: SocketAddr) {
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                let totp_secret_repo = Arc::new(TotpTestRepo);

                HttpServer::new(move || {
                    App::new()
                        .service(secured_route)
                        .configure(login_config(SessionLoginHandler::with_mfa_condition(
                            HardCodedLoadUserService {},
                            mfa_condition,
                        )))
                        .wrap(AuthMiddleware::<_, User>::new_with_factor(
                            SessionAuthProvider,
                            PathMatcher::default(),
                            Box::new(GoogleAuthFactor::<_, User>::with_discrepancy(
                                Arc::clone(&totp_secret_repo),
                                3,
                            )),
                        ))
                        .wrap(create_actix_session_middleware())
                })
                .bind(format!("{addr}"))
                .unwrap()
                .run()
                .await
            })
            .unwrap();
    });
}
