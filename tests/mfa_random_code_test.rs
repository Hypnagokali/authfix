use std::{net::SocketAddr, sync::Arc, thread};

use actix_session::{storage::CookieSessionStore, SessionExt, SessionMiddleware};
use actix_web::{cookie::Key, get, App, HttpRequest, HttpResponse, HttpServer, Responder};
use async_trait::async_trait;
use authfix::{
    middleware::{AuthMiddleware, PathMatcher},
    multifactor::config::{HandleMfaRequest, MfaConfig, MfaError},
    session::{
        auth_flow::SessionAuthFlow,
        config::Routes,
        factor_impl::random_code_auth::{
            CodeSendError, CodeSender, MfaRandomCodeFactor, RandomCode,
        },
        session_auth::SessionAuthProvider,
    },
    AuthToken,
};
use authfix_test_utils::{HardCodedLoadUserService, User};
use chrono::{Duration, Local, TimeDelta};
use reqwest::{Client, StatusCode};

struct OnlyRandomCodeFactor;

#[async_trait(?Send)]
impl HandleMfaRequest for OnlyRandomCodeFactor {
    type User = User;

    async fn mfa_id_by_user(&self, _: &Self::User) -> Result<Option<String>, MfaError> {
        Ok(Some(MfaRandomCodeFactor::id().to_owned()))
    }
}

#[actix_rt::test]
async fn should_be_able_to_logout() {
    let addr = actix_test::unused_addr();
    start_test_server(addr, single_code_generator);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "anna", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    client
        .post(format!("http://{addr}/login/mfa"))
        .body(format!("{{ \"code\": \"{}\" }}", "123abc"))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    client
        .post(format!("http://{addr}/logout"))
        .send()
        .await
        .unwrap();

    let res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn should_be_possible_to_try_mfa_again() {
    let addr = actix_test::unused_addr();
    start_test_server(addr, single_code_generator);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "anna", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    client
        .post(format!("http://{addr}/login/mfa"))
        .body(format!("{{ \"code\": \"{}\" }}", "oops wrong code"))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    client
        .post(format!("http://{addr}/login/mfa"))
        .body(format!("{{ \"code\": \"{}\" }}", "123abc"))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

#[actix_rt::test]
async fn should_be_possible_to_login_again_before_mfa_has_been_passed() {
    let addr = actix_test::unused_addr();
    start_test_server(addr, single_code_generator);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "anna", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    // sets a value to annas login session
    client
        .get(format!("http://{addr}/unsecure/manipulate-session"))
        .send()
        .await
        .unwrap();

    // now, login with bob:
    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "bob", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    client
        .post(format!("http://{addr}/login/mfa"))
        .body(format!("{{ \"code\": \"{}\" }}", "123abc"))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    // Annas session attribute should not be available to Bobs session
    assert_eq!(
        res.text().await.unwrap(),
        "User: bob@example.org, privateValue: na"
    );
}

#[actix_rt::test]
async fn should_not_be_logged_in_if_code_is_wrong() {
    let addr = actix_test::unused_addr();
    start_test_server(addr, single_code_generator);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "anna", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn should_be_logged_in_after_sending_correct_code() {
    let addr = actix_test::unused_addr();
    start_test_server(addr, single_code_generator);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "anna", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    client
        .post(format!("http://{addr}/login/mfa"))
        .body(format!("{{ \"code\": \"{}\" }}", "123abc"))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

#[actix_rt::test]
async fn should_not_be_logged_in_after_time_is_up() {
    let addr = actix_test::unused_addr();
    start_test_server(addr, immediately_not_valid_generator);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "anna", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    client
        .post(format!("http://{addr}/login/mfa"))
        .body(format!("{{ \"code\": \"{}\" }}", "123abc"))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

struct DummySender;

impl CodeSender for DummySender {
    type User = User;
    async fn send_code(&self, _: &User, _: RandomCode) -> Result<(), CodeSendError> {
        // send code
        Ok(())
    }
}

#[get("/secured-route")]
pub async fn secured_route(token: AuthToken<User>, req: HttpRequest) -> impl Responder {
    let pv = req
        .get_session()
        .get::<String>("privateValue")
        .unwrap()
        .unwrap_or("na".to_owned());
    HttpResponse::Ok().body(format!(
        "User: {}, privateValue: {}",
        token.authenticated_user().email,
        pv
    ))
}

#[get("/unsecure/manipulate-session")]
pub async fn manipulate_session(req: HttpRequest) -> impl Responder {
    req.get_session()
        .insert("privateValue", "some value")
        .unwrap();
    HttpResponse::Ok()
}

fn create_actix_session_middleware() -> SessionMiddleware<CookieSessionStore> {
    let key = Key::generate();

    SessionMiddleware::new(CookieSessionStore::default(), key.clone())
}

fn single_code_generator() -> RandomCode {
    let valid_until = Local::now()
        .checked_add_signed(TimeDelta::minutes(5))
        .unwrap();
    RandomCode::new("123abc", valid_until.into())
}

fn immediately_not_valid_generator() -> RandomCode {
    let valid_until = Local::now() - Duration::minutes(1);
    RandomCode::new("123abc", valid_until.into())
}

fn start_test_server(addr: SocketAddr, generator: fn() -> RandomCode) {
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                let sender = Arc::new(DummySender);

                let load_user_service = Arc::new(HardCodedLoadUserService);
                HttpServer::new(move || {
                    // Hint:
                    // This is the manual configuration of the auth middleware with a session provider and handlers.

                    let code_factor =
                        Box::new(MfaRandomCodeFactor::new(generator, Arc::clone(&sender)));
                    let mfa_config = MfaConfig::new(vec![code_factor], OnlyRandomCodeFactor);

                    App::new()
                        .service(secured_route)
                        .configure(
                            SessionAuthFlow::<HardCodedLoadUserService, User>::default().config(),
                        )
                        .wrap(AuthMiddleware::new(
                            SessionAuthProvider::new_with_mfa(
                                load_user_service.clone(),
                                mfa_config,
                                Routes::default(),
                            ),
                            PathMatcher::new(vec!["/login", "/unsecure/*"], true),
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
