use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime},
};

use actix_web::{cookie::Key, get, HttpRequest, HttpResponse, HttpServer, Responder};
use async_trait::async_trait;
use authfix::{
    multifactor::factor_impl::random_code_auth::{CodeSendError, CodeSender, MfaRandomCodeFactor, RandomCode},
    login::{FailureHandler, HandlerError, SuccessHandler},
    multifactor::config::{HandleMfaRequest, MfaConfig, MfaError},
    session::app_builder::SessionLoginAppBuilder,
};
use reqwest::{redirect::Policy, Client, StatusCode};

use crate::test_utils::{HardCodedLoadUserService, User};

mod test_utils;

// -- Start Helper section: struct and function, to check if a method has been called
struct MethodCallUtil {
    call: String,
    success_handler_called: bool,
    failure_handler_called: bool,
}

lazy_static::lazy_static! {
    static ref METHOD_CALLS: Mutex<Vec<MethodCallUtil>> = Mutex::new(Vec::new());
}

fn is_success_handler_called(key: &str) -> bool {
    METHOD_CALLS
        .lock()
        .unwrap()
        .iter()
        .any(|m| m.call == key && m.success_handler_called && !m.failure_handler_called)
}

fn is_failure_handler_called(key: &str) -> bool {
    METHOD_CALLS
        .lock()
        .unwrap()
        .iter()
        .any(|m| m.call == key && !m.success_handler_called && m.failure_handler_called)
}
// -- End Helper section

struct MyFailureHandler;
struct MySuccessHandler;

#[async_trait(?Send)]
impl FailureHandler for MyFailureHandler {
    async fn on_failure(&self, req: HttpRequest) -> Result<(), HandlerError> {
        if let Some(h) = req.headers().get("X-CALL") {
            METHOD_CALLS.lock().unwrap().push(MethodCallUtil {
                call: h.to_str().unwrap().to_owned(),
                success_handler_called: false,
                failure_handler_called: true,
            });
        }

        Ok(())
    }
}

#[async_trait(?Send)]
impl SuccessHandler for MySuccessHandler {
    type User = User;

    async fn on_success(&self, _: &Self::User, req: HttpRequest) -> Result<(), HandlerError> {
        if let Some(h) = req.headers().get("X-CALL") {
            METHOD_CALLS.lock().unwrap().push(MethodCallUtil {
                call: h.to_str().unwrap().to_owned(),
                success_handler_called: true,
                failure_handler_called: false,
            });
        }

        Ok(())
    }
}

struct OnlyRandomCodeFactor;

#[async_trait(?Send)]
impl HandleMfaRequest for OnlyRandomCodeFactor {
    type User = User;

    async fn is_condition_met(&self, user: &Self::User, _: HttpRequest) -> bool {
        user.email == "anna@example.org"
    }

    async fn get_mfa_id_by_user(&self, _: &Self::User) -> Result<Option<String>, MfaError> {
        Ok(Some(MfaRandomCodeFactor::id().to_owned()))
    }
}

struct DummySender;

#[async_trait]
impl CodeSender for DummySender {
    async fn send_code(&self, _random_code: RandomCode) -> Result<(), CodeSendError> {
        Ok(())
    }
}

#[get("/secured-route")]
async fn secured_route() -> impl Responder {
    HttpResponse::Ok()
}

#[actix_rt::test]
async fn should_call_success_if_bobs_login_was_successfull() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "bob", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .header("X-CALL", "bob-success")
        .send()
        .await
        .unwrap();

    assert!(is_success_handler_called("bob-success"));
}

#[actix_rt::test]
async fn should_call_failure_if_bobs_login_failed() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "bob", "password": "wrongpass" }"#)
        .header("Content-Type", "application/json")
        .header("X-CALL", "bob-failure")
        .send()
        .await
        .unwrap();

    assert!(is_failure_handler_called("bob-failure"));
}

#[actix_rt::test]
async fn should_call_failure_if_anna_passed_wrong_mfa_code() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

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
        .body(r#"{ "code": "999" }"#)
        .header("Content-Type", "application/json")
        .header("X-CALL", "anna-failure")
        .send()
        .await
        .unwrap();

    assert!(is_failure_handler_called("anna-failure"));
}

#[actix_rt::test]
async fn should_call_success_if_anna_passed_correct_mfa_code() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

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
        .body(r#"{ "code": "123" }"#)
        .header("Content-Type", "application/json")
        .header("X-CALL", "anna-success")
        .send()
        .await
        .unwrap();

    assert!(is_success_handler_called("anna-success"));
}

#[actix_rt::test]
async fn should_response_401_if_any_other_request() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap();

    let res = client
        .get(format!("http://{addr}/secured-route?some=value"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

fn start_test_server(addr: SocketAddr) {
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                let sender = Arc::new(DummySender);
                let key = Key::generate();

                HttpServer::new(move || {
                    let code_factor = Box::new(MfaRandomCodeFactor::new(
                        || {
                            RandomCode::new(
                                "123",
                                SystemTime::now()
                                    .checked_add(Duration::from_secs(300))
                                    .unwrap(),
                            )
                        },
                        Arc::clone(&sender),
                    ));
                    let mfa_config = MfaConfig::new(vec![code_factor], OnlyRandomCodeFactor);
                    SessionLoginAppBuilder::create(HardCodedLoadUserService, key.clone())
                        .set_mfa(mfa_config)
                        .set_login_failure_handler(MyFailureHandler)
                        .set_login_success_handler(MySuccessHandler)
                        .build()
                        .service(secured_route)
                })
                .bind(format!("{addr}"))
                .unwrap()
                .run()
                .await
            })
            .unwrap();
    });
}
