use std::{
    net::SocketAddr,
    sync::Arc,
    thread,
    time::{Duration, SystemTime},
};

use actix_web::{cookie::Key, get, HttpRequest, HttpResponse, HttpServer, Responder};
use async_trait::async_trait;
use authfix::{
    factor_impl::random_code_auth::{CodeSendError, CodeSender, MfaRandomCodeFactor, RandomCode},
    multifactor::config::{HandleMfaRequest, MfaConfig, MfaError},
    session::app_builder::SessionLoginAppBuilder,
};
use reqwest::{redirect::Policy, Client, StatusCode};

use crate::test_utils::{HardCodedLoadUserService, User};

mod test_utils;

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

#[get("/login")]
async fn login_page() -> impl Responder {
    HttpResponse::Ok().body("Login Page")
}

#[actix_rt::test]
async fn should_redirect_to_login_if_not_authorized_if_browser_request() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap();

    let res = client
        .get(format!("http://{addr}/secured-route?some=value"))
        // just an example of a possible accept header
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FOUND);
    assert!(res.headers().get("location").is_some());
    let location_header = res.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(
        location_header,
        "/login?redirect_uri=%2Fsecured-route%3Fsome%3Dvalue"
    );
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

#[actix_rt::test]
async fn should_redirect_to_mfa() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap();

    let res = client
        .post(format!(
            "http://{addr}/login?redirect_uri=%2Fsecured-route%3Fsome%3Dvalue"
        ))
        .body("email=anna&password=test123")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FOUND);
    let location_header = res.headers().get("location").unwrap();
    assert_eq!(
        location_header,
        "/login/mfa?redirect_uri=%2Fsecured-route%3Fsome%3Dvalue"
    );
}

#[actix_rt::test]
async fn should_redirect_without_error_if_login_succeeded() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap();

    let res = client
        .post(format!(
            "http://{addr}/login?error&redirect_uri=%2Fsecured-route%3Fsome%3Dvalue"
        ))
        .body("email=anna&password=test123")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FOUND);
    let location_header = res.headers().get("location").unwrap();
    assert_eq!(
        location_header,
        "/login/mfa?redirect_uri=%2Fsecured-route%3Fsome%3Dvalue"
    );
}

#[actix_rt::test]
async fn should_redirect_to_redirect_uri_after_mfa_correct() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap();

    client
        .post(format!(
            "http://{addr}/login?redirect_uri=%2Fsecured-route%3Fsome%3Dvalue"
        ))
        .body("email=anna&password=test123")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .unwrap();

    let res = client
        .post(format!(
            "http://{addr}/login/mfa?redirect_uri=%2Fsecured-route%3Fsome%3Dvalue"
        ))
        .body("code=123")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FOUND);
    let location_header = res.headers().get("location").unwrap();
    assert_eq!(location_header, "/secured-route?some=value");
}

#[actix_rt::test]
async fn should_redirect_to_root_if_redirect_uri_is_empty() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body("email=anna&password=test123")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .unwrap();

    let res = client
        .post(format!("http://{addr}/login/mfa"))
        .body("code=123")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FOUND);
    let location_header = res.headers().get("location").unwrap();
    assert_eq!(location_header, "/");
}

#[actix_rt::test]
async fn should_redirect_to_root_if_redirect_uri_is_login() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap();

    let res = client
        .post(format!("http://{addr}/login?redirect_uri=%2Flogin%2F"))
        .body("email=bob&password=test123")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FOUND);
    let location_header = res.headers().get("location").unwrap();
    assert_eq!(location_header, "/");
}

#[actix_rt::test]
async fn should_redirect_to_default_if_already_authenticated() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap();

    // Bob logs in
    client
        .post(format!("http://{addr}/login"))
        .body("email=bob&password=test123")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .unwrap();

    // Bob tries accessing login page
    let res = client
        .get(format!("http://{addr}/login"))
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FOUND);
    let location_header = res.headers().get("location").unwrap();
    assert_eq!(location_header, "/");
}

#[actix_rt::test]
async fn should_redirect_to_login_with_error_if_credentials_wrong() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap();

    let res = client
        .post(format!(
            "http://{addr}/login?redirect_uri=%2Fsecured-route%3Fsome%3Dvalue"
        ))
        .body("email=anna&password=nopass")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FOUND);
    let location_header = res.headers().get("location").unwrap().to_str().unwrap();
    assert!(location_header.contains("/login"));
    assert!(location_header.contains("error"));
    assert!(location_header.contains("redirect_uri=%2Fsecured-route%3Fsome%3Dvalue"));
}

#[actix_rt::test]
async fn should_redirect_to_login_when_going_to_secured_route_and_if_not_fully_authorized() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder()
        .cookie_store(true)
        .redirect(Policy::none())
        .build()
        .unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body("email=anna&password=test123")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .unwrap();

    let res = client
        .get(format!("http://{addr}/secured-route"))
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FOUND);
    let location_header = res.headers().get("location").unwrap();
    assert_eq!(location_header, "/login?redirect_uri=%2Fsecured-route");
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
                        .with_redirect_flow()
                        .build()
                        .service(secured_route)
                        .service(login_page)
                })
                .bind(format!("{addr}"))
                .unwrap()
                .run()
                .await
            })
            .unwrap();
    });
}
