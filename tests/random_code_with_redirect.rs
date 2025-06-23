use std::{net::SocketAddr, sync::Arc, thread, time::{Duration, SystemTime}};

use actix_web::{cookie::Key, get, http::header::ContentType, HttpResponse, HttpServer, Responder};
use async_trait::async_trait;
use authfix::{mfa::{HandleMfaRequest, MfaConfig, MfaError}, multifactor::random_code_auth::{CodeSendError, CodeSender, MfaRandomCode, RandomCode, MFA_ID_RANDOM_CODE}, session::app_builder::SessionLoginAppBuilder};
use reqwest::{Client, StatusCode};

use crate::test_utils::{HardCodedLoadUserService, User};

mod test_utils;

struct OnlyRandomCodeFactor;

#[async_trait(?Send)]
impl HandleMfaRequest for OnlyRandomCodeFactor {
    type User = User;

    async fn get_mfa_id_by_user(&self, _: &Self::User) -> Result<Option<String>, MfaError> {
        Ok(Some(MFA_ID_RANDOM_CODE.to_owned()))
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
async fn should_redirect_to_login_if_not_authorized() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    let res = client
        .get(format!("http://{addr}/secured-route"))
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FOUND);
    let location_header = res.headers().get("location").unwrap();
    assert_eq!(location_header, "/login");
}


#[actix_rt::test]
async fn should_redirect_to_mfa() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    let res = client
        .post(format!("http://{addr}/login"))
        .body("email=anna&password=test123")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FOUND);
    let location_header = res.headers().get("location").unwrap();
    assert_eq!(location_header, "/login/mfa");
}


fn start_test_server(addr: SocketAddr) {
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                let sender = Arc::new(DummySender);
                let key = Key::generate();

                HttpServer::new(move || {
                    let code_factor = Box::new(
                        MfaRandomCode::new(
                            || RandomCode::new("123", SystemTime::now().checked_add(Duration::from_secs(300)).unwrap()), 
                            Arc::clone(&sender)
                        )
                    );
                    let mfa_config = MfaConfig::new(vec![code_factor], OnlyRandomCodeFactor);
                    SessionLoginAppBuilder::create(HardCodedLoadUserService, key.clone())
                        .set_mfa(mfa_config)
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