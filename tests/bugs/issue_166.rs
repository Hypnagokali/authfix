use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    thread,
};

use actix_web::{cookie::Key, HttpServer};
use async_trait::async_trait;
use authfix::{
    multifactor::config::{HandleMfaRequest, MfaConfig, MfaError},
    session::{
        app_builder::SessionLoginAppBuilder,
        factor_impl::random_code_auth::{
            CodeSendError, CodeSender, MfaRandomCodeFactor, RandomCode,
        },
    },
};
use authfix_test_utils::{HardCodedLoadUserService, User};
use chrono::{Local, TimeDelta};
use reqwest::Client;

struct OnlyRandomCodeFactor;

#[async_trait(?Send)]
impl HandleMfaRequest for OnlyRandomCodeFactor {
    type User = User;

    async fn mfa_id_by_user(&self, _: &Self::User) -> Result<Option<String>, MfaError> {
        Ok(Some(MfaRandomCodeFactor::id().to_owned()))
    }
}

struct LoggingDummySender {
    send_to: Mutex<Option<String>>,
}

impl CodeSender for LoggingDummySender {
    type User = User;
    async fn send_code(&self, user: &User, _: RandomCode) -> Result<(), CodeSendError> {
        let mut send_to_guard = self.send_to.lock().unwrap();
        *send_to_guard = Some(user.email.clone());
        Ok(())
    }
}

#[actix_rt::test]
async fn should_send_a_message_to_user() {
    let addr = actix_test::unused_addr();

    let sender = Arc::new(LoggingDummySender {
        send_to: Mutex::new(None),
    });
    start_test_server(addr, Arc::clone(&sender));

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "anna", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let send_to_guard = sender.send_to.lock().unwrap();
    assert!(send_to_guard.is_some());
    assert_eq!(send_to_guard.as_ref().unwrap(), "anna@example.org");
}

fn single_code_generator() -> RandomCode {
    let valid_until = Local::now()
        .checked_add_signed(TimeDelta::minutes(5))
        .unwrap();
    RandomCode::new("123abc", valid_until.into())
}

fn start_test_server(addr: SocketAddr, sender: Arc<LoggingDummySender>) {
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                let key = Key::generate();

                HttpServer::new(move || {
                    let code_factor = Box::new(MfaRandomCodeFactor::new(
                        single_code_generator,
                        Arc::clone(&sender),
                    ));
                    let mfa_config = MfaConfig::new(vec![code_factor], OnlyRandomCodeFactor);

                    SessionLoginAppBuilder::create(HardCodedLoadUserService, key.clone())
                        .set_mfa(mfa_config)
                        .build()
                })
                .bind(format!("{addr}"))
                .unwrap()
                .run()
                .await
            })
            .unwrap();
    });
}
