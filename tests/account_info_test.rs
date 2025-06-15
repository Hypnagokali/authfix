use std::{net::SocketAddr, thread};

use actix_web::{cookie::Key, get, HttpResponse, HttpServer, Responder};
use async_trait::async_trait;
use authfix::{
    login::{LoadUserByCredentials, LoadUserError, LoginToken},
    session::{app_builder::SessionLoginAppBuilder, AccountInfo},
    AuthToken,
};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
struct User {
    name: String,
    disabled: bool,
    account_logged: bool,
}

struct LoadUser;

#[async_trait]
impl LoadUserByCredentials for LoadUser {
    type User = User;

    async fn load_user(&self, login_token: &LoginToken) -> Result<Self::User, LoadUserError> {
        if login_token.email == "bernd" {
            Ok(User {
                name: "Bernd".to_owned(),
                disabled: true,
                account_logged: false,
            })
        } else if login_token.email == "anna" {
            Ok(User {
                name: "Anna".to_owned(),
                disabled: false,
                account_logged: true,
            })
        } else {
            Err(LoadUserError::LoginFailed)
        }
    }
}

impl AccountInfo for User {
    fn get_user_identification(&self) -> String {
        self.name.clone()
    }

    fn is_user_disabled(&self) -> bool {
        self.disabled
    }

    fn is_account_locked(&self) -> bool {
        self.account_logged
    }
}

#[get("/secured-route")]
pub async fn secured_route(_: AuthToken<User>) -> impl Responder {
    HttpResponse::Ok()
}

#[actix_rt::test]
async fn should_not_login_if_user_disabled() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "bernd", "password": "none" }"#)
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
async fn should_not_login_if_account_locked() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "anna", "password": "none" }"#)
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

fn start_test_server(addr: SocketAddr) {
    let key = Key::generate();
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                HttpServer::new(move || {
                    SessionLoginAppBuilder::create(LoadUser, key.clone())
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
