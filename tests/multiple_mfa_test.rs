use std::{net::SocketAddr, sync::Arc, thread};

use actix_web::{cookie::Key, get, HttpResponse, HttpServer, Responder};
use async_trait::async_trait;
use authfix::{
    login::{LoadUserByCredentials, LoadUserError, LoginToken},
    mfa::{HandleMfaRequest, MfaConfig, MfaError},
    multifactor::{
        authenticator::{AuthenticatorFactor, MFA_ID_AUTHENTICATOR_TOTP},
        random_code_auth::{MfaRandomCode, MFA_ID_RANDOM_CODE},
        Factor,
    },
    session::{app_builder::SessionLoginAppBuilder, AccountInfo},
    AuthToken,
};

use google_authenticator::GoogleAuthenticator;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use test_utils::{single_code_generator, DoNotSendCode, TotpTestRepo, SECRET};

mod test_utils;

#[derive(Serialize, Deserialize, Clone)]
struct UserWithMfa {
    name: String,
    mfa: Option<String>,
}

impl AccountInfo for UserWithMfa {}

struct LoadMfa;

#[async_trait(?Send)]
impl HandleMfaRequest for LoadMfa {
    type User = UserWithMfa;

    async fn get_mfa_id_by_user(&self, user: &Self::User) -> Result<Option<String>, MfaError> {
        Ok(user.mfa.clone())
    }
}

struct ThreeUserService;

#[async_trait]
impl LoadUserByCredentials for ThreeUserService {
    type User = UserWithMfa;

    async fn load_user(&self, login_token: &LoginToken) -> Result<Self::User, LoadUserError> {
        match login_token.email.as_ref() {
            "joe" => Ok(UserWithMfa {
                name: "Joe".into(),
                mfa: Some(MFA_ID_AUTHENTICATOR_TOTP.into()),
            }),
            "anna" => Ok(UserWithMfa {
                name: "anna".into(),
                mfa: Some(MFA_ID_RANDOM_CODE.into()),
            }),
            "linda" => Ok(UserWithMfa {
                name: "linda".into(),
                mfa: None,
            }),
            _ => Err(LoadUserError::LoginFailed),
        }
    }
}

#[get("/secured-route")]
async fn secured_route(_: AuthToken<UserWithMfa>) -> impl Responder {
    HttpResponse::Ok()
}

#[actix_rt::test]
async fn should_be_logged_in_without_mfa() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "linda", "password": "test123" }"#)
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
async fn should_be_logged_in_using_authenticator() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();
    let authenticator = GoogleAuthenticator::new();
    let code = authenticator
        .get_code(SECRET, 0)
        .expect("Code should be created");

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "joe", "password": "test123" }"#)
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
async fn should_be_logged_in_using_random_code() {
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

fn start_test_server(addr: SocketAddr) {
    let key = Key::generate();
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                let totp_secret_repo = Arc::new(TotpTestRepo);
                let sender = Arc::new(DoNotSendCode);
                let app_closure = move || {
                    let authenticator: Box<dyn Factor> =
                        Box::new(AuthenticatorFactor::<_, UserWithMfa>::with_discrepancy(
                            Arc::clone(&totp_secret_repo),
                            3,
                        ));
                    let rand_code: Box<dyn Factor> = Box::new(MfaRandomCode::new(
                        single_code_generator,
                        Arc::clone(&sender),
                    ));

                    let mfa_config = MfaConfig::new(vec![authenticator, rand_code], LoadMfa);

                    SessionLoginAppBuilder::create(ThreeUserService, key.clone())
                        .set_mfa(mfa_config)
                        .build()
                        .service(secured_route)
                };

                HttpServer::new(app_closure)
                    .bind(format!("{addr}"))
                    .unwrap()
                    .run()
                    .await
            })
            .unwrap();
    });
}
