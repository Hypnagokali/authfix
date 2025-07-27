use std::{net::SocketAddr, sync::Arc, thread};

use actix_web::{cookie::Key, get, HttpRequest, HttpResponse, HttpServer, Responder};
use async_trait::async_trait;
use authfix::{
    login::{LoadUserByCredentials, LoadUserError, LoginToken},
    multifactor::{
        config::{HandleMfaRequest, MfaConfig, MfaError},
        factor::Factor,
        factor_impl::authenticator::{
            AuthenticatorFactor, GetTotpSecretError, TotpSecretRepository,
        },
    },
    session::{
        app_builder::SessionLoginAppBuilder,
        factor_impl::random_code_auth::{
            CodeSendError, CodeSender, MfaRandomCodeFactor, RandomCode,
        },
        AccountInfo,
    },
    AuthToken,
};

use authfix_test_utils::{single_code_generator, SECRET};
use google_authenticator::GoogleAuthenticator;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
struct UserWithMfa {
    name: String,
    mfa: Option<String>,
}

impl AccountInfo for UserWithMfa {}

struct TotpRepositoryForUserWithMfa;

impl TotpSecretRepository for TotpRepositoryForUserWithMfa {
    type User = UserWithMfa;
    async fn auth_secret(&self, _user: &Self::User) -> Result<String, GetTotpSecretError> {
        Ok(SECRET.to_owned())
    }
}

struct LoadMfa;

#[async_trait(?Send)]
impl HandleMfaRequest for LoadMfa {
    type User = UserWithMfa;

    async fn mfa_id_by_user(&self, user: &Self::User) -> Result<Option<String>, MfaError> {
        Ok(user.mfa.clone())
    }

    async fn is_condition_met(&self, user: &Self::User, _: HttpRequest) -> bool {
        user.mfa.is_some()
    }
}

struct SomeCodeSender;

impl CodeSender for SomeCodeSender {
    type User = UserWithMfa;

    async fn send_code(&self, _: &Self::User, _: RandomCode) -> Result<(), CodeSendError> {
        Ok(())
    }
}

struct ThreeUserService;

impl LoadUserByCredentials for ThreeUserService {
    type User = UserWithMfa;

    async fn load_user(&self, login_token: &LoginToken) -> Result<Self::User, LoadUserError> {
        match login_token.email.as_ref() {
            "joe" => Ok(UserWithMfa {
                name: "Joe".into(),
                mfa: Some(AuthenticatorFactor::id()),
            }),
            "anna" => Ok(UserWithMfa {
                name: "anna".into(),
                mfa: Some(MfaRandomCodeFactor::id()),
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
        .body(format!("{{ \"code\": \"{code}\" }}"))
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

    let login = client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "anna", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    println!("LOGIN: {}", login.status());

    let muh = client
        .post(format!("http://{addr}/login/mfa"))
        .body(format!("{{ \"code\": \"{}\" }}", "123abc"))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    println!("MFA: {}", muh.status());

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
                let totp_secret_repo = Arc::new(TotpRepositoryForUserWithMfa);
                let sender = Arc::new(SomeCodeSender);
                let app_closure = move || {
                    let authenticator: Box<dyn Factor> =
                        Box::new(AuthenticatorFactor::<_, UserWithMfa>::with_discrepancy(
                            Arc::clone(&totp_secret_repo),
                            3,
                        ));
                    let rand_code: Box<dyn Factor> = Box::new(MfaRandomCodeFactor::new(
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
