use std::{net::SocketAddr, thread};

use actix_web::{cookie::Cookie, get, HttpRequest, HttpResponse, HttpServer, Responder};
use async_trait::async_trait;
use authfix::{
    mfa::{HandleMfaRequest, MfaConfig, MfaError},
    multifactor::{
        random_code_auth::{MfaRandomCode, MFA_ID_RANDOM_CODE},
        Factor,
    },
    session::app_builder::SessionLoginAppBuilder,
    AuthToken,
};
use reqwest::{Client, StatusCode};
use test_utils::{single_code_generator, DoNotSendCode, HardCodedLoadUserService, User};

mod test_utils;

struct LoadMfa;

#[async_trait(?Send)]
impl HandleMfaRequest for LoadMfa {
    type User = User;

    async fn get_mfa_id_by_user(&self, _: &Self::User) -> Result<Option<String>, MfaError> {
        Ok(Some(MFA_ID_RANDOM_CODE.to_owned()))
    }

    async fn is_condition_met(&self, user: &Self::User, req: HttpRequest) -> bool {
        req.cookie(&user.name).is_none()
    }

    async fn handle_success(&self, user: &Self::User, mut res: HttpResponse) -> HttpResponse {
        res.add_cookie(&Cookie::new(&user.name, "already checked"))
            .unwrap();
        res
    }
}

#[get("secured-route")]
async fn secured_route(_user: AuthToken<User>) -> impl Responder {
    HttpResponse::Ok()
}

#[actix_rt::test]
async fn should_be_logged_in_using_random_code() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    // Anna logs in for the first time
    let res = client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "anna", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    // MFA needed
    assert!(res.text().await.unwrap().contains("MfaNeeded"));

    client
        .post(format!("http://{addr}/login/mfa"))
        .body(format!("{{ \"code\": \"{}\" }}", "123abc"))
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    // Anna can access the resource now
    let res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    client
        .post(format!("http://{addr}/logout"))
        .send()
        .await
        .unwrap();

    // Login again
    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "anna", "password": "test123" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    // Do not need MFA this time
    let res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

fn start_test_server(addr: SocketAddr) {
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                let app_closure = move || {
                    let rand_code: Box<dyn Factor> =
                        Box::new(MfaRandomCode::new(single_code_generator, DoNotSendCode));

                    let mfa_config = MfaConfig::new(vec![rand_code], LoadMfa);

                    SessionLoginAppBuilder::create(HardCodedLoadUserService)
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
