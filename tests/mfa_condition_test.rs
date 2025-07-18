use std::{net::SocketAddr, sync::Arc, thread};

use actix_web::{
    cookie::{Cookie, Key},
    get, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer, Responder,
};
use async_trait::async_trait;
use authfix::{
    factor_impl::random_code_auth::MfaRandomCodeFactor,
    multifactor::{
        config::{HandleMfaRequest, MfaConfig, MfaError},
        factor::Factor,
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
        Ok(Some(MfaRandomCodeFactor::id().to_owned()))
    }

    async fn is_condition_met(&self, user: &Self::User, req: HttpRequest) -> bool {
        req.cookie(&user.name).is_none()
    }

    async fn handle_success(
        &self,
        user: &Self::User,
        mut res: HttpResponseBuilder,
    ) -> HttpResponseBuilder {
        res.cookie(Cookie::new(&user.name, "already checked"));

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
    let key = Key::generate();
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                let sender = Arc::new(DoNotSendCode);
                let app_closure = move || {
                    let rand_code: Box<dyn Factor> = Box::new(MfaRandomCodeFactor::new(
                        single_code_generator,
                        Arc::clone(&sender),
                    ));

                    let mfa_config = MfaConfig::new(vec![rand_code], LoadMfa);

                    SessionLoginAppBuilder::create(HardCodedLoadUserService, key.clone())
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
