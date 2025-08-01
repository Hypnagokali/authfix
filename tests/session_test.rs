use std::{net::SocketAddr, thread};

use actix_web::{cookie::Key, get, HttpResponse, HttpServer, Responder};
use authfix::{
    login::LoadUserByCredentials,
    session::{app_builder::SessionLoginAppBuilder, config::Routes},
    AuthToken,
};
use authfix_test_utils::User;
use reqwest::{Client, StatusCode};

struct AcceptEveryoneLoginService;

impl LoadUserByCredentials for AcceptEveryoneLoginService {
    type User = User;

    async fn load_user(
        &self,
        _: &authfix::login::LoginToken,
    ) -> Result<Self::User, authfix::login::LoadUserError> {
        Ok(User {
            email: "test@example.org".to_owned(),
            name: "Test User".to_owned(),
        })
    }
}

#[get("/public-route")]
pub async fn public_route(token: AuthToken<User>) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Request from user: {}",
        token.authenticated_user().email
    ))
}

#[get("/secured-route")]
pub async fn secured_route(token: AuthToken<User>) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Request from user: {}",
        token.authenticated_user().email
    ))
}

#[actix_rt::test]
async fn should_can_login() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "any", "password": "none" }"#)
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
async fn should_return_500_when_auth_token_is_used_in_a_non_secured_route() {
    let addr = actix_test::unused_addr();

    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    let res = client
        .get(format!("http://{addr}/public-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[actix_rt::test]
async fn should_return_401_when_not_authenticated() {
    let addr = actix_test::unused_addr();

    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    let res = client
        .get(format!("http://{addr}/secured-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn should_respond_success_for_login_status() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    let login_res = client
        .post(format!("http://{addr}/login"))
        .body(r#"{ "email": "any", "password": "none" }"#)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let body = login_res.text().await.unwrap().replace(" ", "");

    assert!(body.contains(r#"status":"Success"#));
    assert!(body.contains(r#"mfaId":null"#));
}

#[actix_rt::test]
async fn logout_should_invalidate_session() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
        .body("{ \"username\": \"any\", \"password\": \"none\" }")
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

fn start_test_server(addr: SocketAddr) {
    let key = Key::generate();
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                HttpServer::new(move || {
                    SessionLoginAppBuilder::create(AcceptEveryoneLoginService, key.clone())
                        .set_login_routes_and_public_paths(Routes::default(), vec!["/public-route"])
                        .build()
                        .service(secured_route)
                        .service(public_route)
                })
                .bind(format!("{addr}"))
                .unwrap()
                .run()
                .await
            })
            .unwrap();
    });
}
