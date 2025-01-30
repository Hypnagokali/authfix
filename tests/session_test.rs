use std::{net::SocketAddr, thread};

use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, get, post, App, HttpResponse, HttpServer, Responder};
use auth_middleware_for_actix_web::{
    middleware::{AuthMiddleware, PathMatcher},
    session::session_auth::{SessionAuthProvider, UserSession},
    AuthToken,
};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub email: String,
    pub name: String,
}

#[get("/public-route")]
pub async fn public_route(token: AuthToken<User>) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Request from user: {}",
        token.get_authenticated_user().email
    ))
}

#[get("/secured-route")]
pub async fn secured_route(token: AuthToken<User>) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "Request from user: {}",
        token.get_authenticated_user().email
    ))
}

#[post("/logout")]
pub async fn logout(token: AuthToken<User>) -> impl Responder {
    token.invalidate();
    HttpResponse::Ok()
}

#[post("/login")]
async fn login(session: UserSession) -> impl Responder {
    // For session based authentication we need to manually check user and password and save the user in the session
    let user = User {
        email: "jenny@example.org".to_owned(),
        name: "Jenny B.".to_owned(),
    };

    session
        .set_user(user)
        .expect("User could not be set in session");

    HttpResponse::Ok()
}

fn create_actix_session_middleware() -> SessionMiddleware<CookieSessionStore> {
    let key = Key::generate();

    SessionMiddleware::new(CookieSessionStore::default(), key.clone())
}

#[actix_rt::test]
async fn should_can_login() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
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
async fn should_return_401_when_auth_token_is_used_in_a_non_secured_route() {
    let addr = actix_test::unused_addr();

    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    let res = client
        .get(format!("http://{addr}/public-route"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
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
async fn logout_should_invalidate_session() {
    let addr = actix_test::unused_addr();
    start_test_server(addr);

    let client = Client::builder().cookie_store(true).build().unwrap();

    client
        .post(format!("http://{addr}/login"))
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
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                HttpServer::new(move || {
                    App::new()
                        .service(secured_route)
                        .service(login)
                        .service(logout)
                        .service(public_route)
                        .wrap(AuthMiddleware::<_, User>::new(
                            SessionAuthProvider,
                            PathMatcher::new(vec!["/login", "/public-route"], true),
                        ))
                        .wrap(create_actix_session_middleware())
                })
                .bind(format!("{addr}"))
                .unwrap()
                .run()
                .await
            })
            .unwrap();
    });
}
