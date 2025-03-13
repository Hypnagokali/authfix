use std::{net::SocketAddr, thread};

use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    body::MessageBody,
    cookie::Key,
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    get, App, Error, HttpResponse, HttpServer, Responder,
};
use auth_middleware_for_actix_web::{
    login::LoadUserService,
    middleware::{AuthMiddleware, PathMatcher},
    session::{
        handlers::{login_config, SessionLoginHandler},
        session_auth::SessionAuthProvider,
    },
    AuthToken, AuthenticationProvider,
};
use reqwest::{Client, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub email: String,
    pub name: String,
}

struct AcceptEveryoneLoginService {}

impl LoadUserService for AcceptEveryoneLoginService {
    type User = User;

    fn load_user(
        &self,
        _: &auth_middleware_for_actix_web::login::LoginToken,
    ) -> futures::future::LocalBoxFuture<
        '_,
        Result<Self::User, auth_middleware_for_actix_web::login::LoadUserError>,
    > {
        Box::pin(async {
            Ok(User {
                email: "test@example.org".to_owned(),
                name: "Test User".to_owned(),
            })
        })
    }

    fn on_success_handler(
        &self,
        _: &actix_web::HttpRequest,
        _: &Self::User,
    ) -> futures::future::LocalBoxFuture<
        '_,
        Result<(), auth_middleware_for_actix_web::login::HandlerError>,
    > {
        Box::pin(async { Ok(()) })
    }

    fn on_error_handler(
        &self,
        _: &actix_web::HttpRequest,
    ) -> futures::future::LocalBoxFuture<
        '_,
        Result<(), auth_middleware_for_actix_web::login::HandlerError>,
    > {
        Box::pin(async { Ok(()) })
    }
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

#[actix_rt::test]
async fn should_can_login() {
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

fn session_login_factory<U: Serialize + DeserializeOwned + Clone + 'static>(
    login_handler: SessionLoginHandler<impl LoadUserService<User = U> + 'static, U>,
    auth_middleware: AuthMiddleware<impl AuthenticationProvider<U> + Clone + 'static, U>,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Response = ServiceResponse<impl MessageBody>,
        Config = (),
        InitError = (),
        Error = Error,
    >,
> {
    App::new()
        .configure(login_config(login_handler))
        .wrap(auth_middleware)
        .wrap(create_actix_session_middleware())
}

fn create_actix_session_middleware() -> SessionMiddleware<CookieSessionStore> {
    let key = Key::generate();

    SessionMiddleware::new(CookieSessionStore::default(), key.clone())
}

fn start_test_server(addr: SocketAddr) {
    thread::spawn(move || {
        actix_rt::System::new()
            .block_on(async {
                HttpServer::new(move || {
                    session_login_factory(
                        SessionLoginHandler::new(AcceptEveryoneLoginService {}),
                        AuthMiddleware::<_, User>::new(
                            SessionAuthProvider,
                            PathMatcher::new(vec!["/login", "/public-route"], true),
                        ),
                    )
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
