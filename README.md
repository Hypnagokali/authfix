# auth-middleware-for-actix-web
> Middleware that secures routes globally and provides an extractor for the authenticated user with Actix-Web and Actix-Session

This library provides a middleware for [Actix-Web](https://github.com/actix/actix-web) to secure routes globally based on other authentication middleware like [Actix-Session](https://github.com/actix/actix-extras/tree/master/actix-session) and it provides an extractor to retrieve the logged in user.

*I have implemented this middleware for my personal use, but maybe it can help others to save time as well. Feel free to submit issues.*

ToDo:
- [x] Implementation for Actix-Session
    - [ ] Logout-Wrapper for Actix-Session
    - [ ] Docs and Tests
    - [ ] CI/CD
- [ ] Implementation for OAuth 2.0
- [ ] Implementation for a JWT library(?)


Example with Actix-Session:

```rust
use auth_middleware_for_actix_web::{
    middleware::{AuthMiddleware, PathMatcher},
    session::session_auth::{GetUserFromSession, UserSession},
    AuthToken
};
use actix_web::{
    post, get,
    web::{Form, Data},
    HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};

// To serialize User to and deserialize from Session it needs these serde traits:
#[derive(Serialize, Deserialize)]
pub struct User {
    pub email: String,
    pub name: String,
}

#[get("/secured-route")]
pub async fn secured_route(token: AuthToken<User>) -> impl Responder {
    HttpResponse::Ok().body(format!("Request from user: {}", token.get_authenticated_user().email))
}

#[post("/login")]
async fn login(
    login_form: Form<FormLogin>,
    session: UserSession
) -> impl Responder {
    match find_user_logic(&login_form.email).await {
        Ok(user) => {
            if is_password_correct_logic(&user, &login_form.password).await {
                session.set_user(user).expect("User could not be set in session");
                return HttpResponse::Ok();
            }
        }
    }

    HttpResponse::BadRequest()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let server = HttpServer::new(move || {
        App::new()
        .service(secured_route)
        .service(login)
        // The order is important. Actix-Session must be executed before AuthMiddleware
        .wrap(AuthMiddleware::<_, User>::new(GetUserFromSession, PathMatcher::default()))
        .wrap(create_actix_session_middleware()) // see Actix-Session on how to create the session middleware
        
    })
    .bind(("127.0.0.1", "8080"))?
    .run();

    server.await
}
```







