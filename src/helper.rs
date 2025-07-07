use actix_web::{
    http::header::{CacheControl, CacheDirective, EXPIRES, PRAGMA},
    HttpResponse, HttpResponseBuilder,
};

// redirect header builder
pub(crate) fn redirect_response_builder() -> HttpResponseBuilder {
    let mut builder = HttpResponse::Found();

    builder
        .insert_header(CacheControl(vec![
            CacheDirective::NoCache,
            CacheDirective::NoStore,
            CacheDirective::MustRevalidate,
        ]))
        .insert_header((PRAGMA, "no-cache"))
        .insert_header((EXPIRES, 0));

    builder
}
