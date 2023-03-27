use crate::relying_party::RelyingParty;
use crate::response::SiopResponse;
use axum::{http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use std::net::SocketAddr;

pub async fn relying_party() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new()
        // `POST /users` goes to `create_user`
        .route("/redirect_uri", post(redirect_uri));

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([127, 0, 0, 1], 4200));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn redirect_uri(
    // this argument tells axum to parse the request body
    // as JSON into a `CreateUser` type
    // Json(payload): Json<CreateUser>,
    Json(response): Json<SiopResponse>,
) -> impl IntoResponse {
    println!(
        "GREAT: Response received!, this is the response: {:?}",
        response
    );
    StatusCode::OK
}
// }
