use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::CONTENT_TYPE;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::tls::Snapshot;
use crate::{alidns, challenge};

const MAX_BODY_BYTES: usize = 1 << 20;

pub struct State {
    group_version: String,
    discovery_path: String,
    solver_path: String,
    solver_name: String,
    alidns: alidns::Client,
}

impl State {
    /// Derives the API paths for `group_name` and `solver_name`.
    pub fn new(group_name: &str, solver_name: &str, alidns: alidns::Client) -> Self {
        let group_version = format!("{group_name}/v1alpha1");
        Self {
            discovery_path: format!("/apis/{group_version}"),
            solver_path: format!("/apis/{group_version}/{solver_name}"),
            group_version,
            solver_name: solver_name.to_owned(),
            alidns,
        }
    }
}

/// Accepts TLS connections until `shutdown` resolves, using the current TLS snapshot per connection.
pub async fn serve(
    listener: TcpListener,
    tls: Arc<ArcSwap<Snapshot>>,
    state: Arc<State>,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    loop {
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(error) => {
                    tracing::warn!("accept failed: {error}");
                    continue;
                }
            },
            () = &mut shutdown => return,
        };
        let snapshot = tls.load_full();
        let state = state.clone();
        tokio::spawn(async move {
            let stream = match TlsAcceptor::from(snapshot.server_config.clone())
                .accept(stream)
                .await
            {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!("TLS handshake failed: {error}");
                    return;
                }
            };
            let authenticated = snapshot.is_front_proxy(stream.get_ref().1.peer_certificates());
            let service = service_fn(move |request| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(route(&state, authenticated, request).await) }
            });
            if let Err(error) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!("connection closed with error: {error}");
            }
        });
    }
}

/// Dispatches one request; only health endpoints are served to unauthenticated clients.
async fn route(
    state: &State,
    authenticated: bool,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let path = request.uri().path();
    if request.method() == Method::GET && matches!(path, "/healthz" | "/livez" | "/readyz") {
        return text(StatusCode::OK, "ok");
    }
    if !authenticated {
        return status(StatusCode::UNAUTHORIZED, "Unauthorized", "Unauthorized");
    }
    if path == state.discovery_path {
        if request.method() != Method::GET {
            return status(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "method not allowed",
            );
        }
        return json_response(StatusCode::OK, &discovery(state));
    }
    if path != state.solver_path {
        return status(
            StatusCode::NOT_FOUND,
            "NotFound",
            "the server could not find the requested resource",
        );
    }
    if request.method() != Method::POST {
        return status(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "method not allowed",
        );
    }
    let body = match Limited::new(request.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(error) => {
            return status(
                StatusCode::BAD_REQUEST,
                "BadRequest",
                &format!("cannot read body: {error}"),
            );
        }
    };
    let (payload, challenge) = match challenge::decode(&body) {
        Ok(decoded) => decoded,
        Err(message) => return status(StatusCode::BAD_REQUEST, "BadRequest", &message),
    };
    let result = challenge::solve(&state.alidns, &challenge).await;
    match &result {
        Ok(()) => {
            tracing::info!(uid = %challenge.uid, action = ?challenge.action, fqdn = %challenge.resolved_fqdn, "challenge solved")
        }
        Err(error) => {
            tracing::warn!(uid = %challenge.uid, action = ?challenge.action, fqdn = %challenge.resolved_fqdn, "challenge failed: {error}")
        }
    }
    let result = result.map_err(|error| error.to_string());
    json_response(
        StatusCode::CREATED,
        &challenge::respond(payload, &state.group_version, &challenge, result),
    )
}

/// The `APIResourceList` advertising the solver resource.
fn discovery(state: &State) -> Value {
    json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": state.group_version,
        "resources": [{
            "name": state.solver_name,
            "singularName": "ChallengePayload",
            "namespaced": false,
            "kind": "ChallengePayload",
            "verbs": ["create"],
        }],
    })
}

/// A Kubernetes `Status` failure response.
fn status(code: StatusCode, reason: &str, message: &str) -> Response<Full<Bytes>> {
    json_response(
        code,
        &json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": message,
            "reason": reason,
            "code": code.as_u16(),
        }),
    )
}

/// A JSON response with the given status code.
fn json_response(code: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    response(code, "application/json", body.to_string())
}

/// A plain-text response with the given status code.
fn text(code: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    response(code, "text/plain; charset=utf-8", body.to_owned())
}

/// A response with the given status, content type, and body.
fn response(code: StatusCode, content_type: &'static str, body: String) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = code;
    response.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(content_type),
    );
    response
}
