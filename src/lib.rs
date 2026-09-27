//! cert-manager DNS01 webhook solver for Alibaba Cloud DNS.

pub mod alidns;
pub mod challenge;
pub mod config;
pub mod requestheader;
pub mod server;
pub mod tls;

use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::tls::{ReloadingCert, Snapshot};

/// Loads TLS and trust material, then serves the webhook until SIGTERM or Ctrl-C.
pub async fn run(config: Config) -> Result<()> {
    let certificate = Arc::new(ReloadingCert::load(
        config.tls_cert_file.clone(),
        config.tls_key_file.clone(),
    )?);
    let kube = kube::Client::try_default()
        .await
        .context("cannot create Kubernetes client")?;
    let request_header = requestheader::fetch(&kube).await?;
    let snapshot = Arc::new(ArcSwap::from_pointee(Snapshot::build(
        request_header,
        certificate.clone(),
    )?));
    tokio::spawn(requestheader::refresh(kube, certificate, snapshot.clone()));

    let alidns = alidns::Client::new(&config.alidns_endpoint, config.credentials.clone())
        .context("cannot create AliDNS client")?;
    let state = Arc::new(server::State::new(
        &config.group_name,
        &config.solver_name,
        alidns,
    ));
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("cannot listen on {}", config.listen_addr))?;
    tracing::info!(
        addr = %config.listen_addr,
        group = %config.group_name,
        solver = %config.solver_name,
        "serving cert-manager DNS01 webhook"
    );
    server::serve(listener, snapshot, state, shutdown_signal()).await;
    tracing::info!("shutting down");
    Ok(())
}

/// Resolves on SIGTERM or Ctrl-C.
async fn shutdown_signal() {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::warn!("cannot install SIGTERM handler: {error}");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        () = terminate => {},
    }
}
