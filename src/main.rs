use cert_manager_alidns_webhook::config::Config;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    // kube-client and reqwest build their TLS configs from the process default.
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        anyhow::bail!("a rustls crypto provider was already installed");
    }
    cert_manager_alidns_webhook::run(Config::from_env()?).await
}
