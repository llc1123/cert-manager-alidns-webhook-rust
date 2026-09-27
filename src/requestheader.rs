use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::Api;

use crate::tls::{ReloadingCert, RequestHeader, Snapshot};

const NAMESPACE: &str = "kube-system";
const NAME: &str = "extension-apiserver-authentication";
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Reads the aggregator trust material from the cluster.
pub async fn fetch(client: &kube::Client) -> Result<RequestHeader> {
    let config_map = Api::<ConfigMap>::namespaced(client.clone(), NAMESPACE)
        .get(NAME)
        .await
        .with_context(|| format!("cannot read ConfigMap {NAMESPACE}/{NAME}"))?;
    parse(config_map.data.unwrap_or_default())
}

/// Extracts the client CA and allowed names from the ConfigMap data.
fn parse(data: BTreeMap<String, String>) -> Result<RequestHeader> {
    let client_ca_pem = data
        .get("requestheader-client-ca-file")
        .filter(|pem| !pem.trim().is_empty())
        .with_context(|| format!("{NAMESPACE}/{NAME} has no requestheader-client-ca-file"))?
        .clone();
    let allowed_names = match data.get("requestheader-allowed-names") {
        Some(names) if !names.trim().is_empty() => serde_json::from_str(names)
            .context("requestheader-allowed-names is not a JSON string array")?,
        _ => Vec::new(),
    };
    Ok(RequestHeader {
        client_ca_pem,
        allowed_names,
    })
}

/// Periodically re-read the aggregator trust material and swap in a new TLS
/// configuration when it changes. Failures keep the last good configuration.
pub async fn refresh(
    client: kube::Client,
    certificate: Arc<ReloadingCert>,
    snapshot: Arc<ArcSwap<Snapshot>>,
) {
    let mut interval = tokio::time::interval(REFRESH_INTERVAL);
    interval.tick().await;
    loop {
        interval.tick().await;
        let result = async {
            let request_header = fetch(&client).await?;
            if request_header != snapshot.load().request_header {
                snapshot.store(Arc::new(Snapshot::build(
                    request_header,
                    certificate.clone(),
                )?));
                tracing::info!("reloaded requestheader client CA");
            }
            anyhow::Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!("cannot refresh requestheader configuration: {error:#}");
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn data(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn parses_allowed_names() -> Result<()> {
        let parsed = parse(data(&[
            ("requestheader-client-ca-file", "PEM"),
            ("requestheader-allowed-names", "[\"front-proxy-client\"]"),
        ]))?;
        assert_eq!(parsed.allowed_names, ["front-proxy-client"]);
        Ok(())
    }

    #[test]
    fn empty_allowed_names_mean_any_ca_signed_client() -> Result<()> {
        for names in [None, Some(""), Some("[]")] {
            let mut pairs = vec![("requestheader-client-ca-file", "PEM")];
            pairs.extend(names.map(|names| ("requestheader-allowed-names", names)));
            assert!(parse(data(&pairs))?.allowed_names.is_empty());
        }
        Ok(())
    }

    #[test]
    fn requires_client_ca() {
        assert!(parse(data(&[("requestheader-allowed-names", "[]")])).is_err());
    }
}
