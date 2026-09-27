use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::alidns::Credentials;

#[derive(Debug, Clone)]
pub struct Config {
    pub group_name: String,
    pub solver_name: String,
    pub listen_addr: SocketAddr,
    pub tls_cert_file: PathBuf,
    pub tls_key_file: PathBuf,
    pub alidns_endpoint: String,
    pub credentials: Credentials,
}

impl Config {
    /// Reads the configuration from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Builds the configuration from `get`; empty values count as unset.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let value = |key: &str| get(key).filter(|value| !value.is_empty());
        let required = |key: &str| value(key).with_context(|| format!("{key} must be set"));
        let or = |key: &str, default: &str| value(key).unwrap_or_else(|| default.to_owned());

        let group_name = required("GROUP_NAME")?;
        let solver_name = or("SOLVER_NAME", "alidns-solver");
        for (key, name) in [("GROUP_NAME", &group_name), ("SOLVER_NAME", &solver_name)] {
            if name.contains('/') {
                bail!("{key} must not contain '/'");
            }
        }
        let listen_addr = or("LISTEN_ADDR", "0.0.0.0:8443");
        Ok(Self {
            group_name,
            solver_name,
            listen_addr: listen_addr
                .parse()
                .with_context(|| format!("LISTEN_ADDR {listen_addr:?} is not a socket address"))?,
            tls_cert_file: or("TLS_CERT_FILE", "/tls/tls.crt").into(),
            tls_key_file: or("TLS_KEY_FILE", "/tls/tls.key").into(),
            alidns_endpoint: or("ALIDNS_ENDPOINT", "https://alidns.aliyuncs.com"),
            credentials: Credentials {
                access_key_id: required("ALIBABA_CLOUD_ACCESS_KEY_ID")?,
                access_key_secret: required("ALIBABA_CLOUD_ACCESS_KEY_SECRET")?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        move |key| map.get(key).cloned()
    }

    const MINIMAL: &[(&str, &str)] = &[
        ("GROUP_NAME", "acme.example.com"),
        ("ALIBABA_CLOUD_ACCESS_KEY_ID", "id"),
        ("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "secret"),
    ];

    #[test]
    fn applies_defaults() -> Result<()> {
        let config = Config::from_lookup(lookup(MINIMAL))?;
        assert_eq!(config.solver_name, "alidns-solver");
        assert_eq!(config.listen_addr, "0.0.0.0:8443".parse()?);
        assert_eq!(config.tls_cert_file, PathBuf::from("/tls/tls.crt"));
        assert_eq!(config.alidns_endpoint, "https://alidns.aliyuncs.com");
        Ok(())
    }

    #[test]
    fn rejects_missing_or_empty_required_values() {
        for missing in [
            "GROUP_NAME",
            "ALIBABA_CLOUD_ACCESS_KEY_ID",
            "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
        ] {
            let pairs: Vec<_> = MINIMAL
                .iter()
                .map(|&(key, value)| (key, if key == missing { "" } else { value }))
                .collect();
            let error = Config::from_lookup(lookup(&pairs)).err();
            assert!(
                error.is_some_and(|error| error.to_string().contains(missing)),
                "{missing}"
            );
        }
    }

    #[test]
    fn rejects_path_separators_in_api_names() {
        let mut pairs = MINIMAL.to_vec();
        pairs.push(("SOLVER_NAME", "a/b"));
        assert!(Config::from_lookup(lookup(&pairs)).is_err());
    }
}
