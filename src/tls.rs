//! Serving certificate hot reload and front-proxy (requestheader) client authentication.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use anyhow::{Context, Result};
use rustls::RootCertStore;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, crypto::aws_lc_rs};

/// Kubernetes aggregator trust material from
/// `kube-system/extension-apiserver-authentication`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub client_ca_pem: String,
    pub allowed_names: Vec<String>,
}

/// Immutable per-connection TLS state; swapped atomically when trust changes.
pub struct Snapshot {
    pub server_config: Arc<ServerConfig>,
    pub request_header: RequestHeader,
}

impl Snapshot {
    /// Builds the rustls server configuration for `request_header` and `certificate`.
    pub fn build(request_header: RequestHeader, certificate: Arc<ReloadingCert>) -> Result<Self> {
        let provider = Arc::new(aws_lc_rs::default_provider());
        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(request_header.client_ca_pem.as_bytes()) {
            roots
                .add(certificate.context("invalid requestheader client CA PEM")?)
                .context("invalid requestheader client CA certificate")?;
        }
        // Unauthenticated handshakes are allowed so kubelet probes can reach the
        // health endpoints; every API route requires a verified front-proxy client.
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .allow_unauthenticated()
                .build()
                .context("cannot build requestheader client verifier")?;
        let mut server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(certificate);
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            server_config: Arc::new(server_config),
            request_header,
        })
    }

    /// Whether the verified client chain belongs to an allowed front proxy.
    pub fn is_front_proxy(&self, peer_certificates: Option<&[CertificateDer<'_>]>) -> bool {
        let Some(leaf) = peer_certificates.and_then(<[_]>::first) else {
            return false;
        };
        let allowed = &self.request_header.allowed_names;
        allowed.is_empty() || common_name(leaf).is_some_and(|name| allowed.contains(&name))
    }
}

/// The first subject common name of `certificate`, if any.
fn common_name(certificate: &CertificateDer<'_>) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate).ok()?;
    parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok())
        .map(str::to_owned)
}

type Stamp = [(Option<SystemTime>, u64); 2];

/// Serves the certificate on disk, reloading it when either file changes.
///
/// Kubelet swaps projected Secret files atomically, so a changed modification
/// time or size on the next handshake is a reliable rotation signal.
#[derive(Debug)]
pub struct ReloadingCert {
    cert_file: PathBuf,
    key_file: PathBuf,
    current: Mutex<(Stamp, Arc<CertifiedKey>)>,
}

impl ReloadingCert {
    /// Loads the initial certificate pair; fails if it is missing or mismatched.
    pub fn load(cert_file: PathBuf, key_file: PathBuf) -> Result<Self> {
        let stamp = stamp(&cert_file, &key_file);
        let key = load_certified_key(&cert_file, &key_file)?;
        Ok(Self {
            cert_file,
            key_file,
            current: Mutex::new((stamp, Arc::new(key))),
        })
    }

    /// The current pair, reloading it first when the files changed.
    fn current(&self) -> Arc<CertifiedKey> {
        let stamp = stamp(&self.cert_file, &self.key_file);
        let mut current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        if current.0 != stamp {
            match load_certified_key(&self.cert_file, &self.key_file) {
                Ok(key) => {
                    tracing::info!("reloaded serving certificate");
                    *current = (stamp, Arc::new(key));
                }
                // Keep serving the previous pair; the next handshake retries.
                Err(error) => tracing::warn!("cannot reload serving certificate: {error:#}"),
            }
        }
        current.1.clone()
    }
}

impl ResolvesServerCert for ReloadingCert {
    /// Serves the current certificate for every handshake.
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// Modification time and size of both files, used to detect rotation.
fn stamp(cert_file: &Path, key_file: &Path) -> Stamp {
    [cert_file, key_file].map(|path| match fs::metadata(path) {
        Ok(metadata) => (metadata.modified().ok(), metadata.len()),
        Err(_) => (None, 0),
    })
}

/// Reads a PEM chain and key and checks that they match.
fn load_certified_key(cert_file: &Path, key_file: &Path) -> Result<CertifiedKey> {
    let chain = CertificateDer::pem_file_iter(cert_file)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| format!("cannot read certificate {}", cert_file.display()))?;
    anyhow::ensure!(
        !chain.is_empty(),
        "{} contains no certificate",
        cert_file.display()
    );
    let key = PrivateKeyDer::from_pem_file(key_file)
        .with_context(|| format!("cannot read private key {}", key_file.display()))?;
    let provider: &CryptoProvider = &aws_lc_rs::default_provider();
    CertifiedKey::from_der(chain, key, provider).context("certificate and private key do not match")
}
