//! Minimal AliDNS OpenAPI client: RPC style with signature V3
//! (`ACS3-HMAC-SHA256`), the default of the current Alibaba Cloud SDKs.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

use anyhow::Context;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Url;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const API_VERSION: &str = "2015-01-09";
const ALGORITHM: &str = "ACS3-HMAC-SHA256";
const PAGE_SIZE: u64 = 500;
const DUPLICATE_RECORD: &str = "DomainRecordDuplicate";

#[derive(Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub access_key_secret: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("access_key_secret", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("AliDNS {action} request failed: {source}")]
    Transport {
        action: &'static str,
        #[source]
        source: reqwest::Error,
    },
    #[error("AliDNS {action} returned {code}: {message} (RequestId {request_id})")]
    Api {
        action: &'static str,
        code: String,
        message: String,
        request_id: String,
    },
    #[error("AliDNS {action} returned an undecodable HTTP {status} response: {source}")]
    Decode {
        action: &'static str,
        status: u16,
        #[source]
        source: serde_json::Error,
    },
    #[error("cannot sign AliDNS request: {0}")]
    Signing(#[from] hmac::digest::InvalidLength),
    #[error("record {fqdn} is not inside zone {zone}")]
    OutsideZone { fqdn: String, zone: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Record {
    #[serde(rename = "RecordId")]
    pub id: String,
    #[serde(rename = "RR")]
    pub rr: String,
    #[serde(rename = "Type")]
    pub kind: String,
    #[serde(rename = "Value")]
    pub value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DescribeDomainRecords {
    total_count: u64,
    domain_records: RecordList,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RecordList {
    #[serde(default)]
    record: Vec<Record>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ApiError {
    code: String,
    message: String,
    #[serde(default)]
    request_id: String,
}

#[derive(Deserialize)]
struct Ignored {}

pub struct Client {
    http: reqwest::Client,
    endpoint: Url,
    host: String,
    credentials: Credentials,
}

impl Client {
    pub fn new(endpoint: &str, credentials: Credentials) -> anyhow::Result<Self> {
        let mut endpoint = Url::parse(endpoint)
            .with_context(|| format!("invalid AliDNS endpoint {endpoint:?}"))?;
        endpoint.set_path("/");
        let host = endpoint
            .host_str()
            .with_context(|| format!("AliDNS endpoint {endpoint} has no host"))?;
        // Must equal the Host header reqwest sends: the port only when non-default.
        let host = match endpoint.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            http,
            endpoint,
            host,
            credentials,
        })
    }

    /// Ensure a TXT record `fqdn` with `value` exists. Repeated calls are no-ops.
    pub async fn present(&self, zone: &str, fqdn: &str, value: &str) -> Result<(), Error> {
        let domain = unfqdn(zone);
        let rr = record_name(fqdn, domain)?;
        if self
            .txt_records(domain, &rr)
            .await?
            .iter()
            .any(|record| record.value == value)
        {
            return Ok(());
        }
        let params = [
            ("DomainName", domain),
            ("RR", rr.as_str()),
            ("Type", "TXT"),
            ("Value", value),
        ];
        match self.call::<Ignored>("AddDomainRecord", &params).await {
            Err(Error::Api { code, .. }) if code == DUPLICATE_RECORD => Ok(()),
            result => result.map(|_| ()),
        }
    }

    /// Delete every TXT record `fqdn` whose value is exactly `value`.
    pub async fn cleanup(&self, zone: &str, fqdn: &str, value: &str) -> Result<(), Error> {
        let domain = unfqdn(zone);
        let rr = record_name(fqdn, domain)?;
        for record in self.txt_records(domain, &rr).await? {
            if record.value == value {
                self.call::<Ignored>("DeleteDomainRecord", &[("RecordId", record.id.as_str())])
                    .await?;
            }
        }
        Ok(())
    }

    async fn txt_records(&self, domain: &str, rr: &str) -> Result<Vec<Record>, Error> {
        let mut matching = Vec::new();
        // The page count is fixed by the first response so a moving TotalCount
        // cannot extend the scan; a short page is always the last one.
        let mut last_page = 1;
        for page in 1_u64.. {
            let page_number = page.to_string();
            let page_size = PAGE_SIZE.to_string();
            // COMBINATION matches RRKeyWord and TypeKeyWord exactly.
            let params = [
                ("DomainName", domain),
                ("SearchMode", "COMBINATION"),
                ("RRKeyWord", rr),
                ("TypeKeyWord", "TXT"),
                ("PageNumber", page_number.as_str()),
                ("PageSize", page_size.as_str()),
            ];
            let response: DescribeDomainRecords =
                self.call("DescribeDomainRecords", &params).await?;
            if page == 1 {
                last_page = response.total_count.div_ceil(PAGE_SIZE);
            }
            let fetched = response.domain_records.record.len() as u64;
            matching.extend(
                response
                    .domain_records
                    .record
                    .into_iter()
                    .filter(|record| record.rr == rr && record.kind == "TXT"),
            );
            if fetched < PAGE_SIZE || page >= last_page {
                break;
            }
        }
        Ok(matching)
    }

    async fn call<T: DeserializeOwned>(
        &self,
        action: &'static str,
        params: &[(&str, &str)],
    ) -> Result<T, Error> {
        let query = canonical_query(params);
        let headers = BTreeMap::from([
            ("host", self.host.clone()),
            ("x-acs-action", action.to_owned()),
            ("x-acs-content-sha256", hex_sha256(b"")),
            ("x-acs-date", timestamp(OffsetDateTime::now_utc())),
            (
                "x-acs-signature-nonce",
                uuid::Uuid::new_v4().simple().to_string(),
            ),
            ("x-acs-version", API_VERSION.to_owned()),
        ]);
        let authorization = authorization(&self.credentials, &query, &headers)?;
        let mut url = self.endpoint.clone();
        url.set_query(Some(&query));
        let transport = |source| Error::Transport { action, source };
        let mut request = self
            .http
            .post(url)
            .header("authorization", authorization)
            .header("accept", "application/json");
        for (name, value) in &headers {
            request = request.header(*name, value);
        }
        let response = request.send().await.map_err(transport)?;
        let status = response.status();
        let body = response.bytes().await.map_err(transport)?;
        let decode = |source| Error::Decode {
            action,
            status: status.as_u16(),
            source,
        };
        if status.is_success() {
            return serde_json::from_slice(&body).map_err(decode);
        }
        let error: ApiError = serde_json::from_slice(&body).map_err(decode)?;
        Err(Error::Api {
            action,
            code: error.code,
            message: error.message,
            request_id: error.request_id,
        })
    }
}

/// Relative record name of `fqdn` inside `domain` ("@" for the apex).
pub fn record_name(fqdn: &str, domain: &str) -> Result<String, Error> {
    let name = unfqdn(fqdn);
    let domain = unfqdn(domain);
    if name.eq_ignore_ascii_case(domain) {
        return Ok("@".to_owned());
    }
    let outside = || Error::OutsideZone {
        fqdn: fqdn.to_owned(),
        zone: domain.to_owned(),
    };
    let split = name
        .len()
        .checked_sub(domain.len() + 1)
        .filter(|&at| name.is_char_boundary(at))
        .ok_or_else(outside)?;
    let (rr, suffix) = name.split_at(split);
    if suffix.len() == domain.len() + 1
        && suffix.starts_with('.')
        && suffix[1..].eq_ignore_ascii_case(domain)
        && !rr.is_empty()
    {
        Ok(rr.to_owned())
    } else {
        Err(outside())
    }
}

fn unfqdn(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

fn timestamp(now: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Sorted, RFC 3986-encoded query string; it is both sent and signed.
fn canonical_query(params: &[(&str, &str)]) -> String {
    let sorted: BTreeMap<&str, &str> = params.iter().copied().collect();
    sorted
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `Authorization` header for a body-less `POST /` (signature V3). `headers`
/// must hold exactly the lowercase headers to sign, including
/// `x-acs-content-sha256`.
fn authorization(
    credentials: &Credentials,
    canonical_query: &str,
    headers: &BTreeMap<&str, String>,
) -> Result<String, hmac::digest::InvalidLength> {
    let canonical_headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let signed_headers = headers.keys().copied().collect::<Vec<_>>().join(";");
    let payload_hash = headers
        .get("x-acs-content-sha256")
        .map_or("", String::as_str);
    let canonical_request = format!(
        "POST\n/\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let string_to_sign = format!("{ALGORITHM}\n{}", hex_sha256(canonical_request.as_bytes()));
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(credentials.access_key_secret.as_bytes())?;
    mac.update(string_to_sign.as_bytes());
    Ok(format!(
        "{ALGORITHM} Credential={},SignedHeaders={signed_headers},Signature={}",
        credentials.access_key_id,
        hex(&mac.finalize().into_bytes())
    ))
}

fn hex_sha256(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// RFC 3986 percent-encoding as required by the Alibaba Cloud RPC signature.
fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vector produced by Alibaba Cloud's official
    /// `github.com/alibabacloud-go/openapi-util` `GetAuthorization`.
    #[test]
    fn signs_like_official_sdk() -> Result<(), hmac::digest::InvalidLength> {
        let credentials = Credentials {
            access_key_id: "YourAccessKeyId".into(),
            access_key_secret: "YourAccessKeySecret".into(),
        };
        let query = canonical_query(&[
            ("Value", "k/+=é"),
            ("DomainName", "example.com"),
            ("RR", "_acme-challenge.a b*~"),
            ("Type", "TXT"),
        ]);
        assert_eq!(
            query,
            "DomainName=example.com&RR=_acme-challenge.a%20b%2A~&Type=TXT&Value=k%2F%2B%3D%C3%A9"
        );
        let headers = BTreeMap::from([
            ("host", "alidns.aliyuncs.com".to_owned()),
            ("x-acs-action", "AddDomainRecord".to_owned()),
            ("x-acs-content-sha256", hex_sha256(b"")),
            ("x-acs-date", "2026-09-27T01:02:03Z".to_owned()),
            (
                "x-acs-signature-nonce",
                "3156853299f313e23d1673dc12e1703d".to_owned(),
            ),
            ("x-acs-version", "2015-01-09".to_owned()),
        ]);
        assert_eq!(
            headers["x-acs-content-sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            authorization(&credentials, &query, &headers)?,
            "ACS3-HMAC-SHA256 Credential=YourAccessKeyId,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version,Signature=98648f18f798a6d0a3879e7f236ea65df4917667858b849e1927a43d3f81fcb0"
        );
        Ok(())
    }

    #[test]
    fn percent_encodes_reserved_characters() {
        assert_eq!(percent_encode("a b*c~d/é+="), "a%20b%2Ac~d%2F%C3%A9%2B%3D");
    }

    #[test]
    fn formats_utc_timestamp() -> Result<(), time::error::ComponentRange> {
        let at = OffsetDateTime::from_unix_timestamp(1_458_837_714)?;
        assert_eq!(timestamp(at), "2016-03-24T16:41:54Z");
        Ok(())
    }

    #[test]
    fn extracts_record_names() -> Result<(), Error> {
        assert_eq!(
            record_name("_acme-challenge.example.com.", "example.com")?,
            "_acme-challenge"
        );
        assert_eq!(
            record_name("_acme-challenge.a.b.example.com.", "example.com.")?,
            "_acme-challenge.a.b"
        );
        assert_eq!(
            record_name("_acme-challenge.EXAMPLE.com.", "example.com")?,
            "_acme-challenge"
        );
        assert_eq!(record_name("example.com.", "example.com")?, "@");
        Ok(())
    }

    #[test]
    fn rejects_names_outside_zone() {
        for fqdn in ["_acme-challenge.badexample.com.", "com.", "other.org."] {
            assert!(
                matches!(
                    record_name(fqdn, "example.com"),
                    Err(Error::OutsideZone { .. })
                ),
                "{fqdn}"
            );
        }
    }

    #[test]
    fn debug_redacts_secret() {
        let credentials = Credentials {
            access_key_id: "id".into(),
            access_key_secret: "secret-value".into(),
        };
        assert!(!format!("{credentials:?}").contains("secret-value"));
    }
}
