//! Minimal AliDNS OpenAPI client (RPC style, signature version 1.0).

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha1::Sha1;
use time::OffsetDateTime;

const API_VERSION: &str = "2015-01-09";
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
    endpoint: String,
    credentials: Credentials,
}

impl Client {
    pub fn new(endpoint: &str, credentials: Credentials) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            http,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
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
            let params = [
                ("DomainName", domain),
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
        let nonce = uuid::Uuid::new_v4().to_string();
        let query = signed_query(
            &self.credentials,
            action,
            params,
            &timestamp(OffsetDateTime::now_utc()),
            &nonce,
        )?;
        let transport = |source| Error::Transport { action, source };
        let response = self
            .http
            .get(format!("{}/?{query}", self.endpoint))
            .send()
            .await
            .map_err(transport)?;
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

fn signed_query(
    credentials: &Credentials,
    action: &str,
    params: &[(&str, &str)],
    timestamp: &str,
    nonce: &str,
) -> Result<String, hmac::digest::InvalidLength> {
    let mut all = BTreeMap::from([
        ("AccessKeyId", credentials.access_key_id.as_str()),
        ("Action", action),
        ("Format", "JSON"),
        ("SignatureMethod", "HMAC-SHA1"),
        ("SignatureNonce", nonce),
        ("SignatureVersion", "1.0"),
        ("Timestamp", timestamp),
        ("Version", API_VERSION),
    ]);
    all.extend(params.iter().copied());
    let canonical = canonical_query(&all);
    let signature = sign(&credentials.access_key_secret, &string_to_sign(&canonical))?;
    Ok(format!(
        "{canonical}&Signature={}",
        percent_encode(&signature)
    ))
}

fn canonical_query(params: &BTreeMap<&str, &str>) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn string_to_sign(canonical_query: &str) -> String {
    format!("GET&%2F&{}", percent_encode(canonical_query))
}

fn sign(secret: &str, string_to_sign: &str) -> Result<String, hmac::digest::InvalidLength> {
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(format!("{secret}&").as_bytes())?;
    mac.update(string_to_sign.as_bytes());
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
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

    /// Worked example from the AliDNS "request signature" documentation.
    #[test]
    fn signs_documented_example() -> Result<(), hmac::digest::InvalidLength> {
        let params = BTreeMap::from([
            ("AccessKeyId", "testid"),
            ("Action", "DescribeDomainRecords"),
            ("DomainName", "example.com"),
            ("Format", "XML"),
            ("SignatureMethod", "HMAC-SHA1"),
            ("SignatureNonce", "f59ed6a9-83fc-473b-9cc6-99c95df3856e"),
            ("SignatureVersion", "1.0"),
            ("Timestamp", "2016-03-24T16:41:54Z"),
            ("Version", "2015-01-09"),
        ]);
        let string_to_sign = string_to_sign(&canonical_query(&params));
        assert_eq!(
            string_to_sign,
            "GET&%2F&AccessKeyId%3Dtestid%26Action%3DDescribeDomainRecords%26DomainName%3Dexample.com%26Format%3DXML%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3Df59ed6a9-83fc-473b-9cc6-99c95df3856e%26SignatureVersion%3D1.0%26Timestamp%3D2016-03-24T16%253A41%253A54Z%26Version%3D2015-01-09"
        );
        assert_eq!(
            sign("testsecret", &string_to_sign)?,
            "uRpHwaSEt3J+6KQD//svCh/x+pI="
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
