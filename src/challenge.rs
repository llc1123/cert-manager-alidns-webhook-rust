//! cert-manager `ChallengePayload` handling (`acme.cert-manager.io` webhook v1alpha1).

use serde::Deserialize;
use serde_json::{Value, json};

use crate::alidns;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest {
    #[serde(default)]
    pub uid: String,
    pub action: Action,
    #[serde(rename = "resolvedFQDN")]
    pub resolved_fqdn: String,
    pub resolved_zone: String,
    pub key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Action {
    Present,
    CleanUp,
}

/// Decode a `ChallengePayload`, returning the raw document for echoing back.
pub fn decode(body: &[u8]) -> Result<(Value, ChallengeRequest), String> {
    let payload: Value =
        serde_json::from_slice(body).map_err(|error| format!("invalid JSON body: {error}"))?;
    let request = payload
        .get("request")
        .filter(|request| !request.is_null())
        .ok_or("payload request field cannot be empty")?;
    let request = ChallengeRequest::deserialize(request)
        .map_err(|error| format!("invalid challenge request: {error}"))?;
    Ok((payload, request))
}

pub async fn solve(
    client: &alidns::Client,
    request: &ChallengeRequest,
) -> Result<(), alidns::Error> {
    let ChallengeRequest {
        resolved_fqdn: fqdn,
        resolved_zone: zone,
        key,
        ..
    } = request;
    match request.action {
        Action::Present => client.present(zone, fqdn, key).await,
        Action::CleanUp => client.cleanup(zone, fqdn, key).await,
    }
}

/// Build the response document the same way cert-manager's Go webhook server
/// does: echo the request and attach `response`.
pub fn respond(
    mut payload: Value,
    group_version: &str,
    request: &ChallengeRequest,
    result: Result<(), String>,
) -> Value {
    let response = match result {
        Ok(()) => json!({ "uid": request.uid, "success": true }),
        Err(message) => json!({
            "uid": request.uid,
            "success": false,
            "status": { "metadata": {}, "status": "Failed", "message": message },
        }),
    };
    if let Some(object) = payload.as_object_mut() {
        object.insert("apiVersion".into(), group_version.into());
        object.insert("kind".into(), "ChallengePayload".into());
        object.insert("response".into(), response);
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"{
        "apiVersion": "acme.example.com/v1alpha1",
        "kind": "ChallengePayload",
        "request": {
            "uid": "u-1",
            "action": "CleanUp",
            "type": "dns-01",
            "dnsName": "example.com",
            "key": "k",
            "resourceNamespace": "default",
            "resolvedFQDN": "_acme-challenge.example.com.",
            "resolvedZone": "example.com.",
            "allowAmbientCredentials": false,
            "config": {}
        }
    }"#;

    #[test]
    fn decodes_cert_manager_request() -> Result<(), String> {
        let (_, request) = decode(BODY.as_bytes())?;
        assert_eq!(request.action, Action::CleanUp);
        assert_eq!(request.resolved_fqdn, "_acme-challenge.example.com.");
        assert_eq!(request.resolved_zone, "example.com.");
        Ok(())
    }

    #[test]
    fn rejects_missing_request_and_unknown_action() {
        assert!(decode(br#"{"kind":"ChallengePayload"}"#).is_err());
        assert!(decode(BODY.replace("CleanUp", "fly").as_bytes()).is_err());
    }

    #[test]
    fn failure_response_carries_status_message() -> Result<(), String> {
        let (payload, request) = decode(BODY.as_bytes())?;
        let response = respond(payload, "g/v1alpha1", &request, Err("boom".into()));
        assert_eq!(response["request"]["uid"], "u-1");
        assert_eq!(response["response"]["success"], false);
        assert_eq!(response["response"]["status"]["message"], "boom");
        Ok(())
    }
}
