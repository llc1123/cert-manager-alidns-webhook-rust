# cert-manager/AliDNS conformance

This module drives the compiled Rust webhook through cert-manager's own DNS01
webhook client (`pkg/issuer/acme/dns/webhook`). The client is configured the
way the kube-apiserver aggregator reaches the webhook: the APIService CA
bundle, plus a front-proxy client certificate.

No cluster is needed. The suite starts:

- a fake kube-apiserver that serves
  `kube-system/extension-apiserver-authentication` through a generated
  kubeconfig;
- a stateful AliDNS fake. It verifies signature V3 (`ACS3-HMAC-SHA256`) with
  Alibaba Cloud's official `openapi-util` signer, rejects nonce replays,
  implements `SearchMode=COMBINATION` and paging, returns
  `DomainRecordDuplicate`, and supports failure injection;
- the Rust binary, on a dynamically allocated port.

From the Rust checkout root:

```sh
cargo build --release
cd conformance
RUST_BINARY="$PWD/../target/release/cert-manager-alidns-webhook" \
  go test -race -shuffle=on -count=1 ./...
```

The conformance module pins the cert-manager pseudo-version built from commit
`99714653`, which provides the client APIs used by the suite. An unset
`RUST_BINARY` fails the suite instead of skipping it.

## External AliDNS mode

To run the shared scenarios against the real AliDNS API, set all three
variables below. Partial settings are rejected. Records are then verified the
way cert-manager's ACME self-check does it: through the zone's authoritative
nameservers.

```sh
CONFORMANCE_ALIDNS_ACCESS_KEY_ID=LTAI... \
CONFORMANCE_ALIDNS_ACCESS_KEY_SECRET='...' \
CONFORMANCE_ALIDNS_ZONE=example.com \
RUST_BINARY="$PWD/../target/release/cert-manager-alidns-webhook" \
  go test -race -count=1 ./...
```

Optional settings:

- `CONFORMANCE_DNS_SERVER`: recursive resolver, default `223.5.5.5:53`.
- `CONFORMANCE_ALIDNS_ENDPOINT`: API endpoint override.

The suite only creates and deletes `_acme-challenge.*-<nonce>.<zone>` TXT
records. Scenarios that need the fake (pagination, failure injection) are
skipped.
