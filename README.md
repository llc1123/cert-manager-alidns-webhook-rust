# cert-manager AliDNS Rust Webhook

A Rust implementation of a [cert-manager DNS01 webhook
solver](https://cert-manager.io/docs/configuration/acme/dns01/webhook/) for
Alibaba Cloud DNS (AliDNS). It is a drop-in replacement for the unmaintained
Go `cert-manager-alidns-webhook` at the Issuer level (`solverName:
alidns-solver`). It is deployed with plain Kustomize manifests.

## How it works

```text
cert-manager ── POST /apis/<group>/v1alpha1/alidns-solver ──▶ kube-apiserver
                                                                 │ RBAC check, aggregation proxy
                                                                 ▼  (front-proxy client certificate)
                                                 Rust webhook (APIService backend)
                                                                 │ RPC signature v1
                                                                 ▼
                                                              AliDNS API
```

- **Present** creates the `_acme-challenge` TXT record. It is idempotent: an
  existing record, or a lost `DomainRecordDuplicate` race, counts as success.
- **CleanUp** deletes only records whose value equals the challenge key, so
  concurrent validations for the same name keep working. Lookups page through
  every result.
- **Authentication** mirrors the Kubernetes aggregation layer. API routes
  require a client certificate that chains to `requestheader-client-ca-file`
  and whose CN is in `requestheader-allowed-names`. Both values come from
  `kube-system/extension-apiserver-authentication` and are re-read every 60s.
  `/healthz`, `/livez` and `/readyz` need no client certificate.
- **Serving certificate** rotation is picked up on the next TLS handshake. No
  restart is needed.
- **Credentials** come from the webhook's own environment (single tenant).
  Issuers carry no secret references, so the webhook needs no cluster-wide
  Secret read access.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GROUP_NAME` | required | API group registered by the APIService |
| `SOLVER_NAME` | `alidns-solver` | resource name used as `solverName` |
| `ALIBABA_CLOUD_ACCESS_KEY_ID` | required | RAM AccessKey ID |
| `ALIBABA_CLOUD_ACCESS_KEY_SECRET` | required | RAM AccessKey secret |
| `LISTEN_ADDR` | `0.0.0.0:8443` | HTTPS listen address |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | `/tls/tls.crt` / `/tls/tls.key` | serving certificate |
| `ALIDNS_ENDPOINT` | `https://alidns.aliyuncs.com` | AliDNS API endpoint |
| `RUST_LOG` | `info` | log filter |

Minimal RAM policy (replace `example.com` with the hosted zones):

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "alidns:DescribeDomainRecords",
        "alidns:AddDomainRecord",
        "alidns:DeleteDomainRecord"
      ],
      "Resource": "acs:alidns:*:*:domain/example.com"
    }
  ]
}
```

## Deployment (GitOps)

`deploy/base` is a Kustomize base for a cluster where cert-manager runs in the
`cert-manager` namespace with the `cert-manager` service account. It contains:

- the webhook ServiceAccount;
- a RoleBinding to read the aggregator CA;
- the `domain-solver` ClusterRole for cert-manager;
- a private CA and the serving Certificate;
- the Deployment, Service and APIService.

1. Provide the `alidns-credentials` Secret, using SOPS, ExternalSecrets or
   similar. [`deploy/examples/credentials-secret.yaml`](deploy/examples/credentials-secret.yaml)
   shows its shape.
2. Point Argo CD or Flux at an overlay that references `deploy/base` and pins
   the image:

   ```yaml
   apiVersion: kustomize.config.k8s.io/v1beta1
   kind: Kustomization
   resources:
     - https://github.com/llc1123/cert-manager-alidns-webhook-rust//deploy/base?ref=<commit>
   images:
     - name: ghcr.io/llc1123/cert-manager-alidns-webhook-rust
       newTag: sha-<commit>
   ```

3. Reference the solver from an Issuer or ClusterIssuer, as in
   [`deploy/examples/clusterissuer.yaml`](deploy/examples/clusterissuer.yaml).

The group name `alidns.acme.local` is internal to the cluster. To change it,
patch the APIService (name and `spec.group`), the `domain-solver` ClusterRole,
and `GROUP_NAME`. Do not add a `namespace:` transformer to an overlay: it would
also move the RoleBinding out of `kube-system`.

## Verification

```sh
cargo fmt --all -- --check
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
cd conformance
RUST_BINARY="$PWD/../target/release/cert-manager-alidns-webhook" \
  go test -race -shuffle=on -count=1 ./...
```

The conformance suite drives the compiled binary through cert-manager's own
webhook client. It needs no Kubernetes cluster; see
[`conformance/README.md`](conformance/README.md).
