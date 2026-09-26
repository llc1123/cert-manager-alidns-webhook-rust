# cert-manager AliDNS Rust Webhook

## Project purpose

This repository is an independent Rust implementation of a cert-manager DNS01
webhook solver for Alibaba Cloud DNS (AliDNS). It replaces the unmaintained Go
`cert-manager-alidns-webhook` at the Issuer level (`solverName:
alidns-solver`).

The binary is a Kubernetes aggregated API backend. kube-apiserver
authenticates and authorizes cert-manager, then proxies `ChallengePayload`
requests to the webhook over TLS. The proxied request carries the front-proxy
client certificate. The webhook then presents or cleans up `_acme-challenge`
TXT records through the AliDNS RPC API.

## Repository map

- `src/alidns.rs`: AliDNS RPC with signature V3 (`ACS3-HMAC-SHA256`, the
  current SDK default), paginated TXT lookup, idempotent Present, and
  key-scoped CleanUp. Follow the current API definitions in
  [alibabacloud-typescript-sdk/alidns-20150109](https://github.com/aliyun/alibabacloud-typescript-sdk/tree/master/alidns-20150109).
- `src/challenge.rs`: decoding and responding to cert-manager
  `ChallengePayload` (`v1alpha1`).
- `src/server.rs`: the TLS accept loop, routing, health endpoints, discovery,
  and Kubernetes `Status` errors.
- `src/tls.rs`: serving-certificate hot reload and front-proxy client
  verification (requestheader CA plus allowed names).
- `src/requestheader.rs`: reading and refreshing
  `kube-system/extension-apiserver-authentication`.
- `src/config.rs`: environment configuration.
- `conformance/`: Go tests. They run cert-manager's real webhook client against
  the compiled binary, using a fake kube-apiserver, a stateful AliDNS fake, and
  an opt-in real AliDNS mode.
- `deploy/base`: the Kustomize base (RBAC, PKI, Deployment, Service,
  APIService).
- `deploy/examples`: Issuer, Certificate, and credential Secret templates.
- `.github/workflows/`: CI (formatting, tests, clippy, release build,
  conformance, Kustomize render) and GHCR publishing.

## Development rules

### Preserve the protocol boundary

- Keep the aggregated API shape that cert-manager and kube-aggregator rely on:
  - `GET /apis/<group>/v1alpha1` returns an `APIResourceList` with the solver
    resource, verb `create`, and kind `ChallengePayload`;
  - `POST /apis/<group>/v1alpha1/<solver>` returns HTTP 201 with the request
    echoed and `response.uid`, `response.success`, and, on failure,
    `response.status.message`.
- Do not serve `/apis`. A 404 makes kube-aggregator fall back to legacy
  per-version discovery.
- Provider failures are reported in `response.status.message` with
  `success: false`. They are not HTTP errors, which matches cert-manager's Go
  webhook server.
- Run the conformance suite whenever routes, payload handling, TLS, or AliDNS
  calls change.

### Preserve the authentication boundary

- Every route except `/healthz`, `/livez`, and `/readyz` requires a client
  certificate. It must chain to `requestheader-client-ca-file`, and when
  `requestheader-allowed-names` is non-empty, its CN must be in that list.
- Keep trust material sourced from the cluster ConfigMap. Keep a
  failed refresh on the last good configuration; never fail open.
- Serving-certificate rotation must not need a restart. Keep the previous pair
  whenever the files on disk are unreadable or mismatched.

### Preserve DNS safety

- Present must be idempotent. An existing matching record, or a
  `DomainRecordDuplicate` response, is success.
- CleanUp deletes only TXT records whose RR and value both match exactly.
  Concurrent challenges for the same name must survive.
- Never touch records outside the resolved zone, or records other than TXT.
- Look up records with `SearchMode=COMBINATION` (exact `RRKeyWord` and
  `TypeKeyWord`), page through all results, and still filter exactly on the
  client side.
- Keep the signature V3 unit vector sourced from Alibaba Cloud's official
  `openapi-util` `GetAuthorization`. The conformance fake verifies every
  request with that same implementation.
- Do not add generic retries. cert-manager retries failed challenges and
  converges from observed state.

### Preserve deployment safety

- The webhook stays single-tenant. Credentials come from its own environment,
  and it must not gain cluster-wide Secret read access.
- Keep the private CA chain for the serving certificate, so leaf rotation never
  changes the APIService `caBundle`.
- Do not add a Kustomize `namespace:` transformer to the base. It would move
  the `kube-system` RoleBinding.

### Code quality

- Use stable Rust. Keep `cargo fmt`, `cargo test`, and clippy with warnings
  denied green.
- Do not use `unsafe`, `unwrap`, `expect`, `panic`, or type-error suppressions.
- Keep modules focused. Do not introduce abstractions without a demonstrated
  protocol or domain need.
- Never log AliDNS credentials, or put them in tests, fixtures, commits, or
  documentation.
- Add regression coverage for every change to signing, record matching,
  payload handling, authentication, or certificate reload.

## Required verification

```sh
cargo fmt --all -- --check
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
kubectl kustomize deploy/base > /dev/null

cd conformance
RUST_BINARY="$PWD/../target/release/cert-manager-alidns-webhook" \
  go test -race -shuffle=on -count=1 ./...
```

Use the external AliDNS mode in `conformance/README.md` only with a dedicated
test zone and a RAM AccessKey scoped to it. Never use production credentials in
automated tests.

## Git workflow

These repository rules are mandatory:

1. **Every new feature or behavior change must start on a new branch.** Do not
   develop features directly on `main`.
2. **Every change must be submitted through a pull request.** Do not push
   feature branches directly into `main`.
3. **Pull requests must be squash-merged.** The resulting `main` history should
   contain one purposeful commit per pull request.
4. **Commit messages must be English Conventional Commits**, for example:
   - `feat: page through AliDNS record lookups`
   - `fix: keep the previous serving certificate on mismatch`
   - `test: add CleanUp isolation coverage`
   - `docs: document RAM policy scope`
   - `ci: pin cert-manager checkout`
5. Keep commits focused and reviewable. Do not mix unrelated refactors,
   generated output, credentials, or local build artifacts into a pull request.
6. Before opening a pull request, run the required verification commands and
   report any unavailable external validation explicitly.

For documentation-only changes, use the same branch and pull request workflow;
the rule is about repository history and reviewability, not only executable
code.
