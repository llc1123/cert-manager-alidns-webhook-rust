FROM rust:1-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /src/target/release/cert-manager-alidns-webhook /usr/local/bin/cert-manager-alidns-webhook
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/cert-manager-alidns-webhook"]
