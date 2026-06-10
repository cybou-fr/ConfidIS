FROM rust:1-bookworm AS builder

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dpkg-dev \
        gnupg \
        jq \
        libssl-dev \
        pkg-config \
        python3 \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Synthetic but valid rehearsal root key. A real production release must replace
# this with the public key from the real authority ceremony/HSM path.
ENV CONFIDIS_GENESIS_ROOT_PUBKEY_HEX=7751e37adf01a7a4831f614ba7e902ce16611b387ac6d418519b9930c428bea3

RUN ./scripts/check-packaging.sh \
    && ./scripts/build-deb.sh \
    && deb="$(ls -t target/confidis_*.deb | head -n 1)" \
    && target/release/confidis authority init-keyset \
        --count 3 \
        --threshold 2 \
        --out-dir /tmp/release-authority \
    && target/release/confidis authority sign-release \
        --artifact "$deb" \
        --authority-set /tmp/release-authority/authority-set.json \
        --privkey /tmp/release-authority/authority-1.key \
        --privkey /tmp/release-authority/authority-2.key \
        --out "$deb.sig.json" \
    && target/release/confidis authority verify-release \
        --artifact "$deb" \
        --signature "$deb.sig.json" \
        --authority-set /tmp/release-authority/authority-set.json \
    && mkdir -p /out \
    && artifact_name="$(basename "$deb")" \
    && cp "$deb" "/out/$artifact_name" \
    && cp "$deb.sig.json" "/out/$artifact_name.sig.json" \
    && cp /tmp/release-authority/authority-set.json /out/authority-set.json \
    && (cd /out && sha256sum "$artifact_name" > "$artifact_name.sha256") \
    && printf '%s\n' "$artifact_name" > /out/artifact-name

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        adduser \
        ca-certificates \
        curl \
        iproute2 \
        jq \
        libssl3 \
        procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/ /tmp/confidis-release/
COPY docker/deb-rehearsal/scripts/deb-container-smoke.sh /usr/local/lib/confidis-deb/deb-container-smoke.sh

RUN deb="/tmp/confidis-release/$(cat /tmp/confidis-release/artifact-name)" \
    && dpkg -i "$deb" \
    && chmod 0755 /usr/local/lib/confidis-deb/deb-container-smoke.sh

ENTRYPOINT ["/usr/local/lib/confidis-deb/deb-container-smoke.sh"]
