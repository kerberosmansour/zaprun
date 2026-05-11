# syntax=docker/dockerfile:1.7

# Build stage for the zaprun Rust CLI. Pinned to a specific upstream Rust
# 1.90 digest so the build is reproducible and supply-chain attestable. The
# workspace's declared MSRV is 1.82, but Cargo.lock pulls in transitive deps
# that require Cargo's stable `edition2024` (>= 1.85) and rustc >= 1.88
# (time-macros 0.2.27, idna 1.2.2, icu 2.2). 1.90 is the smallest stable that
# satisfies the lockfile today; bumping the workspace MSRV is tracked
# separately. The binary is dynamically linked against glibc; the Wolfi
# runtime base also uses glibc (>= the bookworm-slim version), so the
# artifact runs unchanged in the runner stage. Build context MUST be the
# repository root so Cargo.toml, Cargo.lock and crates/ are reachable.
FROM docker.io/library/rust:1.90-slim-bookworm@sha256:64232e656c058f4468e8d024e990acff04f0fd5a5c0a88a574dc37773d7325c9 AS cargo-build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN cargo build -p zaprun --release --locked && \
    strip target/release/zaprun && \
    test -x target/release/zaprun

FROM cgr.dev/chainguard/wolfi-base@sha256:31da6565f35af6401031c1d7aa91dc84ac76c5c48edd17fb90f0ed9e3173c7a9 AS base-runtime

RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache \
      bash \
      ca-certificates \
      curl \
      firefox-docker-selenium-compat \
      fontconfig \
      gnutar \
      gzip \
      openjdk-26-jre \
      py3.13-pyyaml \
      py3.13-setuptools-79 \
      py3.13-six \
      py3.13-zaproxy \
      python-3.13 \
      tini \
      ttf-dejavu && \
    ln -sf /usr/lib/jvm/java-26-openjdk/bin/java /usr/bin/java && \
    ln -sf /usr/lib/jvm/java-26-openjdk/bin/keytool /usr/bin/keytool && \
    ln -sf /usr/bin/python3.13 /usr/bin/python3 && \
    ln -sf /usr/bin/python3.13 /usr/bin/python && \
    rm -rf /var/cache/apk/*

FROM base-runtime AS zap-install

ARG ZAP_VERSION=2.17.0
ARG ZAP_RELEASE_TAG=v2.17.0
ARG ZAP_LINUX_TGZ_SHA256=efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a
ARG ZAP_LINUX_TGZ_URL=https://github.com/zaproxy/zaproxy/releases/download/${ZAP_RELEASE_TAG}/ZAP_${ZAP_VERSION}_Linux.tar.gz
ARG ZAP_NETWORK_ADDON_VERSION=0.27.0
ARG ZAP_NETWORK_ADDON_SHA256=1ee957c473eca42865417115a126927790dbc972771cc86354d0f7f0cc7edbb9
ARG ZAP_NETWORK_ADDON_URL=https://github.com/zaproxy/zap-extensions/releases/download/network-v${ZAP_NETWORK_ADDON_VERSION}/network-beta-${ZAP_NETWORK_ADDON_VERSION}.zap
ARG ZAP_API_SCAN_SHA256=f37e812e26733ea5e5f071ecbe08ed443671280fa1336be29f5c7e4ab3b4a029
ARG ZAP_BASELINE_SHA256=18df1d2275c2cc7113ec4dd061687f8c9d6b9032b2e9d7e561bcd173236eda42
ARG ZAP_FULL_SCAN_SHA256=45896f6d66e48697a20a3a5469943757b2f5ee77487655eaf89a2ec4af4d2217
ARG ZAP_COMMON_SHA256=9554545f10fd2adebecd9a4d1d7248e9bc7ca27dccf44e2c2d5a7449a1225f82
ARG ZAP_API_MINIMAL_POLICY_SHA256=029a8670ff8f78a5a2af027c3667bf25500c6e2bed7996644a35f9e147144520
ARG ZAP_HTTP_RESPONSE_SCRIPT_SHA256=f24c7c209b2a62dab78a072f67ee2248aaa7cb287b1faa85b2001cf9994ea964
ARG ZAP_UNEXPECTED_CONTENT_SCRIPT_SHA256=2be9938cf3070e940dc96f7b6f72149309682f60c8a3411051d3e475c3905956

# Exclude optional or stale add-on archives until their bundled Java dependencies are refreshed upstream.
RUN curl -fsSL "${ZAP_LINUX_TGZ_URL}" -o /tmp/zap-linux.tar.gz && \
    echo "${ZAP_LINUX_TGZ_SHA256}  /tmp/zap-linux.tar.gz" | sha256sum -c - && \
    mkdir -p /opt/zap /usr/local/bin /home/zap/.ZAP/policies /home/zap/.ZAP_D/policies /home/zap/.ZAP_D/scripts/scripts/httpsender && \
    tar -xzf /tmp/zap-linux.tar.gz -C /opt/zap --strip-components=1 && \
    rm -f /tmp/zap-linux.tar.gz && \
    find /opt/zap -type f \( -name "*.bat" -o -name "*.exe" -o -name "*.dll" -o -name "*.dylib" \) -delete && \
    rm -f /opt/zap/plugin/fuzz-*.zap && \
    rm -f /opt/zap/plugin/network-beta-*.zap && \
    curl -fsSL "${ZAP_NETWORK_ADDON_URL}" -o "/opt/zap/plugin/network-beta-${ZAP_NETWORK_ADDON_VERSION}.zap" && \
    echo "${ZAP_NETWORK_ADDON_SHA256}  /opt/zap/plugin/network-beta-${ZAP_NETWORK_ADDON_VERSION}.zap" | sha256sum -c - && \
    chmod +x /opt/zap/zap.sh && \
    curl -fsSL "https://raw.githubusercontent.com/zaproxy/zaproxy/${ZAP_RELEASE_TAG}/docker/zap-api-scan.py" -o /usr/local/bin/zap-api-scan.py && \
    echo "${ZAP_API_SCAN_SHA256}  /usr/local/bin/zap-api-scan.py" | sha256sum -c - && \
    curl -fsSL "https://raw.githubusercontent.com/zaproxy/zaproxy/${ZAP_RELEASE_TAG}/docker/zap-baseline.py" -o /usr/local/bin/zap-baseline.py && \
    echo "${ZAP_BASELINE_SHA256}  /usr/local/bin/zap-baseline.py" | sha256sum -c - && \
    curl -fsSL "https://raw.githubusercontent.com/zaproxy/zaproxy/${ZAP_RELEASE_TAG}/docker/zap-full-scan.py" -o /usr/local/bin/zap-full-scan.py && \
    echo "${ZAP_FULL_SCAN_SHA256}  /usr/local/bin/zap-full-scan.py" | sha256sum -c - && \
    curl -fsSL "https://raw.githubusercontent.com/zaproxy/zaproxy/${ZAP_RELEASE_TAG}/docker/zap_common.py" -o /usr/local/bin/zap_common.py && \
    echo "${ZAP_COMMON_SHA256}  /usr/local/bin/zap_common.py" | sha256sum -c - && \
    curl -fsSL "https://raw.githubusercontent.com/zaproxy/zaproxy/${ZAP_RELEASE_TAG}/docker/policies/API-Minimal.policy" -o /home/zap/.ZAP_D/policies/API-Minimal.policy && \
    echo "${ZAP_API_MINIMAL_POLICY_SHA256}  /home/zap/.ZAP_D/policies/API-Minimal.policy" | sha256sum -c - && \
    cp /home/zap/.ZAP_D/policies/API-Minimal.policy /home/zap/.ZAP/policies/API-Minimal.policy && \
    curl -fsSL "https://raw.githubusercontent.com/zaproxy/zaproxy/${ZAP_RELEASE_TAG}/docker/scripts/scripts/httpsender/Alert_on_HTTP_Response_Code_Errors.js" -o /home/zap/.ZAP_D/scripts/scripts/httpsender/Alert_on_HTTP_Response_Code_Errors.js && \
    echo "${ZAP_HTTP_RESPONSE_SCRIPT_SHA256}  /home/zap/.ZAP_D/scripts/scripts/httpsender/Alert_on_HTTP_Response_Code_Errors.js" | sha256sum -c - && \
    curl -fsSL "https://raw.githubusercontent.com/zaproxy/zaproxy/${ZAP_RELEASE_TAG}/docker/scripts/scripts/httpsender/Alert_on_Unexpected_Content_Types.js" -o /home/zap/.ZAP_D/scripts/scripts/httpsender/Alert_on_Unexpected_Content_Types.js && \
    echo "${ZAP_UNEXPECTED_CONTENT_SCRIPT_SHA256}  /home/zap/.ZAP_D/scripts/scripts/httpsender/Alert_on_Unexpected_Content_Types.js" | sha256sum -c - && \
    chmod 0755 /usr/local/bin/zap-api-scan.py /usr/local/bin/zap-baseline.py /usr/local/bin/zap-full-scan.py && \
    chmod 0644 /usr/local/bin/zap_common.py

FROM zap-install AS runner

ENV ZAP_HOME=/opt/zap \
    JAVA_HOME=/usr/lib/jvm/java-26-openjdk \
    HOME=/home/zap \
    PATH="/opt/zap:${PATH}" \
    _JAVA_OPTIONS="-Xmx4g -Xss2m -XX:+UseG1GC -XX:MaxGCPauseMillis=200" \
    DAST_SPIKE_DOM_XSS_ENABLED=0

RUN addgroup -g 1000 zap 2>/dev/null || true && \
    adduser -D -u 1000 -G zap -h /home/zap zap 2>/dev/null || true && \
    mkdir -p /zap/wrk /zap/scripts/passive /zap/policies /home/zap && \
    ln -sf /opt/zap/zap.sh /zap/zap.sh && \
    ln -sf /opt/zap/zap.sh /zap/zap-x.sh && \
    chown -R 1000:1000 /zap /home/zap /opt/zap

# NB: build context is the repository root, so COPY sources are repo-relative.
COPY --chown=1000:1000 docker/zap/policies/ /zap/policies/
COPY --chown=1000:1000 docker/zap/scripts/ /zap/scripts/passive/
COPY --chown=1000:1000 docker/zap/entrypoint.sh /usr/local/bin/dast-spike-entrypoint
COPY --from=cargo-build --chown=1000:1000 /build/target/release/zaprun /usr/local/bin/zaprun
RUN chmod 0755 /usr/local/bin/dast-spike-entrypoint /usr/local/bin/zaprun

USER 1000:1000
WORKDIR /zap
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/dast-spike-entrypoint"]
