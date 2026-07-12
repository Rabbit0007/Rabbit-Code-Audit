FROM kalilinux/kali-rolling@sha256:82c8e267c5b46031c6671f7dc8a30b240dabdc7d129e07ac9290ec06dac9b93c

ARG TARGETARCH
ARG NODE_VERSION=22.17.0

USER root

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends \
      bash ca-certificates curl fd-find git gitleaks golang-go jq \
      openjdk-21-jre-headless php-cli php-curl php-mbstring php-xml python3 \
      python3-pip python3-venv ripgrep ruby-full sudo unzip universal-ctags wget xz-utils yq && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash kali && \
    echo "kali ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

RUN case "$TARGETARCH" in \
      amd64) node_arch=x64 ;; \
      arm64) node_arch=arm64 ;; \
      *) echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    cd /tmp && \
    wget -q "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz" -O node.tar.xz && \
    tar -xJf node.tar.xz --strip-components=1 -C /usr/local && \
    rm -f node.tar.xz

ARG BANDIT_VERSION=1.9.4
ARG PIP_AUDIT_VERSION=2.10.1
ARG SEMGREP_VERSION=1.168.0
ARG ESLINT_VERSION=10.6.0
ARG ESLINT_SECURITY_VERSION=4.0.1

RUN pip3 install --break-system-packages \
      "bandit==${BANDIT_VERSION}" "pip-audit==${PIP_AUDIT_VERSION}" "semgrep==${SEMGREP_VERSION}" && \
    npm install -g @anthropic-ai/claude-code@2.1.98 @mariozechner/pi-coding-agent@0.73.0 \
      @openai/codex@0.118.0 "eslint@${ESLINT_VERSION}" \
      "eslint-plugin-security@${ESLINT_SECURITY_VERSION}"

ARG TRIVY_VERSION=0.71.0
ARG GOSEC_VERSION=2.27.1
ARG OSV_SCANNER_VERSION=2.4.0

RUN case "$TARGETARCH" in \
      amd64) osv_arch=amd64; trivy_arch=64bit; gosec_arch=amd64 ;; \
      arm64) osv_arch=arm64; trivy_arch=ARM64; gosec_arch=arm64 ;; \
      *) echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    cd /tmp && \
    wget -q "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${osv_arch}" -O /usr/local/bin/osv-scanner && \
    wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" -O trivy.tar.gz && \
    tar -xzf trivy.tar.gz trivy && mv trivy /usr/local/bin/trivy && \
    wget -q "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${gosec_arch}.tar.gz" -O gosec.tar.gz && \
    tar -xzf gosec.tar.gz gosec && mv gosec /usr/local/bin/gosec && \
    chmod +x /usr/local/bin/osv-scanner /usr/local/bin/trivy /usr/local/bin/gosec && \
    rm -rf /tmp/*

ARG PSALM_VERSION=6.16.1
ARG PHPSTAN_VERSION=2.2.5

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer && \
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer2 && \
    curl -L "https://github.com/vimeo/psalm/releases/download/${PSALM_VERSION}/psalm.phar" -o /usr/local/bin/psalm && \
    curl -L "https://github.com/phpstan/phpstan/releases/download/${PHPSTAN_VERSION}/phpstan.phar" -o /usr/local/bin/phpstan && \
    chmod +x /usr/local/bin/psalm /usr/local/bin/phpstan

RUN GOBIN=/usr/local/bin go install golang.org/x/vuln/cmd/govulncheck@v1.6.0

ENV TZ=Asia/Shanghai
ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
ENV PYTHONUNBUFFERED=1

USER kali
RUN mkdir -p /home/kali/workspace
COPY ./AGENTS.md /home/kali/workspace/AGENTS.md
COPY ./AGENTS.md /home/kali/workspace/CLAUDE.md
WORKDIR /home/kali/workspace
