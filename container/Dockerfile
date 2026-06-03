FROM kalilinux/kali-rolling:latest

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

RUN pip3 install --break-system-packages bandit pip-audit semgrep && \
    npm install -g @anthropic-ai/claude-code@2.1.98 @mariozechner/pi-coding-agent@0.73.0 \
      @openai/codex@0.118.0 eslint eslint-plugin-security

ARG TRIVY_VERSION=0.71.0
ARG GOSEC_VERSION=2.27.1

RUN case "$TARGETARCH" in \
      amd64) osv_arch=amd64; trivy_arch=64bit; gosec_arch=amd64 ;; \
      arm64) osv_arch=arm64; trivy_arch=ARM64; gosec_arch=arm64 ;; \
      *) echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    cd /tmp && \
    wget -q "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_${osv_arch}" -O /usr/local/bin/osv-scanner && \
    wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" -O trivy.tar.gz && \
    tar -xzf trivy.tar.gz trivy && mv trivy /usr/local/bin/trivy && \
    wget -q "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${gosec_arch}.tar.gz" -O gosec.tar.gz && \
    tar -xzf gosec.tar.gz gosec && mv gosec /usr/local/bin/gosec && \
    chmod +x /usr/local/bin/osv-scanner /usr/local/bin/trivy /usr/local/bin/gosec && \
    rm -rf /tmp/*

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer && \
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer2 && \
    curl -L https://github.com/vimeo/psalm/releases/latest/download/psalm.phar -o /usr/local/bin/psalm && \
    curl -L https://github.com/phpstan/phpstan/releases/latest/download/phpstan.phar -o /usr/local/bin/phpstan && \
    chmod +x /usr/local/bin/psalm /usr/local/bin/phpstan

RUN GOBIN=/usr/local/bin go install golang.org/x/vuln/cmd/govulncheck@latest

ENV TZ=Asia/Shanghai
ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
ENV PYTHONUNBUFFERED=1

USER kali
RUN mkdir -p /home/kali/workspace
COPY ./AGENTS.md /home/kali/workspace/AGENTS.md
COPY ./AGENTS.md /home/kali/workspace/CLAUDE.md
WORKDIR /home/kali/workspace
