# =============================================================================
# webscan — Full Web Security Scanner Suite
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build Go tools
# -----------------------------------------------------------------------------
FROM docker.io/library/golang:1.25-bookworm AS go-builder

ENV GOPATH=/go
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev gcc \
    && rm -rf /var/lib/apt/lists/*

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest            && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest  && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest          && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest        && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest           && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest               && \
    go install -v github.com/ffuf/ffuf/v2@latest                                 && \
    go install -v github.com/OJ/gobuster/v3@latest

# -----------------------------------------------------------------------------
# Stage 2: Final image
# -----------------------------------------------------------------------------
FROM docker.io/library/debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV ZAP_DIR=/opt/zap
ENV PATH="${PATH}:/opt/zap"

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget git bash jq \
    dnsutils iputils-ping net-tools libpcap-dev procps \
    openssl bsdmainutils \
    ruby ruby-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev \
    build-essential libcurl4-openssl-dev libgmp-dev \
    perl libnet-ssleay-perl libio-socket-ssl-perl liburi-perl libwww-perl \
    libjson-perl libxml-writer-perl \
    python3 python3-pip python3-venv \
    nodejs npm \
    dirb \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/share/wordlists \
    && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt \
        -o /usr/share/wordlists/big.txt

# WhatWeb
RUN git clone --depth=1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && chmod +x /opt/whatweb/whatweb \
    && ln -sf /opt/whatweb/whatweb /usr/local/bin/whatweb

# WPScan
RUN gem install wpscan --no-document \
    && wpscan --update --verbose 2>/dev/null || true

# Optional API token for WPScan vulnerability data (free at wpscan.com)
# Pass at runtime: docker run -e WPSCAN_API_TOKEN=yourtoken ...
ENV WPSCAN_API_TOKEN=""

# sqlmap
RUN git clone --depth=1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /opt/sqlmap/sqlmap.py

# Mozilla HTTP Observatory
RUN npm install -g mdn-http-observatory 2>/dev/null \
    && ln -sf "$(npm root -g)/mdn-http-observatory/bin/mdn-http-observatory-scan.js" \
        /usr/local/bin/observatory 2>/dev/null || true

# droopescan (Drupal / Silverstripe scanner)
RUN pip3 install droopescan --break-system-packages 2>/dev/null || \
    pip3 install droopescan 2>/dev/null || true

# JoomScan (OWASP Joomla scanner)
RUN git clone --depth=1 https://github.com/OWASP/joomscan.git /opt/joomscan \
    && chmod +x /opt/joomscan/joomscan.pl \
    && ln -sf /opt/joomscan/joomscan.pl /usr/local/bin/joomscan

# Nikto
RUN git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# testssl.sh
RUN git clone --depth=1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# OWASP ZAP
RUN ZAP_VERSION=$(curl -sf https://api.github.com/repos/zaproxy/zaproxy/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v') \
    && wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
        -O /tmp/zap.tar.gz \
    && mkdir -p ${ZAP_DIR} \
    && tar -xzf /tmp/zap.tar.gz -C ${ZAP_DIR} --strip-components=1 \
    && rm /tmp/zap.tar.gz \
    && mkdir -p /root/.ZAP/session /root/.ZAP/dirbuster /root/.ZAP/fuzzers /root/.ZAP/plugin

# Cap ZAP heap — overrides ZAP's auto-calculation from available system memory
ENV JAVA_OPTS="-Xmx512m"

# Go binaries
COPY --from=go-builder /go/bin/httpx      /usr/local/bin/httpx
COPY --from=go-builder /go/bin/subfinder  /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/naabu      /usr/local/bin/naabu
COPY --from=go-builder /go/bin/nuclei     /usr/local/bin/nuclei
COPY --from=go-builder /go/bin/katana     /usr/local/bin/katana
COPY --from=go-builder /go/bin/dnsx       /usr/local/bin/dnsx
COPY --from=go-builder /go/bin/ffuf       /usr/local/bin/ffuf
COPY --from=go-builder /go/bin/gobuster   /usr/local/bin/gobuster

# Bake nuclei templates
RUN nuclei -update-templates -silent 2>/dev/null || true

# Entrypoint
COPY img/src/scan.sh /usr/local/bin/scan.sh
RUN chmod +x /usr/local/bin/scan.sh

VOLUME ["/output"]
WORKDIR /output

ENTRYPOINT ["/usr/local/bin/scan.sh"]
CMD ["--help"]
