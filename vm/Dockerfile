FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap netcat-openbsd socat curl wget \
    dnsutils whois \
    hydra john \
    tcpdump \
    vim tmux git \
    python3 python3-pip \
    jq procps \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages --no-cache-dir \
    impacket scapy requests beautifulsoup4 paramiko 2>/dev/null || true

RUN useradd -m -s /bin/bash redteam

RUN printf 'strict_chain\nquiet_mode\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n\n[ProxyList]\nsocks5 127.0.0.1 9050\n' > /etc/proxychains4.conf

WORKDIR /home/redteam
USER redteam
CMD ["/bin/bash"]
