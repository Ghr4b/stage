# Scanner box. Debian-based (glibc) so the lab's dynamically-linked tlsscan
# binary actually runs - Alpine/musl images (like nicolaka/netshoot) cannot
# exec it. Ships the cross-checking tools the README mentions: nmap, tcpdump,
# openssl, ping/arping, curl, nc.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        gcc \
        iproute2 \
        iputils-arping \
        iputils-ping \
        libc6-dev \
        make \
        netcat-openbsd \
        nmap \
        openssl \
        procps \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
