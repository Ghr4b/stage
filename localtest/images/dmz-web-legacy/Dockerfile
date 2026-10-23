# Debian 9 (stretch) is EOL - its default apt mirrors are dead, so we
# point at the archive. We need an old OS/OpenSSL pairing here because
# current OpenSSL builds have compiled SSLv3 support out entirely; this
# is genuinely the more fragile part of the whole lab (see README) -
# verify with `openssl s_client -connect ... -ssl3` after building, and
# expect to possibly need a different base image/tag if SSLv3 doesn't
# come up. TLS 1.0/1.1 are far more reliably reproducible than SSLv3.
FROM debian:9

RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g' /etc/apt/sources.list \
    && sed -i '/stretch-updates/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends nginx openssl \
    && rm -rf /var/lib/apt/lists/*

COPY nginx.conf /etc/nginx/nginx.conf
COPY certs/ /etc/nginx/certs/

EXPOSE 443
CMD ["nginx", "-g", "daemon off;"]