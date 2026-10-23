#!/bin/sh
# Builds the custom images the lab needs. Every other host uses a stock
# image configured via bind-mounts and exec commands instead of a custom
# build.
#
# Builds:
#   tls-lab/dmz-web-legacy   - Debian 9 + nginx with SSLv3/TLS1.0/1.1 + weak ciphers
#   tls-lab/fin-db-pgsql     - PostgreSQL with TLS enabled (correct cert ownership)
#   tls-lab/scanner          - Debian-based scanner box with nmap/tcpdump/openssl
#
# Run configs/gen-certs.sh BEFORE this script - it generates the certs that
# get copied into the build contexts below.

set -e
cd "$(dirname "$0")"

# --- dmz-web-legacy -------------------------------------------------------
mkdir -p images/dmz-web-legacy/certs
if [ ! -f configs/certs/modern/cert.pem ]; then
  echo "ERROR: configs/certs/modern/cert.pem missing. Run configs/gen-certs.sh first." >&2
  exit 1
fi
cp configs/certs/modern/cert.pem configs/certs/modern/key.pem images/dmz-web-legacy/certs/
docker build -t tls-lab/dmz-web-legacy:latest images/dmz-web-legacy/

# --- fin-db-pgsql ---------------------------------------------------------
mkdir -p images/fin-db-pgsql/certs
cp configs/certs/modern/cert.pem configs/certs/modern/key.pem images/fin-db-pgsql/certs/
docker build -t tls-lab/fin-db-pgsql:latest images/fin-db-pgsql/

# --- scanner --------------------------------------------------------------
docker build -t tls-lab/scanner:latest images/scanner/

echo "built tls-lab/dmz-web-legacy, tls-lab/fin-db-pgsql, tls-lab/scanner:latest"