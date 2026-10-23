#!/bin/sh
# Generates the TLS certs the lab uses:
#   certs/modern/   - a valid self-signed cert with SANs covering the hosts
#                     that mount it (dmz-web-modern 10.20.0.11, fin-app
#                     10.30.10.11). Also baked into the dmz-web-legacy image.
#   certs/badcert/  - a deliberately EXPIRED, wrong-hostname cert
#                     (used by dmz-web-badcert).
#   certs/weakdh/   - a deliberately WEAK setup: 1024-bit RSA key + 1024-bit
#                     DHE params (used by dmz-web-weakdh to trip
#                     CERT-WEAK-KEY and WEAK-DH/Logjam).
#
# Run this once, before `containerlab deploy` and before build-images.sh.

set -e
BASE="$(cd "$(dirname "$0")" && pwd)/configs/certs"
mkdir -p "$BASE/modern" "$BASE/badcert" "$BASE/weakdh"

# --- valid cert: SANs cover the hosts that use it ------------------------
# (dmz-web-modern 10.20.0.11 and fin-app 10.30.10.11)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$BASE/modern/key.pem" -out "$BASE/modern/cert.pem" \
  -days 365 -subj "/CN=internal.lab" \
  -addext "subjectAltName=DNS:dmz-web-modern.internal,IP:10.20.0.11,IP:10.30.10.11"

# --- deliberately expired + wrong-hostname cert ---------------------------
# -not_before/-not_after need OpenSSL 3.0+. If your openssl errors out on
# these flags, fall back to: generate normally with `-days 1`, then just
# leave the lab running a day or two before you scan it, or wrap this
# command with `faketime "2020-01-01"` to backdate generation instead.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$BASE/badcert/key.pem" -out "$BASE/badcert/cert.pem" \
  -subj "/CN=wrong-hostname.example" \
  -not_before 20200101000000Z -not_after 20210101000000Z

# --- deliberately weak cert + DHE params ----------------------------------
# 1024-bit RSA key (CERT-WEAK-KEY) and 1024-bit DHE prime (WEAK-DH/Logjam).
openssl req -x509 -newkey rsa:1024 -nodes \
  -keyout "$BASE/weakdh/key.pem" -out "$BASE/weakdh/cert.pem" \
  -days 365 -subj "/CN=weak-dh.internal"
openssl dhparam -out "$BASE/weakdh/dhparam.pem" 1024

echo "certs written to $BASE"