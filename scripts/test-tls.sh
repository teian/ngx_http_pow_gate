#!/usr/bin/env bash
# Ephemeral fixture certificate, trusted only by the isolated test client.
set -euo pipefail
destination="${1:?usage: test-tls.sh output-directory}"
mkdir -p "$destination"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -keyout "$destination/key.pem" -out "$destination/cert.pem" \
  -subj /CN=nginx \
  -addext 'subjectAltName=DNS:nginx,DNS:localhost,IP:127.0.0.1' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,digitalSignature,keyCertSign'
