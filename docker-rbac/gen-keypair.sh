#!/usr/bin/env bash
# Generates the RSA keypair MDS uses to sign/verify its bearer tokens.
# Confluent's own RBAC example (confluentinc/examples, security/rbac/scripts/init.sh)
# generates it exactly this way. Run once before `docker compose up`.
set -euo pipefail
cd "$(dirname "$0")/secrets"

# OpenSSL >= 3.0 defaults to PKCS#8; MDS needs the traditional PKCS#1 format.
if openssl genrsa -help 2>&1 | grep -q traditional; then
  openssl genrsa -traditional -out tokenKeypair.pem 2048
else
  openssl genrsa -out tokenKeypair.pem 2048
fi
openssl rsa -in tokenKeypair.pem -outform PEM -pubout -out tokenPublicKey.pem
chmod 644 tokenKeypair.pem tokenPublicKey.pem
echo "wrote $(pwd)/tokenKeypair.pem and tokenPublicKey.pem"
