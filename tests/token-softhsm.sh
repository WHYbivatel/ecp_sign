#!/bin/sh
# Runs tests/token-softhsm.mjs in a disposable Debian container with SoftHSM2, OpenSC, PyKCS11 and OpenSSL,
# so nothing is installed on the machine. The repository is mounted read-only.
set -eu
cd "$(dirname "$0")/.."
exec docker run --rm --network bridge -v "$PWD:/repo:ro" -w /repo node:22-slim sh -c '
  apt-get update -qq >/dev/null &&
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends softhsm2 opensc python3-pykcs11 openssl >/dev/null &&
  node tests/token-softhsm.mjs'
