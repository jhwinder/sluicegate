#!/bin/sh
# Creates a self-signed Mission Control server certificate and private key with OpenSSL (1.1.1 or later).
# Usage: new-selfsigned-certificate.sh <dns-name> [extra-dns-name-or-ip ...]
# Environment: OUTPUT_DIR (default: current directory), DAYS (default: 365)
set -eu

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <dns-name> [extra-dns-name-or-ip ...]" >&2
    exit 2
fi

primary="$1"
shift
output_dir="${OUTPUT_DIR:-.}"
days="${DAYS:-365}"

san="DNS:${primary}"
for name in "$@"; do
    case "$name" in
        *[!0-9.]* | "") san="${san},DNS:${name}" ;;
        *) san="${san},IP:${name}" ;;
    esac
done

mkdir -p "$output_dir"
umask 077
certificate="${output_dir}/sluicegate-server.pem"
key="${output_dir}/sluicegate-server.key"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days "$days" \
    -subj "/CN=${primary}" \
    -addext "subjectAltName=${san}" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "$key" -out "$certificate"
chmod 0644 "$certificate"

echo "Certificate: $certificate"
echo "Private key: $key (keep on the SluiceGate server only)"
openssl x509 -in "$certificate" -noout -fingerprint -sha256 -enddate
