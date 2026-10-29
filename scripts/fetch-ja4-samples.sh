#!/usr/bin/env bash
# Fetch free JA4 validation samples from the FoxIO ja4 repository.
#
# Usage:
#   scripts/fetch-ja4-samples.sh [--ja4db]
#
# The optional --ja4db flag also downloads the frozen JA4DB export. That file
# is about 32 MB and is not committed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAP_DIR="${ROOT}/datasets/pcap"
PCAP_BASE="https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/pcap"
PCAPS=(
  tls12.pcap
  tls-alpn-h2.pcap
  tls-non-ascii-alpn.pcapng
  sigalg-grease.pcapng
  tls-handshake.pcapng
  tls-sni.pcapng
)

mkdir -p "${PCAP_DIR}"

for name in "${PCAPS[@]}"; do
  echo "fetching ${name}"
  curl -fsSL --retry 3 "${PCAP_BASE}/${name}" -o "${PCAP_DIR}/${name}"
done

echo "samples written to ${PCAP_DIR}"

if [[ "${1:-}" == "--ja4db" ]]; then
  target="${ROOT}/datasets/ja4db-all_records.csv"
  echo "fetching JA4DB frozen export (~32 MB)"
  curl -fsSL --retry 3 \
    "https://raw.githubusercontent.com/Niicolaa/ja4db-export/main/csv/all_records.csv" \
    -o "${target}"
  echo "JA4DB samples written to ${target}"
fi

cat <<EOF

Try:
  ./bin/ja4check -pcap ${PCAP_DIR}/tls-handshake.pcapng
  ./bin/ja4check -pcap ${PCAP_DIR}/tls-non-ascii-alpn.pcapng

With the optional JA4DB export:
  ./bin/ja4check -dataset datasets/ja4db-all_records.csv -lenient -ja4 <fingerprint>
EOF
