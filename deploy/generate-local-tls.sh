#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: sh deploy/generate-local-tls.sh <control-plane-ip>" >&2
  exit 2
fi

control_plane_ip=$1
if ! printf '%s' "$control_plane_ip" | awk -F. '
  NF != 4 { exit 1 }
  { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1 }
'; then
  echo "IP 格式不正確：$control_plane_ip" >&2
  exit 2
fi

project_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
output_dir=${TLS_OUTPUT_DIR:-$project_root/secrets/tls}
mkdir -p "$output_dir"
umask 077

ca_key="$output_dir/local-ca.key"
ca_cert="$output_dir/local-ca.crt"
server_key="$output_dir/server.key"
server_csr="$output_dir/server.csr"
server_cert="$output_dir/server.crt"
serial_file="$output_dir/local-ca.srl"
extensions="$output_dir/server.ext"

if [ ! -s "$ca_key" ] || [ ! -s "$ca_cert" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$ca_key"
  openssl req -x509 -new -sha256 -key "$ca_key" -days 3650 \
    -subj "/O=Linux AI Local Lab/CN=Linux AI Local Root CA" -out "$ca_cert"
  echo "已建立新的 Local Root CA。請妥善保存 local-ca.key，不要複製到用戶端。"
else
  echo "沿用既有 Local Root CA。"
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$server_key"
openssl req -new -sha256 -key "$server_key" \
  -subj "/O=Linux AI Local Lab/CN=$control_plane_ip" -out "$server_csr"

printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' \
  "subjectAltName=IP:$control_plane_ip,IP:127.0.0.1,DNS:AiAgnet,DNS:linux-ai.local" \
  > "$extensions"

serial_args="-CAcreateserial"
[ -s "$serial_file" ] && serial_args="-CAserial $serial_file"
# shellcheck disable=SC2086
openssl x509 -req -sha256 -in "$server_csr" -CA "$ca_cert" -CAkey "$ca_key" \
  $serial_args -days 825 -extfile "$extensions" -out "$server_cert"

chmod 600 "$ca_key" "$server_key"
chmod 644 "$ca_cert" "$server_cert"
openssl verify -CAfile "$ca_cert" "$server_cert"

echo "TLS 憑證已建立：$output_dir"
echo "只把 local-ca.crt 匯入 Mac；絕對不要匯出或傳送 local-ca.key、server.key。"
echo "啟動指令：docker compose -f compose.yaml -f compose.https.yaml up -d --force-recreate api gateway"
