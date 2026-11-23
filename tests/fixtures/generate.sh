#!/usr/bin/env bash
# Gera os fixtures públicos de certificados em tests/fixtures/.
#
# ATENÇÃO: este script é uma FERRAMENTA GERADORA fora do projeto. Ele usa o
# binário `openssl` e é a única exceção à regra "zero OpenSSL" do CertTui. O
# código Rust do projeto nunca chama o openssl. Os artefatos gerados são
# commitados; os fingerprints (*.fingerprints.txt) foram gerados UMA ÚNICA VEZ
# e servem de verdade-terreno para os testes de `Fingerprints::compute`.
#
# Todas as chaves privadas ficam em um diretório temporário (mktemp -d) e são
# apagadas ao final. Nenhuma chave privada é commitada.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

SUBJ_BASE="/C=BR/O=CertTui Test"
EC_OPTS=(-newkey ec -pkeyopt ec_paramgen_curve:P-256)
RSA_OPTS=(-newkey rsa:2048)

# Grava <nome>.pem, <nome>.der e <nome>.fingerprints.txt a partir de um PEM
# contendo o certificado (o primeiro certificado do arquivo é o usado).
emit() {
  local name="$1" src="$2"
  openssl x509 -in "$src" -outform PEM -out "$name.pem"
  openssl x509 -in "$src" -outform DER -out "$name.der"
  {
    openssl x509 -in "$name.pem" -noout -fingerprint -sha1
    openssl x509 -in "$name.pem" -noout -fingerprint -sha256
    openssl x509 -in "$name.pem" -noout -fingerprint -sha512
  } >"$name.fingerprints.txt"
}

# --- rsa2048-leaf: leaf RSA 2048 autoassinado --------------------------------
openssl req -x509 "${RSA_OPTS[@]}" -nodes -keyout "$TMP/rsa.key" -out "$TMP/rsa.pem" \
  -days 3650 -sha256 -subj "$SUBJ_BASE/CN=rsa2048.example.test" \
  -addext "subjectAltName=DNS:rsa2048.example.test" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"
emit rsa2048-leaf "$TMP/rsa.pem"

# --- ec-p256-leaf: leaf ECDSA P-256 autoassinado -----------------------------
openssl req -x509 "${EC_OPTS[@]}" -nodes -keyout "$TMP/ec.key" -out "$TMP/ec.pem" \
  -days 3650 -sha256 -subj "$SUBJ_BASE/CN=ec-p256.example.test" \
  -addext "subjectAltName=DNS:ec-p256.example.test" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"
emit ec-p256-leaf "$TMP/ec.pem"

# --- san-multi: SAN com DNS + IP + e-mail + URI ------------------------------
openssl req -x509 "${EC_OPTS[@]}" -nodes -keyout "$TMP/san.key" -out "$TMP/san.pem" \
  -days 3650 -sha256 -subj "$SUBJ_BASE/CN=san-multi.example.test" \
  -addext "subjectAltName=DNS:san-multi.example.test,DNS:*.example.test,IP:192.0.2.10,IP:2001:db8::10,email:admin@example.test,URI:https://example.test/path"
emit san-multi "$TMP/san.pem"

# --- expired: validade 2020-01-01 .. 2020-02-01 (já expirado) ----------------
openssl req -x509 "${EC_OPTS[@]}" -nodes -keyout "$TMP/exp.key" -out "$TMP/exp.pem" \
  -sha256 -subj "$SUBJ_BASE/CN=expired.example.test" \
  -not_before 20200101000000Z -not_after 20200201000000Z \
  -addext "subjectAltName=DNS:expired.example.test"
emit expired "$TMP/exp.pem"

# --- chain-3: leaf + intermediário + raiz ------------------------------------
openssl req -x509 "${EC_OPTS[@]}" -nodes -keyout "$TMP/root.key" -out "$TMP/root.pem" \
  -days 7300 -sha256 -subj "$SUBJ_BASE/CN=CertTui Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new "${EC_OPTS[@]}" -nodes -keyout "$TMP/int.key" -out "$TMP/int.csr" \
  -sha256 -subj "$SUBJ_BASE/CN=CertTui Test Intermediate CA"
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' >"$TMP/int.ext"
openssl x509 -req -in "$TMP/int.csr" -CA "$TMP/root.pem" -CAkey "$TMP/root.key" \
  -CAcreateserial -CAserial "$TMP/ca.srl" -days 3650 -sha256 -extfile "$TMP/int.ext" -out "$TMP/int.pem"

openssl req -new "${RSA_OPTS[@]}" -nodes -keyout "$TMP/leaf.key" -out "$TMP/leaf.csr" \
  -sha256 -subj "$SUBJ_BASE/CN=chain.example.test"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:chain.example.test\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' >"$TMP/leaf.ext"
openssl x509 -req -in "$TMP/leaf.csr" -CA "$TMP/int.pem" -CAkey "$TMP/int.key" \
  -CAcreateserial -CAserial "$TMP/ca.srl" -days 1825 -sha256 -extfile "$TMP/leaf.ext" -out "$TMP/leaf.pem"

# chain-3.pem = leaf, intermediário, raiz (nessa ordem).
# chain-3.der e chain-3.fingerprints.txt referem-se ao PRIMEIRO cert (leaf).
cat "$TMP/leaf.pem" "$TMP/int.pem" "$TMP/root.pem" >"$TMP/chain.pem"
emit chain-3 "$TMP/leaf.pem"
cp "$TMP/chain.pem" chain-3.pem
openssl crl2pkcs7 -nocrl -certfile chain-3.pem -outform DER -out chain-3.p7b

# --- public-leaf-with-sct: leaf REAL de site público -------------------------
# Capturado uma única vez com `openssl s_client` (precisa de rede). Só roda se o
# fixture ainda não existir, para não substituir o cert já commitado.
if [ ! -f public-leaf-with-sct.pem ]; then
  openssl s_client -connect example.com:443 -servername example.com -showcerts \
    </dev/null >"$TMP/sclient.txt" 2>/dev/null
  # primeiro certificado impresso = leaf do servidor
  awk '/-----BEGIN CERTIFICATE-----/{f=1} f{print} /-----END CERTIFICATE-----/{exit}' \
    "$TMP/sclient.txt" >"$TMP/public.pem"
  emit public-leaf-with-sct "$TMP/public.pem"
fi

echo "fixtures gerados em $(pwd)"
