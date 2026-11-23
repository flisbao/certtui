#!/usr/bin/env bash
# Gera o corpus de "texto sujo" em tests/fixtures/messy/ a partir de chain-3.pem
# (3 certs: leaf, intermediário, raiz). Gerador FORA do projeto: usa openssl em
# dois pontos (`x509 -text` e `genpkey`), a mesma exceção documentada em
# generate.sh. A chave privada descartável de with-private-key.txt é criada em
# mktemp -d, copiada para esse único arquivo e apagada.
#
# O contrato (arquivo, certs esperados após dedupe, notas esperadas) está em
# messy/expected.tsv, mantido à mão junto com este script.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
OUT=messy
mkdir -p "$OUT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- divide chain-3.pem em c1 (leaf), c2 (intermediário), c3 (raiz) ----------
awk -v dir="$TMP" '
  /-----BEGIN CERTIFICATE-----/ { n++ }
  n > 0 { print > (dir "/c" n ".pem") }
' chain-3.pem
for i in 1 2 3; do
  # corpo base64 (sem cabeçalho/rodapé), 64 colunas, e DER binário
  sed '/-----/d' "$TMP/c$i.pem" >"$TMP/c$i.b64"
  base64 -d "$TMP/c$i.b64" >"$TMP/c$i.der"
  # base64 numa linha só, hex plano e hex com dois-pontos (maiúsculo), uma linha por cert
  tr -d '\n' <"$TMP/c$i.b64" >"$TMP/c$i.b64line"
  xxd -p "$TMP/c$i.der" | tr -d '\n' >"$TMP/c$i.hex"
  sed 's/../&:/g; s/:$//' "$TMP/c$i.hex" | tr 'a-f' 'A-F' >"$TMP/c$i.hexcolon"
done
CHAIN=chain-3.pem

# --- pem-indented.txt: PEM indentado (4 espaços), com prosa -------------------
{
  echo "Segue a cadeia que o time de infra colou no wiki:"
  echo
  sed 's/^/    /' "$CHAIN"
  echo
  echo "Qualquer dúvida, falar com a infra."
} >"$OUT/pem-indented.txt"

# --- pem-email-quoted.txt: citação de e-mail "> " ----------------------------
{
  echo "On Mon, 10 Nov 2026 09:12, Alice <alice@example.test> wrote:"
  echo "> Oi Bob, o cert do servidor novo está abaixo."
  echo ">"
  sed 's/^/> /' "$CHAIN"
  echo ">"
  echo "> Valeu!"
  echo
  echo "Recebi, obrigado."
} >"$OUT/pem-email-quoted.txt"

# --- pem-crlf.txt: finais de linha CRLF --------------------------------------
sed 's/$/\r/' "$CHAIN" >"$OUT/pem-crlf.txt"

# --- pem-json-escaped.json: "\n" literal dentro de string JSON ---------------
{
  printf '{"name":"chain","chain":"'
  awk '{ printf "%s\\n", $0 }' "$CHAIN"
  printf '","version":1}\n'
} >"$OUT/pem-json-escaped.json"

# --- pem-one-line.txt: cada PEM inteiro numa linha só ------------------------
{
  echo "# certificados em formato de uma linha"
  for i in 1 2 3; do
    printf -- '-----BEGIN CERTIFICATE----- %s -----END CERTIFICATE-----\n' "$(cat "$TMP/c$i.b64line")"
  done
} >"$OUT/pem-one-line.txt"

# --- openssl-x509-text.txt: `openssl x509 -text` do leaf e do intermediário ---
# no_sigdump: omite o dump hexadecimal da assinatura (bytes que começam com 30:
# seriam candidatos a DER e poluiriam as notas esperadas).
{
  openssl x509 -in "$TMP/c1.pem" -text -certopt no_sigdump
  echo
  openssl x509 -in "$TMP/c2.pem" -text -certopt no_sigdump
} >"$OUT/openssl-x509-text.txt"

# --- s_client-output.txt: layout de `openssl s_client -showcerts` -------------
# Reconstruído a partir de chain-3 (cadeia 0..2 + "Server certificate" repetindo
# o leaf, o que testa a união de duplicados).
{
  echo "CONNECTED(00000003)"
  echo "depth=2 C = BR, O = CertTui Test, CN = CertTui Test Root CA"
  echo "verify error:num=19:self-signed certificate in certificate chain"
  echo "---"
  echo "Certificate chain"
  printf ' 0 s:C = BR, O = CertTui Test, CN = chain.example.test\n   i:C = BR, O = CertTui Test, CN = CertTui Test Intermediate CA\n   a:PKEY: rsaEncryption, 2048 (bit); sigalg: ecdsa-with-SHA256\n'
  cat "$TMP/c1.pem"
  printf ' 1 s:C = BR, O = CertTui Test, CN = CertTui Test Intermediate CA\n   i:C = BR, O = CertTui Test, CN = CertTui Test Root CA\n   a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA256\n'
  cat "$TMP/c2.pem"
  printf ' 2 s:C = BR, O = CertTui Test, CN = CertTui Test Root CA\n   i:C = BR, O = CertTui Test, CN = CertTui Test Root CA\n   a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA256\n'
  cat "$TMP/c3.pem"
  echo "---"
  echo "Server certificate"
  cat "$TMP/c1.pem"
  echo "subject=C = BR, O = CertTui Test, CN = chain.example.test"
  echo "issuer=C = BR, O = CertTui Test, CN = CertTui Test Intermediate CA"
  echo "---"
  echo "SSL handshake has read 2468 bytes and written 392 bytes"
  echo "Verification error: self-signed certificate in certificate chain"
  echo "---"
  echo "DONE"
} >"$OUT/s_client-output.txt"

# --- utf16le-bom.txt: UTF-16 LE com BOM, CRLF (saída do PowerShell) ----------
{
  printf '\xff\xfe'
  sed 's/$/\r/' "$CHAIN" | iconv -f UTF-8 -t UTF-16LE
} >"$OUT/utf16le-bom.txt"

# --- utf8-bom.txt: UTF-8 com BOM ---------------------------------------------
{
  printf '\xef\xbb\xbf'
  cat "$CHAIN"
} >"$OUT/utf8-bom.txt"

# --- k8s-secret.yaml: tls.crt = base64 do PEM; ca.crt = base64 da raiz --------
{
  echo "apiVersion: v1"
  echo "kind: Secret"
  echo "metadata:"
  echo "  name: meu-tls"
  echo "  namespace: default"
  echo "type: kubernetes.io/tls"
  echo "data:"
  printf '  tls.crt: %s\n' "$(base64 -w0 "$CHAIN")"
  printf '  ca.crt: %s\n' "$(base64 -w0 "$TMP/c3.pem")"
} >"$OUT/k8s-secret.yaml"

# --- jwk-x5c.json: x5c = base64 padrão do DER (sem armadura) ------------------
{
  printf '{"keys":[{"kty":"RSA","use":"sig","kid":"certtui-test","x5c":['
  printf '"%s",' "$(cat "$TMP/c1.b64line")"
  printf '"%s",' "$(cat "$TMP/c2.b64line")"
  printf '"%s"' "$(cat "$TMP/c3.b64line")"
  printf ']}]}\n'
} >"$OUT/jwk-x5c.json"

# --- hex-colon.txt: DER em hex com dois-pontos, uma linha por cert ------------
{
  echo "Certificados em hex (dois-pontos):"
  for i in 1 2 3; do
    echo "cert$i: $(cat "$TMP/c$i.hexcolon")"
  done
} >"$OUT/hex-colon.txt"

# --- hex-plain.txt: DER em hex contínuo, uma linha por cert -------------------
{
  echo "Certificados em hex (continuo):"
  for i in 1 2 3; do
    echo "cert$i = $(cat "$TMP/c$i.hex")"
  done
} >"$OUT/hex-plain.txt"

# --- bare-base64-wrapped.txt: base64 do DER sem armadura, 64 colunas ----------
{
  echo "Base64 solto, sem cabecalho PEM:"
  echo
  for i in 1 2 3; do
    cat "$TMP/c$i.b64"
    echo
  done
} >"$OUT/bare-base64-wrapped.txt"

# --- with-private-key.txt: chave DESCARTÁVEL + 2 certs -------------------------
# A chave é gerada agora, só para este teste, e nunca foi usada em nada.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TMP/throwaway.key" 2>/dev/null
{
  echo "Backup misturado (CHAVE DESCARTAVEL gerada so para o teste do CertTui):"
  echo
  cat "$TMP/c1.pem"
  echo
  cat "$TMP/throwaway.key"
  echo
  cat "$TMP/c2.pem"
} >"$OUT/with-private-key.txt"

# --- duplicates.txt: mesmo cert (leaf) em PEM e em hex ------------------------
{
  echo "Mesmo certificado duas vezes:"
  cat "$TMP/c1.pem"
  echo "de novo, em hex: $(cat "$TMP/c1.hex")"
} >"$OUT/duplicates.txt"

# --- no-certs.txt: nada que se pareça com certificado --------------------------
cat >"$OUT/no-certs.txt" <<'TXT'
Este arquivo nao contem nenhum certificado.
Apenas prosa, um token curto (abc123XYZ) e algo como MIAAAA que e curto demais.
Hash curto: deadbeef cafebabe 0123456789abcdef.
Linha vazia a seguir.

Fim.
TXT

# --- truncated.txt: 2 certs completos + 3o PEM sem END (corpo curto) ----------
{
  cat "$TMP/c1.pem"
  cat "$TMP/c2.pem"
  echo "-----BEGIN CERTIFICATE-----"
  sed -n '1,2p' "$TMP/c3.b64"
} >"$OUT/truncated.txt"

# --- garbage-between.txt: lixo textual e binário entre os PEMs -----------------
{
  echo "=== inicio do dump ==="
  cat "$TMP/c1.pem"
  printf '\x00\x01\x02\xff\xfe garbage !!@@## %%%% \x7f\x80\x81\n'
  echo "2026-11-10T09:12:00Z WARN something odd happened"
  cat "$TMP/c2.pem"
  printf '~~~ ### ??? ;;; \xc3\x28 \xa0\xa1\n'
  cat "$TMP/c3.pem"
  echo "=== fim do dump ==="
} >"$OUT/garbage-between.txt"

# --- bundle-mixed.txt: leaf em PEM, intermediário em base64 solto, raiz em hex -
{
  echo "# leaf (PEM)"
  cat "$TMP/c1.pem"
  echo
  echo "# intermediario (base64 solto)"
  cat "$TMP/c2.b64"
  echo
  echo "# raiz (hex com dois-pontos)"
  cat "$TMP/c3.hexcolon"
} >"$OUT/bundle-mixed.txt"

echo "corpus gerado em $(pwd)/$OUT"
