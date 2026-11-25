#!/usr/bin/env bash
# Gera os fixtures de keystore (PKCS#12 e JKS) desta pasta.
#
# FERRAMENTA GERADORA fora do projeto: usa `openssl` 3.x e `keytool` (JDK). O
# código Rust do projeto nunca chama nenhum dos dois. Os artefatos são
# commitados. Toda chave privada é DESCARTÁVEL: nasce em mktemp -d, entra nos
# keystores (criptografada com a senha `changeit`) e é apagada ao final. O
# repositório guarda só certificados públicos e keystores protegidos por essa
# senha pública; nenhum arquivo em PEM de chave privada é commitado.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASS=changeit
SUBJ="/C=BR/O=CertTui Test"
EC=(-newkey ec -pkeyopt ec_paramgen_curve:P-256)

# --- cadeia descartável: raiz -> intermediária -> folha ----------------------
openssl req -x509 "${EC[@]}" -nodes -keyout "$TMP/root.key" -out "$TMP/root.pem" \
  -days 3650 -sha256 -subj "$SUBJ/CN=Keystore Test Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

issue() { # nome subject extensões... ; emitido por $ISSUER ($TMP/<issuer>.pem/.key)
  local name="$1" subject="$2"; shift 2
  openssl req -new "${EC[@]}" -nodes -keyout "$TMP/$name.key" -out "$TMP/$name.csr" -subj "$subject"
  printf '%s\n' "$@" >"$TMP/$name.ext"
  openssl x509 -req -in "$TMP/$name.csr" -CA "$TMP/$ISSUER.pem" -CAkey "$TMP/$ISSUER.key" \
    -CAcreateserial -out "$TMP/$name.pem" -days 3650 -sha256 -extfile "$TMP/$name.ext"
}
ISSUER=root issue int "$SUBJ/CN=Keystore Test Intermediate" \
  "basicConstraints=critical,CA:TRUE" "keyUsage=critical,keyCertSign,cRLSign"
ISSUER=int issue leaf "$SUBJ/CN=keystore.example.test" \
  "basicConstraints=CA:FALSE" "subjectAltName=DNS:keystore.example.test" \
  "keyUsage=critical,digitalSignature"

# Certificados públicos, usados pelos testes como verdade-terreno.
for c in leaf int root; do openssl x509 -in "$TMP/$c.pem" -outform DER -out "$c.der"; done
cat "$TMP/int.pem" "$TMP/root.pem" >"$TMP/rest.pem"
cat "$TMP/leaf.pem" "$TMP/rest.pem" >"$TMP/all.pem"

# --- PKCS#12 -----------------------------------------------------------------
p12() { # saída, opções do openssl...
  local out="$1"; shift
  openssl pkcs12 -export "$@" -out "$out"
}
p12 chain-with-key.p12 -inkey "$TMP/leaf.key" -in "$TMP/leaf.pem" -certfile "$TMP/rest.pem" \
  -name server -passout "pass:$PASS"
p12 certs-only.p12 -nokeys -in "$TMP/all.pem" -passout "pass:$PASS"
# Sem MAC: nada autentica o conteúdo (`-nomac`).
p12 no-mac.p12 -nomac -nokeys -in "$TMP/all.pem" -passout "pass:$PASS"
p12 empty-password.p12 -nokeys -in "$TMP/all.pem" -passout "pass:"
# Cifra legada (RC2-40 + 3DES, MAC SHA-1): exige o provider `legacy` do OpenSSL 3.
p12 legacy-rc2.p12 -legacy -nokeys -in "$TMP/all.pem" -passout "pass:$PASS" \
  -certpbe PBE-SHA1-RC2-40 -macalg sha1
head -c 100 chain-with-key.p12 >truncated.p12
python3 - <<'PY'
# corrupt-mac.p12: copia de certs-only.p12 com um byte do HMAC trocado.
data = bytearray(open("certs-only.p12", "rb").read())
i = data.rfind(b"\x04\x20")  # OCTET STRING de 32 bytes: o digest do MAC (SHA-256)
assert i > 0, "digest do MAC não encontrado"
data[i + 2] ^= 0x01
open("corrupt-mac.p12", "wb").write(data)
PY

# --- JKS (keytool) -----------------------------------------------------------
rm -f trusted-certs.jks with-private-key.jks
for c in leaf int root; do
  keytool -importcert -noprompt -alias "$c" -file "$TMP/$c.pem" \
    -keystore trusted-certs.jks -storetype JKS -storepass "$PASS" 2>/dev/null
done
keytool -importkeystore -noprompt -srckeystore chain-with-key.p12 -srcstoretype PKCS12 \
  -srcstorepass "$PASS" -destkeystore with-private-key.jks -deststoretype JKS \
  -deststorepass "$PASS" 2>/dev/null
head -c 120 trusted-certs.jks >truncated.jks
cp trusted-certs.jks bad-count.jks
printf '\xff\xff\xff\xff' | dd of=bad-count.jks bs=1 seek=8 conv=notrunc 2>/dev/null



# --- PKCS#12 hostis: custo de derivação de chave (só para os testes de limite) ------
# Nenhum contém chave nem certificado útil. `kdf-scrypt.p12` (190 bytes, escrito à mão em
# DER) pede scrypt N=2^20, r=8: ~1 GiB de memória se algum leitor o obedecesse.
# `kdf-many-pbkdf2.p12` é um .p12 real do OpenSSL (AES-256, PBKDF2, 1 000 000 de iterações,
# senha vazia) com o EncryptedData repetido 10 vezes e SEM MAC (sem MAC nada barra a
# derivação): ~5 s de CPU num leitor sem teto.
openssl pkcs12 -export -nokeys -in "$TMP/all.pem" -iter 1000000 -passout "pass:" -out "$TMP/kdf-one.p12"
KDF_ONE="$TMP/kdf-one.p12" python3 - <<'PY'
import os

def enc(tag, body):
    n = len(body)
    if n < 128:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body

def header(data, at):
    tag, first = data[at], data[at + 1]
    at += 2
    if first & 0x80:
        count = first & 0x7F
        first = int.from_bytes(data[at:at + count], "big")
        at += count
    return tag, first, at

def integer(value):
    return enc(0x02, value.to_bytes((value.bit_length() + 8) // 8, "big"))

DATA = bytes.fromhex("06092a864886f70d010701")

# --- scrypt, à mão ---
def oid(h):
    return bytes.fromhex(h)

scrypt_oid = oid("06092b06010401da47040b")
aes256 = oid("060960864801650304012a")
scrypt_params = enc(0x30, scrypt_oid + enc(0x30, enc(0x04, b"S" * 16) + integer(1 << 20) + integer(8) + integer(1)))
pbes2 = enc(0x30, oid("06092a864886f70d01050d") + enc(0x30, scrypt_params + enc(0x30, aes256 + enc(0x04, b"\x00" * 16))))
eci = enc(0x30, DATA + pbes2 + enc(0x80, b"\x11" * 32))
safe = enc(0x30, oid("06092a864886f70d010706") + enc(0xA0, enc(0x30, integer(0) + eci)))
auth = enc(0x30, safe)
outer = enc(0x30, DATA + enc(0xA0, enc(0x04, auth)))
open("kdf-scrypt.p12", "wb").write(enc(0x30, bytes.fromhex("020103") + outer))

# --- PBKDF2 real, repetido ---
data = open(os.environ["KDF_ONE"], "rb").read()
_, _, at = header(data, 0)                 # PFX
_, size, nxt = header(data, at)            # version
at = nxt + size
_, _, at = header(data, at)                # authSafe ContentInfo
_, size, nxt = header(data, at)            # OID data
at = nxt + size
_, _, at = header(data, at)                # [0]
_, size, at = header(data, at)             # OCTET STRING
authsafe = data[at:at + size]
_, size, at = header(authsafe, 0)          # AuthenticatedSafe SEQUENCE
safes = authsafe[at:at + size]
tag, size, at = header(safes, 0)           # first ContentInfo (the encrypted certs)
first = safes[: at + size]
many = enc(0x30, first * 10)
outer = enc(0x30, DATA + enc(0xA0, enc(0x04, many)))
open("kdf-many-pbkdf2.p12", "wb").write(enc(0x30, bytes.fromhex("020103") + outer))
PY
