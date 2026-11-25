# Fixtures de revogação (OCSP e CRL)

Respostas OCSP e CRLs usadas pelos testes do M5, mais a CA, as folhas e os
responders que as assinaram. **Nenhum arquivo aqui contém chave privada**: as
chaves vivem só na memória do gerador e são descartadas.

> `grep -rl "PRIVATE KE[Y]" tests/fixtures/revocation` não deve listar nada.

## Gerador (fora do projeto)

`./generate.sh` roda `generate.py` (Python 3 + pacote `cryptography` >= 42). É uma
ferramenta geradora fora do projeto, como `../generate.sh`: não roda em CI nem em
`cargo test`, e o código Rust nunca chama Python ou OpenSSL. Os artefatos são
commitados. Regerar troca todas as chaves, portanto todos os bytes; só faça isso
de propósito e atualize os testes junto.

Por que Python e não `openssl ca`/`openssl ocsp`: o `openssl ocsp` sempre usa a
hora atual em `thisUpdate`, e o `openssl ca` não produz CRL sem `nextUpdate` nem
CRL delta. O gerador fixa os instantes, o que permite um `FixedClock` estável, e
é **independente** do código sob teste (OpenSSL/`cryptography` contra
`x509-ocsp`/`x509-parser`). A conferência abaixo usa o próprio `openssl`.

## Instantes fixos

| Nome | Valor |
|---|---|
| Validade da CA e das folhas | 2026-01-01 a 2036-01-01 |
| `thisUpdate` / `nextUpdate` (respostas e CRLs boas) | 2026-11-01 / 2026-12-01 |
| `thisUpdate` / `nextUpdate` (vencidas) | 2026-10-01 / 2026-10-08 |
| Revogação de `leaf-revoked` | 2026-10-15, `keyCompromise` |
| **Relógio dos testes** | **2026-11-02T00:00:00Z** (unix `1793577600`) |

Todas as chaves são ECDSA P-256; assinaturas ECDSA com SHA-256. O `CertID` usa
SHA-1, como manda o RFC 6960 (só identificação).

## Certificados

| Arquivo | O que é |
|---|---|
| `ca` | CA autoassinada, serial 1 |
| `leaf-good` | serial `0x1001`; AIA OCSP `http://ocsp.example.test/ocsp`, CA Issuers `http://ca.example.test/ca.der`, CRL DP `http://crl.example.test/ca.crl` |
| `leaf-revoked` | serial `0x1002`, mesmas extensões |
| `leaf-unknown` | serial `0x1003`, mesmas extensões |
| `responder` | responder delegado, assinado pela CA, EKU `OCSPSigning` |
| `responder-noeku` | responder delegado, assinado pela CA, **sem** EKU |
| `ca-no-crlsign` | segunda CA (serial 2) cujo `keyUsage` tem só `keyCertSign` (sem `cRLSign`) |
| `leaf-no-crlsign` | folha `0x3001` emitida por `ca-no-crlsign`, com os mesmos CRL DP/AIA |
| `leaf-forged` | serial `0x1002`, **issuer name = o da `ca`**, mas assinada por outra chave (não foi emitida pela `ca`) |

Cada um existe em `.pem` e `.der`.

## Respostas OCSP (`*.der`)

| Arquivo | Conteúdo | Resultado esperado |
|---|---|---|
| `ocsp-good` | `good` para `leaf-good`, assinada pela CA | `Good` |
| `ocsp-revoked` | `revoked`, `keyCompromise`, 2026-10-15, para `leaf-revoked` | `Revoked` |
| `ocsp-unknown` | `unknown` para `leaf-unknown` | `Unknown` |
| `ocsp-expired` | `good`, `nextUpdate` 2026-10-08 | `Stale` |
| `ocsp-bad-signature` | `ocsp-good` com o último byte da assinatura trocado | `BadSignature` |
| `ocsp-delegated` | `good`, assinada por `responder` (vai embutido em `certs`) | `Good` |
| `ocsp-delegated-no-eku` | `good`, assinada por `responder-noeku` (embutido) | `ResponderNotAuthorized` |
| `ocsp-other-cert` | `good` sobre o serial de `leaf-revoked`; usada contra `leaf-good` (replay) | `CertIdMismatch` |
| `ocsp-try-later` | `OCSPResponse { responseStatus = tryLater }` sem corpo | `Unsuccessful("tryLater")` |
| `ocsp-unauthorized` | `OCSPResponse { responseStatus = unauthorized }` | `Unsuccessful("unauthorized")` |

## CRLs (`*.der`, emitente = `ca`, `CRLNumber` 7)

| Arquivo | Conteúdo | Resultado esperado |
|---|---|---|
| `crl-with-revoked` | lista o serial `0x1002` (`keyCompromise`, 2026-10-15) | `leaf-revoked`: `Revoked`; `leaf-good`: `Good` |
| `crl-without-leaf` | lista só o serial `0x1FFF` | `leaf-revoked`: `Good` |
| `crl-no-next-update` | como `crl-with-revoked`, sem `nextUpdate` (reassinada) | `Unknown` |
| `crl-bad-signature` | `crl-with-revoked` com o último byte da assinatura trocado | `BadSignature` |
| `crl-stale` | `nextUpdate` 2026-10-08 | `Stale` |
| `crl-delta` | extensão crítica `deltaCRLIndicator` | `Unknown` (escopo) |
| `crl-idp-ca-only` | `IssuingDistributionPoint` crítica `onlyContainsCACerts` | `Unknown` (escopo) |
| `crl-idp-matching-dp` | IDP crítica com `distributionPoint` = `http://crl.example.test/ca.crl` (o CRL DP das folhas); lista `0x1002` | `leaf-revoked`: `Revoked` |
| `crl-idp-other-dp` | IDP crítica com `distributionPoint` = `.../other.crl`; **não** lista `0x1002` | `leaf-revoked`: `Unknown` (partição de outra CRL; nunca `Good`) |
| `crl-idp-garbage` | IDP crítica cujo valor não é um `IssuingDistributionPoint` legível (assinada normalmente) | `Unknown` (nunca ignorada) |
| `crl-no-crlsign` | CRL vazia assinada por `ca-no-crlsign` | `Unknown` ("issuer lacks cRLSign") |

## Conferência independente com `openssl` (3.5)

Rode da pasta `tests/fixtures/revocation`:

```bash
AT=$(date -u -d 2026-11-02T00:00:00Z +%s)   # 1793577600
openssl ocsp -respin ocsp-good.der -issuer ca.pem -cert leaf-good.pem -CAfile ca.pem -attime "$AT"
#   -> "Response verify OK" e "leaf-good.pem: good"
openssl ocsp -respin ocsp-revoked.der -issuer ca.pem -cert leaf-revoked.pem -CAfile ca.pem -attime "$AT"
#   -> "revoked", "Reason: keyCompromise", "Revocation Time: Oct 15 2026"
openssl ocsp -respin ocsp-expired.der -issuer ca.pem -cert leaf-good.pem -CAfile ca.pem -attime "$AT"
#   -> "status expired"
openssl ocsp -respin ocsp-bad-signature.der -issuer ca.pem -cert leaf-good.pem -CAfile ca.pem -attime "$AT"
#   -> "signature failure"
openssl ocsp -respin ocsp-delegated-no-eku.der -issuer ca.pem -cert leaf-good.pem -CAfile ca.pem -attime "$AT"
#   -> "missing ocspsigning usage"
openssl crl -inform DER -in crl-with-revoked.der -CAfile ca.pem -verify -noout     # verify OK
openssl crl -inform DER -in crl-bad-signature.der -CAfile ca.pem -verify -noout    # verify failure
openssl crl -inform DER -in crl-no-next-update.der -noout -text | grep "Next Update"  # NONE
openssl crl -inform DER -in crl-delta.der -noout -text | grep Delta                # Delta CRL Indicator: critical
```

Todas estas saídas foram conferidas ao gerar os fixtures (OpenSSL 3.5.5). Para as CRLs novas: `openssl crl -inform DER -in crl-idp-matching-dp.der -noout -text | grep -A2 "Issuing Dist"` mostra `URI:http://crl.example.test/ca.crl`, e `crl-no-crlsign.der` verifica com `-CAfile ca-no-crlsign.pem` (a assinatura vale; o que falta é `cRLSign`).
