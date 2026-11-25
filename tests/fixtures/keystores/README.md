# Fixtures de keystore (PKCS#12 e JKS)

Keystores usados pelos testes do M7, mais os certificados públicos que eles contêm.
Tudo é **descartável**: a cadeia (raiz, intermediária, folha) e as chaves nascem em
`mktemp -d` no `generate.sh`, entram nos keystores protegidos pela senha **pública**
`changeit` e são apagadas ao final. Nenhuma chave privada em texto é commitada.

> `grep -rl "PRIVATE KE[Y]" tests/fixtures/keystores` não deve listar nada.

Os arquivos `chain-with-key.p12` e `with-private-key.jks` **contêm** uma chave privada
(criptografada com `changeit`) de propósito: é o que prova que o leitor devolve só os
certificados. Scanners de segredos podem sinalizá-los; são falsos positivos conhecidos.

## Gerador (fora do projeto)

`./generate.sh` usa `openssl` 3.x (inclusive o provider `legacy` para o RC2) e `keytool`
do JDK. É uma ferramenta geradora fora do projeto, como `../generate.sh`: não roda em CI
nem em `cargo test`, e o código Rust nunca chama nenhum dos dois. Regerar troca todas as
chaves e certificados (portanto os `.der`); só faça isso de propósito.

## Certificados públicos (verdade-terreno)

| Arquivo | O que é |
|---|---|
| `leaf.der` | folha `keystore.example.test` (EC P-256) |
| `int.der` | intermediária |
| `root.der` | raiz |

## PKCS#12 (senha `changeit` salvo indicação)

| Arquivo | Conteúdo | Resultado esperado |
|---|---|---|
| `chain-with-key.p12` | chave da folha + cadeia de 3 (alias `server`); AES-256 / PBKDF2 / HMAC-SHA256 | 3 certificados, nenhum byte da chave |
| `certs-only.p12` | os mesmos 3 certificados, sem chave | 3 certificados |
| `empty-password.p12` | os 3 certificados, senha **vazia** | abre sem senha e com `""` |
| `legacy-rc2.p12` | os 3 certificados, `pbeWithSHA1And40BitRC2-CBC` + MAC SHA-1 (`openssl -legacy`) | `UnsupportedAlgorithm("pbeWithSHA1And40BitRC2-CBC")` |
| `truncated.p12` | os primeiros 100 bytes de `chain-with-key.p12` | `Malformed` |
| `corrupt-mac.p12` | `certs-only.p12` com um byte do HMAC trocado | `WrongPasswordOrCorrupt` |

## JKS (senha `changeit`, via `keytool`)

| Arquivo | Conteúdo | Resultado esperado |
|---|---|---|
| `trusted-certs.jks` | 3 entradas `trustedCertEntry` (`leaf`, `int`, `root`) | 3 certificados, integridade verificada |
| `with-private-key.jks` | 1 `PrivateKeyEntry` (`server`) com a cadeia de 3 | 3 certificados, nenhum byte da chave |
| `truncated.jks` | os primeiros 120 bytes de `trusted-certs.jks` | `Malformed` |
| `bad-count.jks` | `trusted-certs.jks` com a contagem de entradas trocada por `0xFFFFFFFF` | `TooManyEntries`, sem alocar |
