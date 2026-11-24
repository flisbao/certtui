# Fixtures de certificados

Certificados públicos e um corpus de "texto sujo" usados pelos testes do CertTui.
**Nenhum arquivo aqui contém chave privada**, com uma única exceção deliberada:
`messy/with-private-key.txt`, que carrega uma chave EC **descartável**, gerada só
para testar que blocos PEM de chave privada são pulados e nunca decodificados nem
impressos. Essa chave nunca protegeu nada.

> `grep -rl "PRIVATE KE[Y]" tests/fixtures` deve listar **somente**
> `messy/with-private-key.txt`.

A mesma chave descartável também existe em
`fuzz/corpus/extract_text_certs/with-private-key.txt` (semente do fuzzer).
Scanners de segredos podem sinalizar os dois arquivos; ambos são falsos
positivos conhecidos.

## Regra "zero OpenSSL"

O projeto Rust nunca chama o OpenSSL. Os dois scripts desta pasta
(`generate.sh` e `generate_messy.sh`) são **ferramentas geradoras fora do
projeto**, a única exceção documentada: usam o CLI `openssl` (testado com
OpenSSL 3.5; `-not_before`/`-not_after` em `req -x509` exigem 3.4 ou mais novo).
Os artefatos gerados são commitados. Não rodam em CI nem em `cargo test`.

## Fingerprints gerados uma única vez

Cada `<nome>.fingerprints.txt` tem 3 linhas, saída crua do OpenSSL, geradas **uma
única vez, fora do projeto**, e servem de verdade-terreno para comparar com
`Fingerprints::compute`:

```
sha1 Fingerprint=AB:CD:...
sha256 Fingerprint=AB:CD:...
sha512 Fingerprint=AB:CD:...
```

Comando (por certificado):

```bash
openssl x509 -in <nome>.pem -noout -fingerprint -sha1
openssl x509 -in <nome>.pem -noout -fingerprint -sha256
openssl x509 -in <nome>.pem -noout -fingerprint -sha512
```

Para `chain-3`, o `.der` e os fingerprints se referem ao **primeiro** certificado
(o leaf). Regenerar os fixtures muda os certificados (chaves novas) e portanto
os fingerprints; só faça isso de propósito e atualize os testes junto.

## Certificados (`generate.sh`)

Para cada nome existem `<nome>.pem`, `<nome>.der` e `<nome>.fingerprints.txt`.
As chaves privadas ficam em `mktemp -d` e são apagadas ao final do script.

| Nome | O que é | Como é gerado |
|---|---|---|
| `rsa2048-leaf` | leaf RSA 2048 autoassinado, SAN DNS | `openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -sha256 ...` |
| `ec-p256-leaf` | leaf ECDSA P-256 autoassinado | `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 ...` |
| `san-multi` | SAN com DNS (incl. curinga), IPv4, IPv6, e-mail e URI | `-addext "subjectAltName=DNS:...,IP:...,email:...,URI:..."` |
| `expired` | validade 2020-01-01 a 2020-02-01 (sempre expirado) | `-not_before 20200101000000Z -not_after 20200201000000Z` |
| `chain-3` | leaf RSA 2048 + intermediário EC + raiz EC (nessa ordem em `chain-3.pem`) | `req -x509` para a raiz; `req -new` + `x509 -req -CA ...` para os demais |
| `chain-3.p7b` | PKCS#7 DER com os 3 certs, sem CRL | `openssl crl2pkcs7 -nocrl -certfile chain-3.pem -outform DER` |
| `public-leaf-with-sct` | leaf **real** de `example.com` (lista de SCTs embutida, 2 SCTs v1 com log id de 32 bytes) | veja abaixo |

Nenhum leaf destas fixtures está sem SAN; o teste de "cert sem SAN" usa o intermediário de `chain-3` (2º bloco de `chain-3.pem`).

### `public-leaf-with-sct` (real, não sintético)

É o certificado leaf público de `example.com`, capturado uma vez com:

```bash
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null
```

e extraído o primeiro certificado impresso. É dado público (sem chave privada).
O certificado tem validade curta e **expira**; testes não devem depender de ele
estar válido (use `FixedClock`). O `generate.sh` só recaptura se o arquivo não
existir (precisa de rede), para não trocar o certificado commitado.

## Corpus de texto sujo (`generate_messy.sh`)

`messy/` é construído a partir de `chain-3.pem` (leaf, intermediário, raiz) com
`sed`, `awk`, `printf`, `base64`, `iconv` e `xxd`. Usa `openssl` apenas em
`x509 -text` e para gerar a chave descartável de `with-private-key.txt`.

`messy/expected.tsv` (sem cabeçalho, separado por TAB) tem as colunas
`arquivo`, `certs_esperados` (após remover duplicados por SHA-256) e
`notes_esperadas` (nomes dos tipos de nota separados por vírgula, ou `-`).

| Arquivo | Conteúdo | Certs | Notas |
|---|---|---|---|
| `pem-indented.txt` | PEM indentado 4 espaços, com prosa | 3 | - |
| `pem-email-quoted.txt` | prefixo `> ` e prosa de e-mail | 3 | - |
| `pem-crlf.txt` | finais de linha CRLF | 3 | - |
| `pem-json-escaped.json` | `\n` literal dentro de string JSON | 3 | - |
| `pem-one-line.txt` | cada PEM inteiro numa linha | 3 | - |
| `openssl-x509-text.txt` | `openssl x509 -text -certopt no_sigdump` do leaf e do intermediário | 2 | - |
| `s_client-output.txt` | layout de `openssl s_client -showcerts` (cadeia 0..2 + "Server certificate" repetindo o leaf); **reconstruído** a partir de `chain-3`, não é captura de rede | 3 | - |
| `utf16le-bom.txt` | UTF-16 LE com BOM e CRLF | 3 | - |
| `utf8-bom.txt` | UTF-8 com BOM | 3 | - |
| `k8s-secret.yaml` | `tls.crt` = base64 do PEM (3 certs) e `ca.crt` = base64 da raiz | 3 | - |
| `jwk-x5c.json` | `x5c` com base64 padrão do DER | 3 | - |
| `hex-colon.txt` | DER em hex `30:82:...`, uma linha por cert | 3 | - |
| `hex-plain.txt` | DER em hex contínuo `3082...`, uma linha por cert | 3 | - |
| `bare-base64-wrapped.txt` | base64 do DER sem armadura, 64 colunas | 3 | - |
| `with-private-key.txt` | 2 certs + 1 chave privada descartável (PKCS#8) | 2 | `PrivateKeyBlocksIgnored` |
| `duplicates.txt` | o mesmo leaf em PEM e em hex | 1 | - |
| `no-certs.txt` | só prosa | 0 | - |
| `truncated.txt` | 2 certs + um PEM sem `END` (corpo curto, abaixo do mínimo de base64 solto) | 2 | `UnterminatedPem` |
| `garbage-between.txt` | lixo textual/binário entre os PEMs | 3 | - |
| `bundle-mixed.txt` | leaf em PEM, intermediário em base64 solto, raiz em hex | 3 | - |

Os tipos de nota usados nesta tabela fazem parte do conjunto
`UnterminatedPem`, `LabelMismatch`, `InvalidBase64`, `NotDerSequence`,
`LengthMismatch`, `TooLarge`, `UnsupportedLabel`, `NestingTooDeep` e
`PrivateKeyBlocksIgnored`. O corpus atual só exercita os dois indicados acima;
os demais ficam para testes unitários do `TextScanner`.

Decisão de projeto: `openssl-x509-text.txt` omite o dump hexadecimal da
assinatura (`no_sigdump`), cujos bytes começam com `30:` e seriam candidatos a DER
hex, o que tornaria as notas esperadas dependentes de detalhes do scanner.

## Regenerar

```bash
bash tests/fixtures/generate.sh && bash tests/fixtures/generate_messy.sh
grep -rl "PRIVATE KE[Y]" tests/fixtures   # somente messy/with-private-key.txt
```
