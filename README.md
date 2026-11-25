# certtui

Inspetor de certificados X.509 e cadeias TLS para o terminal: um TUI interativo
e um modo sem interface (`inspect`, `check`, `batch`, `export`) para scripts e CI.

O `certtui` extrai, mostra, valida e exporta certificados de domínios, arquivos,
keystores e de **qualquer texto** que contenha certificados (e-mail, log, saída de
`openssl s_client`, YAML de um Secret do Kubernetes...). É Rust puro, sem OpenSSL,
com limites de memória, tamanho e tempo em toda entrada.

## Instalação

| Como | Comando |
|---|---|
| Homebrew (macOS e Linux) | `brew install flisbao/tap/certtui` |
| Shell (Linux e macOS) | `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/flisbao/certtui/releases/latest/download/certtui-installer.sh \| sh` |
| PowerShell (Windows) | `powershell -ExecutionPolicy Bypass -c "irm https://github.com/flisbao/certtui/releases/latest/download/certtui-installer.ps1 \| iex"` |
| Cargo | `cargo install certtui --locked` (Rust 1.97 ou mais novo) |
| Binários | [GitHub Releases](https://github.com/flisbao/certtui/releases): `.tar.xz` (Linux e macOS) e `.zip` (Windows), cada um com seu `.sha256`, mais `sha256.sum` |

Plataformas dos binários: Linux x86_64 e aarch64 (musl, estáticos), macOS x86_64
e aarch64 e Windows x86_64.

> **Os binários Linux (musl) são compilados sem o clipboard nativo.** Neles a
> cópia funciona só por **OSC 52** (veja [Clipboard](#clipboard)). Isto vale
> também para o Homebrew no Linux, que instala o mesmo binário musl. Para ter o
> clipboard nativo no Linux, instale com `cargo install certtui --locked` (a
> feature `native-clipboard` vem ligada por padrão). Nos binários musl,
> `ui.clipboard` com `native` é erro de configuração (exit 2).

## Uso rápido

Sem argumentos o `certtui` abre o TUI na Home; com um alvo, já abre inspecionando
o alvo (as opções vão antes do alvo: `certtui --sni www.exemplo.com example.com`):

```sh
certtui
certtui example.com
```

Os comandos abaixo não precisam de TTY. Os blocos deste README que usam só os
certificados de `tests/fixtures` são executados pelo teste
`crates/certtui/tests/readme_examples.rs`.

### Inspecionar um domínio, arquivo ou diretório

```sh
certtui inspect example.com
certtui inspect example.com:8443 --json
certtui inspect https://example.com/qualquer/caminho
certtui inspect --sni www.example.com --connect-to 192.0.2.10 example.com
```

Aceita `host`, `host:porta`, `https://host[:porta]/caminho`, IPv4 e `[IPv6]:porta`.
Para arquivos: PEM, DER, PKCS#7 (`.p7b`/`.p7c`, só certificados), PKCS#12
(`.p12`/`.pfx`) e JKS. O formato é detectado pelo **conteúdo**, nunca pela
extensão. Um diretório é varrido sem recursão (`--recursive` vai até a
profundidade 3; links simbólicos não são seguidos).

<!-- test -->
<!-- expect: CN=chain.example.test -->
<!-- expect: SHA-256: 42:3A:5E:B8 -->
```sh
certtui inspect tests/fixtures/chain-3.pem
```

Para imprimir só um campo, sem decoração (bom para `| pbcopy` ou `| xclip`), use
`--field` (`subject`, `issuer`, `serial`, `not_before`, `not_after`, `sans`,
`fingerprint.sha1`, `fingerprint.sha256`, `fingerprint.sha512`, `pem`) com
`--index N` para escolher o certificado da cadeia (padrão 0, o leaf):

<!-- test -->
<!-- expect: DNS:san-multi.example.test -->
<!-- expect: IP:192.0.2.10 -->
```sh
certtui inspect tests/fixtures/san-multi.pem --field sans
```

### Texto sujo e stdin

Um arquivo ou o stdin (`-`) pode conter *qualquer* texto: todos os certificados
encontrados são inspecionados como se fossem um bundle. Funciona com e-mails,
logs, saída de `openssl s_client`, `openssl x509 -text` e `keytool -list -rfc`,
JSON, YAML, XML, Secrets do Kubernetes e UTF-16 do PowerShell.

```sh
pbpaste | certtui inspect -
```

<!-- test -->
<!-- expect: Origin: stdin #0 -->
<!-- expect: CN=chain.example.test -->
```sh
cat tests/fixtures/messy/s_client-output.txt | certtui inspect - --text
```

Chaves privadas encontradas no texto são ignoradas: nunca são decodificadas,
mostradas, exportadas nem registradas em log.

### `check` em CI

`certtui check` valida um ou mais alvos (confiança, hostname, apresentação e
qualidade, validade e revogação) e termina com um exit code, para quebrar o
pipeline:

```sh
certtui check example.com api.example.com:8443 --fail-on warning
certtui check example.com --warn-days 45 --critical-days 14 --json
```

| Exit | Significado |
|---|---|
| 0 | Sucesso, sem achados com severidade igual ou maior que `--fail-on` (padrão `error`) |
| 1 | Há achados com severidade igual ou maior que `--fail-on` |
| 2 | Erro de uso (argumentos, configuração inválida) |
| 3 | Falha de I/O ou de rede em **todos** os alvos (inclui entrada sem nenhum certificado) |
| 4 | Erro interno (bug) |

`--fail-on` é `error` por padrão (`warning` faz os avisos também falharem);
`--warn-days` é 30 e `--critical-days` é 7. Um certificado vencido gera um
achado de severidade `error`, então `check` termina com exit 1:

<!-- test -->
<!-- expect: error EXPIRED -->
<!-- expect: exit 1 -->
```sh
certtui check tests/fixtures/expired.pem --no-revocation || echo "exit $?"
```

Para validar contra a sua própria CA use `--ca-file` (qualquer formato aceito
por `inspect`, inclusive truststore JKS e PKCS#12); `--ca-only` confia só nela.
Para arquivos, o hostname só é conferido com `--host-check <nome>`. Aqui a
cadeia de teste é confiável e o exit code é 0:

<!-- test -->
<!-- expect: trusted (anchor: CertTui Test Intermediate CA) -->
<!-- expect: no findings -->
```sh
certtui check tests/fixtures/chain-3.pem --ca-file tests/fixtures/chain-3.pem --ca-only --no-revocation
```

Uma entrada sem nenhum certificado termina com exit 3:

<!-- test -->
<!-- expect: exit 3 -->
```sh
certtui check tests/fixtures/messy/no-certs.txt 2>/dev/null || echo "exit $?"
```

### `batch`

Lê um arquivo com um alvo por linha (`#` comenta, linhas vazias são ignoradas) ou
um JSON `["a.com", "b.com:8443"]`; `-` lê do stdin. Os alvos são servidores TLS,
deduplicados, inspecionados com concorrência limitada (`--concurrency`, padrão
32, máximo 256). A saída é JSON (padrão) ou `--csv`, uma linha por alvo; o exit
code segue a tabela acima (`--fail-on` vale aqui também).

```sh
certtui batch alvos.txt --csv --fail-on warning
```

Nada escuta na porta 1 do loopback, então todos os alvos falham e o exit code é 3:

<!-- test -->
<!-- expect: target,status,days,cn,issuer,errors,warnings,infos,failure -->
<!-- expect: 127.0.0.1:1,failed -->
<!-- expect: exit 3 -->
```sh
printf '127.0.0.1:1\n' | certtui batch - --csv || echo "exit $?"
```

No TUI, a tecla `b` na Home abre um batch a partir de um arquivo.

### `export`

Grava o certificado (ou a cadeia) em PEM, DER (um certificado) ou JSON (o mesmo
documento de `inspect --json`). A escrita é atômica e **nunca sobrescreve** sem
`--force`.

```sh
certtui export example.com --format pem --chain --out cadeia.pem
certtui export example.com --format der --index 1 --out intermediario.der
```

<!-- test -->
<!-- expect: BEGIN CERTIFICATE -->
```sh
certtui export tests/fixtures/chain-3.pem --format pem --chain --out "${TMPDIR:-/tmp}/cadeia.pem" --force
head -n 1 "${TMPDIR:-/tmp}/cadeia.pem"
```

## Flags e configuração

`certtui <comando> --help` lista todas as flags. As principais:

| Grupo | Flags |
|---|---|
| Rede | `--sni <nome>`, `--connect-to <ip[:porta]>`, `--proxy http://host:porta`, `--no-proxy`, `--timeout <s>` (teto de 120) |
| Validação | `--trust system\|mozilla\|custom` (repetível, padrão `system`), `--ca-file <caminho>`, `--ca-only`, `--host-check <nome>` |
| Revogação e AIA | `--revocation leaf\|full`, `--no-revocation`, `--aia` / `--no-aia` (busca de intermediários, desligada por padrão) |
| Keystores | `--password-env VAR`, `--password-file <caminho>`, `--password-stdin` (nunca passe a senha como argumento) |
| Entrada | `--file` (trata o alvo como arquivo), `--recursive` |
| Saída | `--json`, `--text`, `--pem` (`inspect`), `--csv` (`batch`), `--fingerprint-format colon\|hex\|base64` |
| Outras | `--config <caminho>`, `--log-file <caminho>` |

- **Somente TLS 1.2 e TLS 1.3.** A cadeia é capturada exatamente como o servidor
  a apresentou, junto com OCSP stapling, versão negociada, cipher suite, grupo de
  key exchange, ALPN (`h2`, `http/1.1`) e o IP conectado.
- **Proxy:** só túnel HTTP CONNECT (`http://host:porta`, sem credenciais). As
  variáveis `HTTPS_PROXY`/`NO_PROXY` só são lidas com `network.use_env_proxy`
  ligado na configuração.
- **AIA:** com `--aia`, um intermediário que falta é baixado da URL "CA Issuers" e
  marcado como obtido via AIA; o achado `CHAIN_INCOMPLETE` é mantido.
- **Revogação:** OCSP stapling, OCSP e CRL. Os SCTs embutidos no certificado são
  exibidos, mas a assinatura deles **não** é verificada.
- **Configuração (JSON):** `$CERTTUI_CONFIG` tem precedência sobre `--config`; sem
  nenhum dos dois, lê `~/.config/certtui/config.json` (Linux) se existir. Config
  ausente usa os padrões; config inválida termina com exit 2 apontando o campo.
  O JSON Schema está em [`docs/config.schema.json`](docs/config.schema.json).
  Histórico e favoritos ficam em `history.json` no diretório de dados do usuário.
- O JSON de `inspect`, `check` e `batch` tem `"schema_version": 1` e é um contrato
  público.

```json
{
  "schema_version": 1,
  "thresholds": { "warn_days": 30, "critical_days": 7, "fail_on": "error" },
  "network": { "timeout_secs": 20, "use_env_proxy": false, "aia": false, "revocation": "leaf" },
  "ui": { "theme": "dark", "fingerprint_format": "colon", "clipboard": "auto" }
}
```

O TUI usa teclas vim e setas (`j`/`k`; `h`/`l`/`Tab` troca de painel; `[`/`]` troca de aba; `/`
filtra no batch, `o` novo alvo, `e` exportar, `?` ajuda, `q` sai). A ajuda `?`
sempre mostra as teclas em vigor; o mapa é remapeável em `ui.keymap`. Os temas
são `dark`, `light` e `mono`; `NO_COLOR` é respeitado e o mouse vem desligado.

## Fingerprints

Todo certificado mostra **SHA-1, SHA-256 e SHA-512** calculados sobre o DER
completo (o mesmo valor de `openssl x509 -fingerprint -sha1|-sha256|-sha512`). O
SHA-1 serve **só para identificação** (keytool, painéis de CA); nunca entra em
decisão de segurança.

O formato de exibição é `colon` (`AB:CD:...`, padrão), `hex` (minúsculo, sem
separador) ou `base64`: use `--fingerprint-format` na linha de comando,
`ui.fingerprint_format` na configuração ou a tecla `x` no TUI. Na aba
**Fingerprints** do TUI o valor quebra de linha quando a largura não cabe; a
quebra é só visual, o valor copiado é sempre contínuo.

<!-- test -->
<!-- expect: QjpeuBAV5uzfUixctJrUgvxKXBdfsK85lyHywmHB3r0= -->
```sh
certtui inspect tests/fixtures/chain-3.pem --field fingerprint.sha256 --fingerprint-format base64
```

## Clipboard

No TUI, qualquer dado exibido pode ser copiado. O texto copiado sai do modelo, não
da tela: sem cortes de largura, sem quebra visual, sem bordas. Caracteres de
controle são removidos antes da cópia.

| Tecla | Onde | Copia |
|---|---|---|
| `y` | Inspect, painel de detalhes | o valor do campo sob o cursor (um SHA-256, um serial, um SAN) |
| `y` | Inspect, árvore da cadeia | o Subject DN do certificado selecionado |
| `Y` | Inspect | a aba visível inteira, como `Rótulo: valor` |
| `c` | Inspect | o PEM do certificado selecionado |
| `C` | Inspect | a cadeia inteira em PEM, na ordem apresentada |
| `J` | Inspect | o relatório em JSON (mesmo schema de `--json`) |
| `y` | Batch | a linha selecionada em TSV |
| `Y` | Batch | a tabela filtrada em CSV |
| `y` | Findings | `CÓDIGO severidade: mensagem` do achado selecionado |

Um toast confirma o que foi copiado e o tamanho, ou explica a falha. Texto acima
de 256 KiB (`limits.max_clipboard_bytes`, teto de 1 MiB) não é copiado: o toast
sugere `e` para exportar.

**Dois mecanismos.** O **OSC 52** manda uma sequência de escape ao terminal, que
grava no clipboard dele (funciona por SSH e dentro do tmux). O **clipboard
nativo** do sistema só existe em builds com a feature `native-clipboard` (não nos
binários musl).

**`ui.clipboard`** escolhe a estratégia: `auto` (padrão), `osc52`, `native`,
`osc52,native`, `native,osc52` ou `off`. Uma lista com vírgula define a ordem de
tentativa. Em `auto`, uma sessão SSH (`SSH_CONNECTION` ou `SSH_TTY`) usa OSC 52;
localmente usa o nativo e, se falhar, OSC 52. `native` num binário sem a feature é
erro de configuração (exit 2).

**Problemas comuns**

- **"Sent via OSC 52", mas nada chegou ao clipboard.** O terminal não confirma o
  recebimento do OSC 52, por isso o toast diz *Sent via OSC 52* e não *Copied*.
  Alguns terminais trazem o OSC 52 desligado ou só liberam a escrita por opção
  (iTerm2, xterm com `allowWindowOps`, kitty com `clipboard_control`; confira a
  documentação do seu terminal). Habilite a opção ou, se o seu build tiver o
  clipboard nativo, use `ui.clipboard` com `native`.
- **tmux.** O OSC 52 só atravessa o tmux com `set -g set-clipboard on` no
  `~/.tmux.conf` (recarregue com `tmux source-file ~/.tmux.conf`).
- **X11 e Wayland: o clipboard some quando o `certtui` fecha.** O clipboard nativo
  é servido pelo próprio processo, então o conteúdo só existe enquanto o programa
  está aberto, a menos que um gerenciador de clipboard (por exemplo `clipman`,
  `copyq` ou `klipper`) o guarde. Cole antes de sair, ou use o OSC 52.
- **Binário musl (Linux).** Sem clipboard nativo; só OSC 52.
- **Copiar fora do TUI.** Use `--field` com a ferramenta do seu sistema:
  `certtui inspect example.com --field fingerprint.sha256 | xclip -selection clipboard`.

## Limites de recurso

Toda entrada é tratada como hostil: tem limite de bytes, de itens e de tempo. A
configuração (`limits`) pode reduzir ou aumentar cada limite **até o teto rígido**;
acima do teto o valor é truncado e um aviso é registrado no log.

| Limite | Padrão | Teto |
|---|---|---|
| Arquivo de certificado/PEM/P7B, stdin, keystore | 4 MiB | 16 MiB |
| Certificado DER | 64 KiB | 256 KiB |
| Cadeia (apresentada + AIA) | 10 | 16 |
| Certificados por fonte | 500 | 2 000 |
| Entradas de diretório / profundidade | 1 000 / 3 | 10 000 / 3 |
| Bytes de handshake TLS | 256 KiB | 1 MiB |
| Tempo total por alvo | 20 s | 120 s |
| OCSP/CRL/AIA: tempo por requisição | 5 s | 30 s |
| CRL | 8 MiB | 32 MiB |
| Alvos de um batch / concorrência | 10 000 / 32 | 100 000 / 256 |
| Histórico | 200 entradas | 1 000 |
| Texto copiado | 256 KiB | 1 MiB |

Metas medidas em Linux x86_64, build `--release`: RSS de até 30 MiB num `inspect`
único, 96 MiB num batch de 1 000 alvos locais e 128 MiB com 10 000 linhas de
batch; CPU abaixo de 1% em idle no TUI.

## Segurança

- **Nunca extrai chave privada.** Keystores (PKCS#12, JKS) e textos são lidos só
  para os certificados; chaves privadas nunca são exibidas, exportadas nem
  registradas em log. A senha de um keystore não vai como argumento de linha de
  comando (`--password-env`, `--password-file` ou `--password-stdin`).
- **Sem OpenSSL** (`openssl` e `openssl-sys` são banidos no `deny.toml`) e sem
  invocar binários externos.
- **`unsafe` é proibido** em todos os crates (`#![forbid(unsafe_code)]`).
- Strings vindas de um certificado são sanitizadas antes de serem desenhadas ou
  copiadas, para que um CN malicioso não injete sequências de escape no terminal.
- As URLs de OCSP, CRL e AIA que apontam para loopback, link-local ou metadados de
  nuvem são recusadas por padrão (`--allow-internal-urls` as libera).
- O certificado é mostrado **mesmo que inválido**; a validação é uma camada
  separada, que gera achados.

## Fora do escopo da v1

Estas funções não existem na v1 e o `certtui` não as simula:

- STARTTLS (SMTP, IMAP, Postgres, LDAP): só TLS direto.
- SOCKS5: o proxy é só HTTP CONNECT.
- mTLS: o certificado do servidor chega antes do pedido de certificado de
  cliente, então já é capturado sem ele.
- TLS 1.1 e anteriores: só TLS 1.2 e 1.3.
- Scanner de cipher suites.
- Geração de certificados e de CSR.
- Verificação da assinatura de SCT (os SCTs embutidos são só exibidos).
- Internacionalização: a interface é em inglês; a documentação é em PT-BR.

## Contribuição

O portão de qualidade é `scripts/ci.sh`; o CI roda o mesmo roteiro e qualquer
falha bloqueia. Ele precisa de `cargo-deny`, `cargo-machete`, `cargo-llvm-cov` e
`jq`, e roda, em ordem:

1. `cargo clean` e `cargo fmt --all -- --check`;
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`;
3. `scripts/check_layers.sh`: a direção das dependências é
   `domain` ← `app` ← `infra`/`tui` ← binário;
4. `cargo test --workspace --all-features` (inclui o teste que executa os exemplos
   deste README);
5. `cargo deny check` (advisories, licenças, bans e fontes);
6. `cargo machete` (dependências sem uso);
7. cobertura de linhas: no mínimo 70% no workspace e 90% em `certtui-domain` e
   `certtui-app`;
8. `cargo check` na versão mínima do Rust (`rust-version` do `Cargo.toml`);
9. build `--release` com as verificações de RSS (inspect único, batch de 1 000
   alvos, 10 000 linhas) e de CPU em idle.

Regras de código, aplicadas pelo workspace (`[workspace.lints]`):

- `unsafe` é proibido (`forbid`); `missing_docs` avisa;
- clippy `pedantic` como aviso e, fora de testes, **negados**: `unwrap`,
  `expect`, `panic!`, indexação direta (`indexing_slicing`), `todo!`,
  `unimplemented!`, `dbg!`, `print_stdout` e funções com argumentos demais
  (`too_many_arguments`);
- domínio e casos de uso não fazem I/O: dependem de traits (portas) e recebem o
  relógio por injeção;
- toda leitura de dado externo tem teto de bytes, de itens e de tempo, e nenhuma
  recursão sobre dado não confiável.

O desenvolvimento é guiado por testes (TDD): escreva o teste que falha antes do
código. O diretório `fuzz/` tem alvos de cargo-fuzz para os parsers de entrada.
Os fixtures de `tests/fixtures` não têm chave privada (a única exceção,
descartável, é `messy/with-private-key.txt`).

## Licença

Dupla licença, à sua escolha: [MIT](LICENSE-MIT) ou [Apache-2.0](LICENSE-APACHE).
