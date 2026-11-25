#!/usr/bin/env bash
# Regenera as fixtures de revogação. Ferramenta geradora fora do projeto: precisa de
# `python3` com o pacote `cryptography` (>= 42). Veja README.md.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
exec python3 generate.py
