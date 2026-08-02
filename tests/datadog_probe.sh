#!/usr/bin/env bash
# Que contient réellement le flux Claude Code → Datadog ?
#
# Phase 0 avait mesuré le volume (~343 Ko/session) sans inspecter le contenu.
# Ce script fait tourner une session 100 % SYNTHÉTIQUE avec la télémétrie
# ACTIVÉE, capture les corps vers Datadog et en produit une synthèse
# structurelle (champs présents, types d'événements), pas un dump.
#
# Les corps bruts restent sous captures/ (gitignoré) : les supprimer après
# lecture.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${REPO_ROOT}/captures/datadog-${STAMP}"
CA="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
MITM_PORT="${MITM_PORT:-8092}"

mkdir -p "${OUT}/bodies"
cd "${REPO_ROOT}"

cleanup() { [[ -n "${MITM_PID:-}" ]] && kill "${MITM_PID}" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

command -v mitmdump >/dev/null || { echo "mitmdump absent" >&2; exit 1; }
# L'inventaire tourne en parallèle : sans lui, une absence de trafic Datadog
# serait indiscernable d'une panne du harnais.
mitmdump -q --listen-host 127.0.0.1 --listen-port "${MITM_PORT}" \
  -s tests/egress/datadog_probe.py --set dd_out="${OUT}/bodies" \
  -s tests/egress/inventory_addon.py --set egress_log="${OUT}/flows.jsonl" \
  > "${OUT}/mitmdump.log" 2>&1 &
MITM_PID=$!
sleep 3

# ATTENTION : ne pas poser CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC ici ne
# suffit PAS à réactiver la télémétrie. Claude Code injecte le bloc `env` de
# ~/.claude/settings.json dans la session ; si les drapeaux de coupure y sont,
# ce script mesure une absence déjà acquise. Pour tester réellement, lancer
# avec un fichier de settings temporaire dépourvu de ces variables :
#   claude --settings /tmp/probe-settings.json …
if grep -qE 'DISABLE_TELEMETRY|DISABLE_NONESSENTIAL_TRAFFIC|DO_NOT_TRACK' \
     "${HOME}/.claude/settings.json" 2>/dev/null; then
  echo "  ⚠ télémétrie déjà coupée dans ~/.claude/settings.json :"
  echo "    une absence de flux Datadog ne prouvera rien sur son contenu."
fi

echo "→ session synthétique…"
HTTPS_PROXY="http://127.0.0.1:${MITM_PORT}" \
HTTP_PROXY="http://127.0.0.1:${MITM_PORT}" \
NO_PROXY="127.0.0.1,localhost" \
NODE_EXTRA_CA_CERTS="${CA}" \
  claude -p "Lis tests/fixtures/synthetic_infra.md et résume-le en une phrase." \
    --allowedTools Read --max-turns 4 \
    > "${OUT}/claude_stdout.txt" 2>"${OUT}/claude_stderr.txt"
echo "   code retour claude : $?"

sleep 35   # le flush Datadog intervient toutes les ~15 s ; on en couvre deux
cleanup
trap - EXIT

uv run python tests/egress/datadog_report.py "${OUT}"
