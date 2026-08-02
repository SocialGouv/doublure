#!/usr/bin/env python3
"""Hook PreToolUse — garde du canal 2 (plan §5 Phase 4).

`PreToolUse` est le SEUL hook capable d'empêcher un outil d'atteindre le
réseau : les autres se déclenchent quand la charge est déjà partie.

Ce hook **bloque**, il ne pseudonymise pas. Il n'y a pas de canal de
réécriture au retour vers l'opérateur sur ce chemin (§7) : tenter d'y
substituer donnerait une fausse impression de réversibilité.

Décisions :
  - refus des sorties à haut risque (secrets, credentials, état Terraform…) ;
  - refus de tout accès au COFFRE et à la clé maître — c'est la mitigation du
    gap assumé « coffre local, même utilisateur » (réponse §3.5) ;
  - refus des exfiltrations directes (curl/wget vers le réseau) qui
    contourneraient le proxy (D9) ;
  - tout est tracé dans un journal d'audit append-only.

Protocole : lit l'événement JSON sur stdin, écrit une décision JSON sur
stdout. `permissionDecision: "deny"` bloque avant exécution et remonte la
raison au modèle sous une forme exploitable.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

STATE_DIR = Path(os.environ.get("ANONPROXY_STATE_DIR", Path.home() / ".local/state/anonproxy"))
AUDIT_LOG = Path(os.environ.get("ANONPROXY_AUDIT_LOG", STATE_DIR / "canal2_audit.jsonl"))

#: Chemins du coffre : l'agent ne doit jamais les lire (ni par Read, ni par Bash).
VAULT_PATTERNS = (
    r"\.local/state/anonproxy",
    r"anon_secret_key",
    r"vault\.db",
)

#: Fichiers dont le CONTENU est un secret. Testés sur les chemins (outils
#: fichier) ET sur les commandes shell, quel que soit le lecteur employé :
#: `cat`, `less`, `cp`, `python -c open(...)`, un éditeur… Ne pas énumérer les
#: lecteurs, viser la cible.
SENSITIVE_FILE_PATTERNS: tuple[str, ...] = (
    # Le délimiteur de droite doit inclure les opérateurs shell : sans eux,
    # `cat .env|xxd` et `cat .env;true` passaient.
    # `production.env` autant que `.env` ; mais jamais les TEMPLATES publics
    # (`.env.example`, `.env.sample`…), qui sont faits pour être partagés.
    r"(?!.*\.env\.(example|sample|template|dist|schema))"
    r"[\w-]*\.env(\.[\w-]+)?($|[\s'\"|>;&)\],])",
    r"\.aws/credentials",
    r"\.kube/config",
    r"\bkubeconfig\b",
    r"\.ssh(/|$|\b)",
    r"\.gnupg(/|$|\b)",
    r"/etc/ssl/private(/|$)",
    r"\bid_(rsa|dsa|ecdsa|ed25519)\b",
    r"\.netrc\b",
    r"\.git-credentials\b",
    r"\.docker/config\.json",
    r"\.npmrc\b",
    r"\.pypirc\b",
    r"[\w./-]*secrets?[\w-]*\.(ya?ml|json|env|txt|conf|toml|ini)\b",
    r"\.(pem|key|p12|pfx|ppk|der|jks|keystore|pkcs12)\b",
    r"/proc/[^/\s]+/environ",
    r"\.envrc\b",
    r"\bkubecfg\b",
    r"\bterraform\.tfstate(\.backup)?\b",
    r"\.tfstate\b",
    r"\bcredentials?\.(json|ya?ml|ini|conf)\b",
    r"\bservice[-_]account[\w-]*\.json\b",
)

#: Programmes qui déversent l'environnement, où qu'ils apparaissent dans la
#: commande. Repérés par TOKENISATION, pas par position : `/usr/bin/env`,
#: `command env`, `bash -c env`, `V=$(env)` et `xargs env` doivent tous être
#: bloqués. Seule exception : `env VAR=x cmd`, qui est un préfixe
#: d'exécution — reconnu par la présence d'un argument `NOM=valeur`.
ENV_DUMP_PROGRAMS = frozenset({"env", "printenv", "set", "export", "declare", "compgen"})

#: Interpréteurs et binaires capables d'ouvrir une socket : impossible de tous
#: les énumérer, d'où le rappel que la réponse définitive est le pare-feu (D9).
NETWORK_CAPABLE = frozenset({
    "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp",
    "ssh", "scp", "rsync", "openssl", "dig", "nslookup", "host", "getent",
    "ping", "traceroute", "whois", "aria2c", "httpie", "http", "xh",
})

#: Chemins pseudo-fichiers ouvrant une socket dans le shell.
_SHELL_SOCKET_RE = re.compile(r"/dev/(tcp|udp)/", re.I)

#: Appels réseau embarqués dans un interpréteur (`python3 -c …`, `node -e …`).
#: Lecture de l'environnement depuis un interpréteur : `env` est bloqué, mais
#: `node -e process.env` ou `perl -e %ENV` faisaient exactement la même chose.
#: Syntaxes d'accès à l'environnement PROPRES à un langage. Volontairement
#: précises : un `\bENV\b` générique bloquait `grep -r env src/`, `cat env.md`
#: et `find . -name "*.env.example"` — l'agent ne pouvait plus travailler.
_INLINE_ENV_RE = re.compile(
    r"(os\s*\.\s*(environ|getenv|putenv)|process\s*\.\s*env\b|"
    r"[%$@]_?ENV\s*[\[{]|\$_?ENV\b|"
    r"\bENVIRON\s*\[|\barray\s+get\s+env\b|"
    r"Sys\.getenv|System\.getenv|\bgetenv\s*\()",
    re.I,
)

#: Invocation d'un interpréteur avec le programme EN LIGNE. Dans ce contexte
#: seulement, une simple mention de l'environnement suffit à refuser : le
#: risque est réel et le faux positif quasi nul.
_INTERPRETE_EN_LIGNE = re.compile(
    r"\b(python3?|perl|ruby|node|php|lua|tclsh|Rscript|julia|awk|gawk|mawk)\b"
    r"[^|;&]*\s-(e|c|E|f)?\b|\bawk\b\s+[\"']?BEGIN",
    re.I,
)
_MENTION_ENV = re.compile(r"\b(env|environ|environment)\b", re.I)

#: Charge obfusquée réinjectée dans un interpréteur : le hook ne voit que
#: `base64 -d`, la charge réelle n'apparaît qu'à l'exécution. On refuse le
#: MONTAGE, faute de pouvoir lire ce qu'il transporte.
_DECODER_TO_SHELL_RE = re.compile(
    r"\b(base64|base32|basenc|xxd|od|uudecode|openssl\s+enc|printf|echo)\b[^|]*\|\s*"
    r"(sudo\s+|env\s+)?(ba|z|k|da)?sh\b|"
    r"\b(base64|base32|xxd|od)\b[^|]*\|\s*(python3?|perl|ruby|node|php)\b",
    re.I,
)

#: Interpréteur lisant son programme sur l'entrée standard : même problème.
_STDIN_INTERPRETER_RE = re.compile(
    r"\|\s*(sudo\s+)?(python3?|perl|ruby|node|php|(ba|z|k|da)?sh)\s*(-\s*)?$|"
    r"\b(python3?|perl|ruby|node|(ba|z|k|da)?sh)\s+-\s*$|"
    r"\beval\b|\bsource\s+/dev/stdin\b",
    re.I,
)

#: Variables d'environnement dont la VALEUR est un secret. `env` est bloqué,
#: mais `echo $ANTHROPIC_API_KEY` extrayait la même chose, une par une — et
#: `cat "$ANONPROXY_MASTER_KEY_FILE"` visait directement la clé du coffre.
_SENSITIVE_NAME_RE = re.compile(
    r"(AWS|GCP|AZURE|ANTHROPIC|OPENAI|GITHUB|GITLAB|SLACK|VAULT|ANONPROXY|"
    r"DATADOG|TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|CREDENTIAL|"
    r"PRIVATE_KEY|SIGNING_KEY|ENCRYPTION_KEY|SESSION_KEY|_DSN|_URL|_URI|"
    r"CONNECTION_STRING|BEARER|COOKIE)", re.I,
)

_SENSITIVE_VAR_RE = re.compile(
    r"\$\{?!?\s*[A-Za-z_]*(AWS|GCP|AZURE|ANTHROPIC|OPENAI|GITHUB|GITLAB|SLACK|"
    r"VAULT|ANONPROXY|DOCKER|NPM|PYPI|DATADOG)[A-Za-z0-9_]*|"
    r"\$\{?!?\s*[A-Za-z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|"
    r"CREDENTIAL|PRIVATE_KEY)[A-Za-z0-9_]*",
    re.I,
)

#: (appliqué sur la commande NORMALISÉE : les quotes ont déjà été retirées)
_INLINE_NETWORK_RE = re.compile(
    r"(urllib|requests\.|httpx\.|socket\s*\.\s*(socket|create_connection)|"
    r"http\.client|HTTP::Tiny|LWP::|Net::HTTP|require\s*\(?\s*(https?|net|dgram)\b|"
    r"fetch\s*\(|XMLHttpRequest|axios)",
    re.I,
)

#: Commandes dont la SORTIE exposerait des secrets en clair. Appliquées sur la
#: commande NORMALISÉE (quoting et globs neutralisés).
DENY_COMMAND_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(kubectl|kubecolor|oc|k|kc)\b[^|;&]*\b(get|describe)\b[^|;&]*\bsecret",
     "lecture de secrets Kubernetes en clair"),
    (r"\b(kubectl|oc|k|kc)\b[^|;&]*\b(exec|cp)\b",
     "kubectl exec/cp permet de lire le jeton de compte de service monté dans le pod"),
    (r"\b(kubectl|oc|k|kc)\b[^|;&]*\bcreate\b[^|;&]*\btoken\b", "émission d'un jeton Kubernetes"),
    (r"/(var/)?run/secrets/", "montage de secrets (jeton de compte de service)"),
    (r"\bterraform\b[^|;&]*\b(state|console|show)\b", "l'état Terraform contient des secrets"),
    (r"\bterraform\b[^|;&]*\boutput\b(?![^|;&]*-json\s+\w)", "les sorties Terraform peuvent être sensibles"),
    (r"\b(aws|gcloud|az|gh)\b[^|;&]*\b(get-session-token|print-access-token|get-token|"
     r"get-access-token|print-identity-token|assume-role|export-credentials|sso|"
     r"application-default)\b", "récupération de jeton ou de credentials cloud"),
    (r"\bgh\b[^|;&]*\b(auth\b[^|;&]*\btoken|secret\b)", "jeton ou secrets GitHub"),
    (r"\bhelm\b[^|;&]*\bget\b[^|;&]*\b(values|all|manifest)\b",
     "les values Helm contiennent des secrets"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "clé privée en clair dans la commande"),
    (r"\bgpg\b[^|;&]*--export-secret-keys", "export de clé privée GPG"),
    (r"\bsecurity\b[^|;&]*\bfind-generic-password\b", "extraction du trousseau"),
    # `env` ne montre que SON environnement ; `ps auxe` montre celui de TOUS
    # les processus — agent, base de données, jetons injectés au login.
    (r"\bps\b[^|;&]*(\bauxe\b|\beww\b|-\w*e\w*\b[^|;&]*\benviron\b|\benviron\b)",
     "l'environnement des autres processus (ps) expose leurs jetons"),
    (r"/proc/[^/\s]+/(environ|cmdline)", "environnement d'un autre processus"),
    (r"\b(gdb|strace|ltrace|lldb)\b[^|;&]*\s-p\b", "attachement à un processus vivant"),
    (r"\bsystemctl\b[^|;&]*\b(show-environment|show\b[^|;&]*Environment)\b",
     "environnement des unités systemd"),
    (r"\bdocker\b[^|;&]*\binspect\b", "docker inspect expose l'environnement d'un conteneur"),
    (r"\bgit\b\s+config\b(?![^|;&]*\buser\.(name|email)\b)",
     "la configuration git peut contenir un jeton dans une URL de remote"),
    (r"\bgit\b[^|;&]*\bremote\b[^|;&]*(-v|get-url)", "les remotes git peuvent porter un jeton"),
    (r"\.git/config\b", "la config du dépôt peut contenir un jeton"),
    (r"\bcrontab\b\s+-l\b", "les tâches planifiées portent souvent des secrets"),
    (r"\b(kubectl|oc|k|kc)\b[^|;&]*\b(port-forward|proxy)\b",
     "un tunnel vers le cluster contourne le proxy (D9)"),
    (r"\bgh\b\s+api\b", "`gh api` appelle GitHub directement (D9)"),
    (r"\bdocker\b[^|;&]*\brun\b[^|;&]*-v\s*[^\s:]*(\.ssh|\.aws|\.kube|\.gnupg|/etc/ssl)",
     "montage d'un répertoire de secrets dans un conteneur"),
    (r"(^|[|;&\s])(\.|source)\s+(/tmp/|/dev/|/var/tmp/)",
     "exécution d'un script depuis un répertoire temporaire : contenu non analysable"),
    (r"\bhistory\b(\s|$)|\$HISTFILE\b", "l'historique de shell contient des secrets saisis"),
    (r"\.(bash|zsh|sh)_history\b", "l'historique de shell contient des secrets saisis"),
    (r"\.local/state(/[^/\s]*)*/\*", "accès générique au répertoire d'état (coffre)"),
    (r"\bfind\b[^|;&]*\.local/state\b", "énumération du répertoire d'état (coffre)"),
)

#: Hôtes joignables sans contourner la politique (services locaux du projet).
LOCAL_HOST_RE = re.compile(r"(localhost|127\.0\.0\.1|::1)(:\d+)?")


def audit(record: dict) -> None:
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        # Le hook ne doit jamais faire échouer une session à cause du journal,
        # mais l'échec doit rester visible.
        print(f"anonproxy: journal d'audit inaccessible ({AUDIT_LOG})", file=sys.stderr)


def deny(reason: str, hint: str = "") -> dict:
    message = f"Bloqué par la politique de pseudonymisation : {reason}."
    if hint:
        message += f" {hint}"
    # Marqueur de traçabilité : permet de prouver que CE refus précis a atteint
    # le modèle, là où un simple mot-clé se confondrait avec sa prose.
    if (marker := os.environ.get("ANONPROXY_DENY_MARKER")):
        message += f" [réf. {marker}]"
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": message,
        }
    }


def allow() -> dict:
    return {}


def normalize(command: str) -> str:
    """Neutralise les échappements du shell avant toute analyse.

    Sans cette étape, une regex littérale se contourne trivialement :
    `an[o]nproxy`, `an''onproxy`, `an\\onproxy` et `.en[v]` désignent tous la
    même cible pour bash, mais aucun ne correspond au motif. On retire donc
    quotes, backslashes et classes de globs à un caractère.
    """
    # `e${_+}nv`, `e${IFS}nv` : bash les évalue en `env`. Une expansion sans
    # nom de variable simple est inerte pour le sens de la commande, on la
    # retire avant analyse.
    # `e${_+}nv`, `e${IFS}nv` : bash les évalue en `env`. Une expansion collée
    # AU MILIEU d'un mot ne sert qu'à découper un nom de commande.
    out = re.sub(r"(?<=\w)\$\{[^}]*\}(?=\w)", "", command)
    out = out.replace("''", "").replace('""', "")
    out = re.sub(r"\[([^\]/])\]", r"\1", out)     # glob [o] → o
    out = re.sub(r"\\(.)", r"\1", out)            # \e → e
    out = out.replace("'", "").replace('"', "")
    return out


def tokenize(command: str) -> list[list[str]]:
    """Découpe en commandes simples, sur une base tolérante aux erreurs.

    On ne cherche pas à réimplémenter bash : seulement à voir CHAQUE mot en
    position de programme, y compris derrière `bash -c`, `xargs`, `nohup` ou
    une substitution `$(...)`.
    """
    cleaned = re.sub(r"[$`()]", " ", normalize(command))
    parts = re.split(r"[|;&\n]+|\|\||&&", cleaned)
    return [p.split() for p in parts if p.strip()]


def _basename(token: str) -> str:
    """Nom de commande, chemin retiré : `/usr/bin/env` → `env`."""
    return token.rsplit("/", 1)[-1]


def _program_words(tokens: list[str]) -> list[str]:
    """Mots pouvant désigner un programme : ignore les options et les
    affectations, et déplie les enveloppes (`command`, `bash -c`, `xargs`…)."""
    wrappers = {"command", "builtin", "exec", "nohup", "timeout", "time", "sudo",
                "doas", "xargs", "nice", "ionice", "stdbuf", "env", "sh", "bash",
                "zsh", "ksh", "dash", "watch", "script", "busybox", "toybox",
                "setsid", "chroot", "unshare", "nsenter", "flock", "parallel",
                "do", "then", "else", "elif", "while", "until", "if", "for"}
    words = []
    for tok in tokens:
        if tok.startswith("-") or "=" in tok or tok.isdigit():
            continue  # option, affectation `VAR=x` ou durée : jamais un programme
        base = _basename(tok)
        words.append(base)
        if base not in wrappers:
            break  # premier programme réel atteint : la suite, ce sont ses arguments
    return words


def check_vault_access(text: str) -> str | None:
    normalized = normalize(text)
    for pat in VAULT_PATTERNS:
        if re.search(pat, normalized, re.I):
            return (
                "accès au coffre de pseudonymisation ou à sa clé maître "
                "(le lire annulerait la protection)"
            )
    return None


#: Fichiers de `~/.ssh` qui sont PUBLICS par nature : les bloquer empêchait
#: `ssh-keygen -l -f ~/.ssh/id_rsa.pub` et la lecture d'un `known_hosts`.
_SSH_PUBLIC_RE = re.compile(r"\.ssh/(config|known_hosts\w*|authorized_keys|[\w-]+\.pub)\b")


def check_sensitive_files(text: str) -> str | None:
    normalized = normalize(text)
    if _SSH_PUBLIC_RE.search(normalized) and not re.search(
            r"\.ssh/(id_\w+|identity)\b(?!\.pub)", normalized):
        return None
    for pat in SENSITIVE_FILE_PATTERNS:
        if re.search(pat, normalized, re.I):
            return "accès à un fichier de credentials ou de clés privées"
    return None


def _is_env_prefix(tokens: list[str], idx: int) -> bool:
    """`env VAR=x cmd` : préfixe d'exécution légitime, pas un déversement."""
    return any("=" in t and not t.startswith("-") for t in tokens[idx + 1:])


def _est_deversement(base: str, tokens: list[str], idx: int) -> bool:
    """Ce programme déverse-t-il VRAIMENT l'environnement ?

    `set -e`, `set -euo pipefail` sont l'en-tête idiomatique de tout script
    shell propre ; `declare -f` liste des fonctions ; `printenv PATH` affiche
    UNE variable non sensible. Les bloquer rendait l'agent inutilisable.
    """
    suite = tokens[idx + 1:]
    if _is_env_prefix(tokens, idx):
        return False
    options = [t for t in suite if t.startswith("-")]
    arguments = [t for t in suite if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", t)]
    if base == "set":
        return not options  # `set -e` : mode strict ; `set > f` : déversement
    if base in ("declare", "export"):
        return any(t in ("-p", "-x") for t in options) or not options
    if base == "printenv":
        # une variable nommée : refusé seulement si son nom est sensible
        return not arguments or any(_SENSITIVE_NAME_RE.search(t) for t in arguments)
    return True


def check_bash(command: str) -> str | None:
    if (reason := check_vault_access(command)):
        return reason
    if (reason := check_sensitive_files(command)):
        return reason

    normalized = normalize(command)
    for pattern, reason in DENY_COMMAND_PATTERNS:
        if re.search(pattern, normalized, re.I):
            return reason

    if _SHELL_SOCKET_RE.search(normalized):
        return "socket ouverte par le shell (/dev/tcp) : contourne le proxy (D9)"
    if _INLINE_NETWORK_RE.search(normalized):
        return "appel réseau embarqué dans un interpréteur : contourne le proxy (D9)"
    if _INLINE_ENV_RE.search(normalized):
        return "lecture de l'environnement depuis un interpréteur"
    if _SENSITIVE_VAR_RE.search(normalized):
        return "lecture d'une variable d'environnement porteuse de secret"
    if _DECODER_TO_SHELL_RE.search(normalized) or _STDIN_INTERPRETER_RE.search(normalized):
        return ("charge décodée puis exécutée : son contenu n'est pas analysable "
                "avant exécution, la commande est refusée en l'état")

    # Une substitution (`$(…)`, backticks) exécute ce qu'elle contient, où
    # qu'il apparaisse : on inspecte alors TOUS les mots, pas seulement la
    # position de programme.
    substitution = "`" in command or "$(" in command
    for tokens in tokenize(command):
        candidats = [_basename(t) for t in tokens] if substitution else _program_words(tokens)
        for base_tok in candidats:
            if base_tok in ENV_DUMP_PROGRAMS:
                idx = next((i for i, t in enumerate(tokens)
                            if _basename(t) == base_tok), 0)
                if _est_deversement(base_tok, tokens, idx):
                    return "déversement de l'environnement (jetons et clés compris)"
        # Tous les tokens, pas seulement la position de programme : `curl`
        # caché dans une substitution de processus, un backtick ou un
        # `system()` d'awk échappait à l'analyse.
        for base in {_basename(t) for t in tokens}:
            if base in NETWORK_CAPABLE:
                urls = re.findall(r"[a-z]+://[^\s'\"]+", normalized, re.I)
                if urls and all(_is_local_url(u) for u in urls):
                    continue  # services locaux du projet
                return f"`{base}` peut sortir sur le réseau sans passer par le proxy (D9)"
    return None


def _is_local_url(url: str) -> bool:
    """Vrai seulement si l'HÔTE est local.

    Chercher « localhost » n'importe où dans l'URL suffisait à passer :
    `https://exfil.test/?to=127.0.0.1` et `http://localhost@exfil.test/` sont
    des sorties vers un tiers.
    """
    try:
        hote = urlsplit(url).hostname or ""
    except ValueError:
        return False
    return hote in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or hote.startswith("127.")


def _payload_text(payload: dict) -> str:
    """Aplatit la charge d'un outil : un champ peut arriver en liste ou en
    dict selon l'outil, et `str(liste)` ne matche aucun motif."""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, (list, tuple)):
        return " ".join(_payload_text(v) for v in payload)
    if isinstance(payload, dict):
        return " ".join(_payload_text(v) for v in payload.values())
    return str(payload) if payload is not None else ""


#: Outils portant un chemin ou du texte libre : tous inspectés.
_PATH_TOOLS = {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit", "NotebookRead",
               "Glob", "Grep", "LS"}


def evaluate(event: dict) -> tuple[dict, str | None]:
    tool = event.get("tool_name", "")
    payload = event.get("tool_input", {}) or {}
    hint = ""

    if tool == "Bash":
        command = payload.get("command", "")
        command = " ".join(command) if isinstance(command, list) else str(command)
        reason = check_bash(command)
        hint = "Reformule sans exposer la valeur (référence, agrégat, ou --dry-run)."
    elif tool in _PATH_TOOLS:
        reason = check_vault_access(_payload_text(payload)) or \
            check_sensitive_files(_payload_text(payload))
        hint = "Ce chemin est hors de portée de l'agent par conception."
    elif tool in ("WebFetch", "WebSearch"):
        text = _payload_text(payload)
        reason = check_vault_access(text) or check_sensitive_files(text)
        if reason is None:
            url = str(payload.get("url", ""))
            if url and not _is_local_url(url):
                reason = ("sortie réseau directe hors du proxy (D9) — "
                          "aucune pseudonymisation n'est possible sur ce chemin")
        hint = "Passe par le proxy, ou demande-moi d'ouvrir le domaine explicitement."
    else:
        # Tout autre outil (Task, MCP…). Un serveur MCP expose couramment un
        # champ qui EST une commande : l'inspecter comme telle, sinon
        # `mcp__x__shell {"cmd": "env"}` contournait toute la politique.
        text = _payload_text(payload)
        reason = check_vault_access(text) or check_sensitive_files(text)
        if reason is None and isinstance(payload, dict):
            for champ in ("command", "cmd", "code", "script", "shell", "args", "prompt"):
                valeur = payload.get(champ)
                if valeur is None:
                    continue
                reason = check_bash(_payload_text(valeur))
                if reason:
                    break
        hint = "Cette cible est hors de portée de l'agent par conception."

    if reason:
        return deny(reason, hint), reason
    return allow(), None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"anonproxy: événement PreToolUse illisible : {exc}", file=sys.stderr)
        return 1

    decision, reason = evaluate(event)
    payload = event.get("tool_input", {})
    audit({
        "ts": round(time.time(), 3),
        "tool": event.get("tool_name", ""),
        "session": event.get("session_id", ""),
        "decision": "deny" if reason else "allow",
        "reason": reason or "",
        # La commande n'est journalisée en clair QUE si elle est refusée : le
        # journal ne doit pas devenir une copie de toute l'activité.
        "input": payload if reason else None,
        # Pour les autorisations, une empreinte suffit à reconstituer une
        # chronologie après incident (« cette commande précise est-elle
        # passée ? ») sans dupliquer les données de l'opérateur.
        "digest": None if reason else hashlib.sha256(
            _payload_text(payload).encode("utf-8")
        ).hexdigest()[:16],
    })
    if decision:
        json.dump(decision, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
