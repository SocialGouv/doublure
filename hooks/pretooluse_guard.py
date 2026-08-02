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
import ipaddress
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
#: Suffixes de fichiers d'environnement qui sont des GABARITS publics, faits
#: pour être partagés. L'exclusion est LOCALE au suffixe, jamais globale à la
#: commande : une exclusion en `(?!.*…)` se désamorce en mentionnant
#: `.env.example` n'importe où ailleurs (`cat .env; echo .env.example`).
_GABARIT_ENV = r"(?!(example|sample|template|dist|schema)\b)"

SENSITIVE_FILE_PATTERNS: tuple[str, ...] = (
    # Le délimiteur de droite doit inclure les opérateurs shell : sans eux,
    # `cat .env|xxd` et `cat .env;true` passaient.
    # `production.env`, `.env.local` et `.env-production` autant que `.env` :
    # le séparateur de variante est un point OU un tiret.
    rf"[\w-]*\.env([.\-]{_GABARIT_ENV}[\w-]+)?($|[\s'\"|>;&)\],])",
    # `env.production` sans point initial (convention `env_file:` de Compose).
    # Le point APRÈS `env` est obligatoire, sinon `venv` et `python -m venv env`
    # correspondaient.
    rf"(^|[\s/'\"=(])env\.{_GABARIT_ENV}[\w-]+($|[\s'\"|>;&)\],])",
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
    r"(os\s*\.\s*(environ|getenv|putenv)|"
    # `process["env"]` vaut `process.env` ; les quotes sont déjà retirées.
    r"process\s*(\.\s*env\b|\[\s*env\s*\])|"
    # `from os import environ`, `getattr(os, "environ")` : l'attribut littéral
    # n'apparaît jamais, seul le nom importé ou déréférencé.
    r"from\s+os\s+import\s+[\w\s,]*\benviron\b|"
    r"getattr\s*\(\s*os\s*,\s*environ|"
    r"[%$@]_?ENV\s*[\[{]|\$_?ENV\b|"
    # `perl -e 'print keys %ENV'` et `awk 'BEGIN{for(k in ENVIRON)…}'` déversent
    # tout sans indexer. Casse SIGNIFICATIVE ici : `environ` minuscule est un
    # mot courant, `ENVIRON` majuscule est la table d'awk.
    r"(?-i:[%@]_?ENV)\b|(?-i:\bENVIRON\b)|"
    r"\barray\s+get\s+env\b|"
    r"Sys\.getenv|System\.getenv|\bgetenv\s*\()",
    re.I,
)

#: Régions dont le CONTENU est lui-même une commande : substitutions du shell
#: et primitives d'exécution des interpréteurs. Elles sont analysées
#: récursivement puis retirées de la commande englobante — sans quoi leurs mots
#: y passeraient pour de simples arguments (`perl -e 'system("env")'`).
_NESTED_RE = re.compile(
    r"\$\((?P<sub>[^()]*)\)"
    r"|`(?P<bt>[^`]*)`"
    r"|[<>]\((?P<proc>[^()]*)\)"
    r"|\b(?:system|shell_exec|passthru|popen|Popen|execSync|spawnSync|exec|qx|"
    r"os\.execute|IO\.popen|subprocess\.(?:run|call|check_output|check_call|Popen)|"
    r"check_output|check_call|getoutput|getstatusoutput)"
    # un niveau de parenthèses toléré : `run(("env",))` est un tuple, et
    # l'inversion `[]` → `()` suffisait à sortir de la classe de caractères.
    r"\s*\(\s*[\[(]?(?P<appel>[^()\[\]]*)[\])]?\s*,?\s*\)",
    re.I,
)

#: Ce qu'une région imbriquée laisse derrière elle. Son résultat n'est pas
#: connu avant l'exécution : le remplacer par un BLANC faisait disparaître un
#: argument que le shell, lui, fournira bel et bien
#: (`curl http://local/ $(echo http://tiers/)`).
_MARQUEUR_SUBSTITUTION = "substitution_non_evaluable"

#: Interpréteur dont le programme est donné EN LIGNE : tout ce qui suit est du
#: code, pas des arguments. `system "env"` (Perl/Ruby, sans parenthèses),
#: `qx/env/`, `%x[env]` n'ont aucune forme commune — on inspecte donc TOUS les
#: mots, en découpant sur la ponctuation du langage.
_INTERPRETE_EN_LIGNE = re.compile(
    r"\b(python3?|perl|ruby|node|deno|bun|php|lua|tclsh|Rscript|julia|"
    r"awk|gawk|mawk)\b[^|;&]*?\s-(e|c|r|E|P)\b|\bawk\b[^|;&]*BEGIN",
    re.I,
)
_MOTS_DE_CODE_RE = re.compile(r"[A-Za-z0-9_.-]+")


def _regions_imbriquees(normalized: str) -> list[str]:
    """Contenus exécutables imbriqués, prêts à être ré-analysés.

    La virgule devient un séparateur : `subprocess.run(["curl", "http://x"])`
    est une commande dont les mots sont séparés par des virgules, pas par des
    espaces.
    """
    regions = []
    for m in _NESTED_RE.finditer(normalized):
        contenu = next((v for v in m.groupdict().values() if v is not None), "")
        if contenu.strip():
            regions.append(contenu.replace(",", " "))
    return regions

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
#: UNE seule liste. Elle était dupliquée : la variante qui servait à
#: `echo $VAR` omettait `_DSN`, `_URL`, `CONNECTION_STRING`, `SESSION_KEY`…
#: `printenv DATABASE_URL` était refusé quand `echo $DATABASE_URL` passait.
_SENSITIVE_NAME_RE = re.compile(
    r"(AWS|GCP|AZURE|ANTHROPIC|OPENAI|GITHUB|GITLAB|SLACK|VAULT|ANONPROXY|"
    r"DOCKER|NPM|PYPI|DATADOG|SENTRY|"
    r"TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|CREDENTIAL|"
    r"PRIVATE_KEY|SIGNING_KEY|ENCRYPTION_KEY|SESSION_KEY|_DSN|_URL|_URI|"
    r"CONNECTION_STRING|BEARER|COOKIE)", re.I,
)

#: Le NOM déréférencé, isolé de sa syntaxe (`$X`, `${X}`, `${!X}`).
_NOM_VARIABLE_RE = re.compile(r"\$\{?!?\s*([A-Za-z_][A-Za-z0-9_]*)")

#: Référence INDIRECTE : `x=AWS_SECRET_ACCESS_KEY; echo ${!x}`. Le nom qui
#: compte n'est pas dans l'expansion mais dans l'affectation qui précède.
_REF_INDIRECTE_RE = re.compile(r"\$\{!\s*([A-Za-z_]\w*)")

#: Variables de CONFIGURATION dont le nom porte un mot sensible mais dont la
#: valeur ne l'est pas. Les bloquer empêchait l'agent de vérifier sa propre
#: configuration — `ANTHROPIC_BASE_URL` est l'entrée du proxy, il la lit à
#: chaque session. Liste de noms COMPLETS : un préfixe rouvrirait le trou.
#: `ANONPROXY_STATE_DIR` en est volontairement absente — le chemin du coffre
#: est lui-même un secret.
_VARS_PUBLIQUES = frozenset({
    "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL", "ANTHROPIC_SMALL_FAST_MODEL",
    "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_PAGER",
    "GOOGLE_CLOUD_PROJECT", "DOCKER_HOST", "NPM_CONFIG_REGISTRY",
})


def _nom_sensible(nom: str) -> bool:
    return nom.upper() not in _VARS_PUBLIQUES and bool(_SENSITIVE_NAME_RE.search(nom))


def _variable_sensible(normalized: str) -> str | None:
    for nom in _NOM_VARIABLE_RE.findall(normalized):
        if _nom_sensible(nom):
            return nom
    # `${!x}` ne cite que `x` : le nom réellement lu est la VALEUR de `x`.
    for cible in _REF_INDIRECTE_RE.findall(normalized):
        for valeur in re.findall(rf"\b{re.escape(cible)}=([A-Za-z_]\w*)", normalized):
            if _nom_sensible(valeur):
                return valeur
    return None

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
    # `e${IFS}nv`, `env${IFS}> f`, `e${_+}nv` : bash les évalue en `env`. Ces
    # expansions ne servent qu'à découper un nom de commande — on les retire
    # QUELLE QUE SOIT leur position. Exiger un caractère de mot de chaque côté
    # laissait passer `env${IFS}> dump`, où le `>` suit l'expansion.
    # Une référence simple `${VAR}` est CONSERVÉE : le contrôle des variables
    # porteuses de secret en dépend.
    out = re.sub(r"\$\{IFS\}|\$\{[^}]*[-+:?][^}]*\}", "", command)
    out = re.sub(r"(?<=\w)\$\{[A-Za-z_]\w*\}(?=\w)", "", out)
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
    # Les redirections séparent au même titre que `|` : sans ça, la cible de
    # `env > dump.txt` passait pour le programme exécuté PAR `env`, donc pour
    # un préfixe d'exécution légitime. Les substitutions de processus ont déjà
    # été retirées à ce stade, `<` et `>` ne peuvent plus qu'ouvrir un fichier.
    parts = re.split(r"[|;&\n<>]+|\|\||&&", cleaned)
    return [p.split() for p in parts if p.strip()]


def _basename(token: str) -> str:
    """Nom de commande, chemin retiré : `/usr/bin/env` → `env`."""
    return token.rsplit("/", 1)[-1]


#: Enveloppes : leur argument est lui-même un programme, il faut continuer.
_WRAPPERS = frozenset({
    "command", "builtin", "exec", "nohup", "timeout", "time", "sudo",
    "doas", "xargs", "nice", "ionice", "stdbuf", "env", "sh", "bash",
    "zsh", "ksh", "dash", "watch", "script", "busybox", "toybox",
    "setsid", "chroot", "unshare", "nsenter", "flock", "parallel",
    "su", "runuser", "machinectl", "systemd-run", "proot", "fakeroot",
    "strace", "ltrace",
    "do", "then", "else", "elif", "while", "until", "if", "for",
})

#: Options d'enveloppe dont la valeur occupe le token SUIVANT. Sans elles,
#: `sudo -u root env` faisait passer `root` pour le programme et `env`
#: n'était jamais examiné. `-c` en est exclu : sa valeur EST la commande.
_OPT_AVEC_VALEUR = frozenset({"-u", "--user", "-g", "--group", "-n", "-I", "-t",
                              "--timeout", "--unset"})

#: Enveloppes dont le premier argument est une CIBLE (répertoire, verrou),
#: pas le programme.
_WRAPPERS_AVEC_CIBLE = frozenset({"chroot", "flock"})

#: Ce qui ressemble à une durée (`timeout 5s cmd`), jamais à un programme.
_DUREE_RE = re.compile(r"\d+(\.\d+)?[smhd]?")


def _program_positions(tokens: list[str]) -> list[int]:
    """Indices des mots pouvant désigner un programme.

    Renvoyer les INDICES et non les mots permet d'évaluer chaque occurrence à
    sa place : avec le seul nom, `env PATH=/x env` était jugé sur le premier
    `env` (un préfixe d'exécution légitime) et le second — un déversement —
    passait.
    """
    positions: list[int] = []
    # `find … -exec curl {} \;` : ce qui suit `-exec` est une commande. Ce
    # balayage est SÉPARÉ de la boucle ci-dessous, qui s'arrête au premier
    # programme réel — `find` n'étant pas une enveloppe, elle n'atteignait
    # jamais le `-exec` et la règle était morte.
    positions += [i + 1 for i, tok in enumerate(tokens)
                  if tok in ("-exec", "-execdir", "-ok", "-okdir")
                  and i + 1 < len(tokens)]
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-"):
            i += 2 if tok in _OPT_AVEC_VALEUR else 1
            continue
        if "=" in tok or _DUREE_RE.fullmatch(tok):
            i += 1
            continue
        base = _basename(tok)
        if base == "command" and any(t in ("-v", "-V") for t in tokens[i + 1:]):
            break  # `command -v env` : introspection, rien n'est exécuté
        positions.append(i)
        if base not in _WRAPPERS:
            break  # premier programme réel atteint : la suite, ce sont ses arguments
        i += 1
        if base in _WRAPPERS_AVEC_CIBLE:
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
            i += 1
    # `su root -c env` : l'utilisateur occupe la position de programme et
    # arrêtait l'analyse ; la valeur de `-c` est pourtant une commande.
    if positions and _basename(tokens[positions[0]]) in _WRAPPERS and "-c" in tokens:
        cible = tokens.index("-c") + 1
        if cible < len(tokens) and cible not in positions:
            positions.append(cible)
    return positions


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
    if base == "env":
        # `env` ne déverse que s'il n'exécute RIEN. `env -i cmd` et
        # `env -u FOO cmd` réduisent l'environnement au lieu de l'exposer.
        i = 0
        while i < len(suite):
            tok = suite[i]
            if tok in ("-u", "--unset"):
                i += 2
            elif tok.startswith("-") or "=" in tok:
                i += 1
            else:
                return False  # un programme suit : préfixe d'exécution
        return True
    if _is_env_prefix(tokens, idx):
        return False
    # `+e` est une option au même titre que `-e` : `set +e` désactive le mode
    # strict, il n'imprime rien.
    options = [t for t in suite if t.startswith(("-", "+"))]
    arguments = [t for t in suite if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", t)]
    if base == "set":
        return not options  # `set -e` : mode strict ; `set > f` : déversement
    if base in ("declare", "export"):
        return any(t in ("-p", "-x") for t in options) or not options
    if base == "printenv":
        # une variable nommée : refusé seulement si son nom est sensible.
        # Même dérogation que `echo $VAR`, sinon l'agent pouvait lire sa config
        # d'une façon et pas de l'autre.
        return not arguments or any(_nom_sensible(t) for t in arguments)
    if base == "compgen":
        # `-v` (variables) et `-e` (exportées) déversent ; `-A function`,
        # `-A alias`, `-c` listent des noms sans valeur.
        if any(t in ("-v", "-e") for t in options):
            return True
        if "-A" in suite:
            return suite[suite.index("-A") + 1:][:1] in (["variable"], ["export"],
                                                        ["exported"])
        return not options
    return True


#: Commandes qui n'exposent que des MÉTADONNÉES (nom, taille, date) : `ls` et
#: `stat` ne peuvent pas révéler le CONTENU d'un secret, et interdire de
#: vérifier son existence n'apporte rien.
_METADATA_PROGRAMS = frozenset({"ls", "stat", "file", "du", "test", "dirname",
                                "basename", "realpath", "readlink"})


#: Sous-commandes d'`openssl` purement locales : chiffrement, empreinte, tirage
#: aléatoire. Rien n'y sort sur le réseau — contrairement à `s_client`.
_OPENSSL_LOCAL = frozenset({
    "passwd", "rand", "dgst", "enc", "x509", "req", "genrsa", "genpkey",
    "pkey", "rsa", "ec", "version", "base64", "sha256", "md5", "cms", "pkcs12",
})


def _est_usage_local(base: str, suite: list[str]) -> bool:
    """Invocation d'un binaire réseau qui n'ouvre aucune connexion."""
    if any(t in ("--version", "-V") for t in suite):
        return True
    if base == "openssl":
        premier = next((t for t in suite if not t.startswith("-")), "")
        return premier in _OPENSSL_LOCAL
    return False


def _metadata_seule(command: str) -> bool:
    """Commande simple UNIQUE dont le programme ne lit aucun contenu.

    L'unicité est essentielle : `ls ~/.ssh && cat ~/.ssh/id_rsa` doit rester
    refusé, et une substitution pourrait cacher n'importe quel lecteur.
    """
    normalized = normalize(command)
    if _NESTED_RE.search(normalized):
        return False
    commandes = tokenize(command)
    if len(commandes) != 1:
        return False
    positions = _program_positions(commandes[0])
    return bool(positions) and all(
        _basename(commandes[0][i]) in _METADATA_PROGRAMS for i in positions)


def check_bash(command: str, _profondeur: int = 0) -> str | None:
    if (reason := check_vault_access(command)):
        return reason
    if not _metadata_seule(command) and (reason := check_sensitive_files(command)):
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
    if _variable_sensible(normalized):
        return "lecture d'une variable d'environnement porteuse de secret"
    if _DECODER_TO_SHELL_RE.search(normalized) or _STDIN_INTERPRETER_RE.search(normalized):
        return ("charge décodée puis exécutée : son contenu n'est pas analysable "
                "avant exécution, la commande est refusée en l'état")

    # Une région imbriquée est une commande à part entière : on l'analyse
    # récursivement, puis on la RETIRE de la commande englobante — sinon ses
    # mots y seraient lus comme des arguments (`echo $(find . -name env)`
    # refusé) ou au contraire ignorés (`bash <(env)` accepté).
    if _profondeur < 4:
        for interne in _regions_imbriquees(normalized):
            if (reason := check_bash(interne, _profondeur + 1)):
                return reason

    # Le programme d'un interpréteur donné en ligne est du CODE : ses mots ne
    # sont pas des arguments, et aucune syntaxe commune ne les délimite.
    if _INTERPRETE_EN_LIGNE.search(normalized):
        mots = _MOTS_DE_CODE_RE.findall(normalized)
        for idx, mot in enumerate(mots):
            base = _basename(mot)
            if base in ENV_DUMP_PROGRAMS and _est_deversement(base, mots, idx):
                return "déversement de l'environnement depuis un interpréteur"
            if base in NETWORK_CAPABLE:
                return f"`{base}` appelé depuis un interpréteur : contourne le proxy (D9)"

    exterieur = _NESTED_RE.sub(f" {_MARQUEUR_SUBSTITUTION} ", normalized)

    for tokens in tokenize(exterieur):
        opaque = _MARQUEUR_SUBSTITUTION in tokens
        for idx in _program_positions(tokens):
            base = _basename(tokens[idx])
            if base == _MARQUEUR_SUBSTITUTION:
                return ("le programme exécuté est produit par une substitution : "
                        "son contenu n'est pas analysable avant exécution")
            if base in ENV_DUMP_PROGRAMS and _est_deversement(base, tokens, idx):
                return "déversement de l'environnement (jetons et clés compris)"
            if base in NETWORK_CAPABLE:
                if _est_usage_local(base, tokens[idx + 1:]):
                    continue
                if opaque:
                    return (f"`{base}` reçoit un argument produit par une "
                            "substitution : la destination n'est pas vérifiable (D9)")
                urls = re.findall(r"[a-z]+://[^\s'\"]+", " ".join(tokens), re.I)
                if urls and all(_is_local_url(u) for u in urls):
                    continue  # services locaux du projet
                return f"`{base}` peut sortir sur le réseau sans passer par le proxy (D9)"
    return None


def _is_local_url(url: str) -> bool:
    """Vrai seulement si l'HÔTE est local.

    Chercher « localhost » n'importe où dans l'URL suffisait à passer :
    `https://exfil.test/?to=127.0.0.1` et `http://localhost@exfil.test/` sont
    des sorties vers un tiers.

    L'hôte est comparé en tant qu'ADRESSE, jamais en tant que chaîne : un test
    de préfixe `127.` accepte le nom de domaine `127.evil.test`, qui résout où
    son propriétaire veut.
    """
    try:
        hote = urlsplit(url).hostname or ""
    except ValueError:
        return False
    if hote == "localhost":
        return True
    try:
        adresse = ipaddress.ip_address(hote)
    except ValueError:
        return False  # nom de domaine : jamais local, quelle que soit sa forme
    return adresse.is_loopback or adresse.is_unspecified


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
