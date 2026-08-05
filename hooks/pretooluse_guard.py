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
    # Les lookbehind écartent le CODE JavaScript (`process` + suffixe `env`,
    # `import.meta` + suffixe) : ce n'est pas un fichier de secrets, et le
    # bloquer refusait un simple `grep -r` dans des sources.
    # Le motif commence sur le littéral `.env`, jamais sur une classe libre :
    # un `[\w-]*` de tête rétro-traque à chaque position d'un mot long, et
    # vingt mille caractères sans le moindre point coûtaient plusieurs
    # secondes. Il était de toute façon redondant — `production.env` contient
    # `.env`, et les lookbehind s'évaluent au même endroit.
    rf"(?<!process)(?<!\.meta)\.env([.\-]{_GABARIT_ENV}[\w-]+)?"
    rf"($|[\s'\"|>;&)\],])",
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
    r"secrets?[\w-]*\.(ya?ml|json|env|txt|conf|toml|ini)\b",
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
ENV_DUMP_PROGRAMS = frozenset(
    {"env", "printenv", "set", "export", "declare", "typeset", "compgen"})

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
#: Formes SIGILÉES : `%ENV`, `$ENV`, `@ENV`. Non ambiguës — elles désignent
#: l'environnement partout où elles apparaissent.
_INLINE_ENV_RE = re.compile(
    r"(?-i:[%@]_?ENV)\b|\$_?ENV\b|[%$@]_?ENV\s*[\[{]",
    re.I,
)

#: Formes propres à un LANGAGE. Elles ne comptent que si un interpréteur reçoit
#: son programme EN LIGNE : `grep -r process.env src/` cherche du texte dans des
#: sources, il n'exécute rien.
_CODE_ENV_RE = re.compile(
    r"os\s*\.\s*(environ|getenv|putenv)|"
    # `process["env"]` vaut `process.env` ; les quotes sont déjà retirées.
    r"process\s*(\.\s*env\b|\[\s*env\s*\])|"
    # `from os import environ`, `getattr(os, "environ")` : l'attribut littéral
    # n'apparaît jamais, seul le nom importé ou déréférencé.
    r"from\s+os\s+import\s+[\w\s,]*\benviron\b|"
    r"getattr\s*\(\s*os\s*,\s*environ|"
    # Casse SIGNIFICATIVE : `environ` minuscule est un mot courant, `ENVIRON`
    # majuscule est la table d'awk. Ruby n'a ni sigil ni `ENVIRON` : `ENV[…]`,
    # `ENV.fetch(…)`, ou `p ENV` tout court.
    r"(?-i:\bENVIRON\b)|(?-i:\bENV\b)(?=\s*[\[.)\]]|\s*$)|"
    r"\barray\s+get\s+env\b|"
    r"Sys\.getenv|System\.getenv|\bgetenv\s*\(",
    re.I,
)

#: Régions dont le CONTENU est lui-même une commande : substitutions du shell
#: et primitives d'exécution des interpréteurs. Elles sont analysées
#: récursivement puis retirées de la commande englobante — sans quoi leurs mots
#: y passeraient pour de simples arguments (`perl -e 'system("env")'`).
#: Substitutions du SHELL : elles s'exécutent partout, sans condition.
_NESTED_RE = re.compile(
    r"\$\((?P<sub>[^()]*)\)"
    r"|`(?P<bt>[^`]*)`"
    r"|[<>]\((?P<proc>[^()]*)\)",
)

#: Primitives d'exécution d'un LANGAGE. Réservées au code donné en ligne :
#: `git commit -m 'add system(env) support'` n'exécute rien, et l'analyser
#: refusait un message de commit ordinaire.
_APPEL_LANGAGE_RE = re.compile(
    # `exec\w*` et `spawn\w*` : le `\b` de droite ratait `execvp`, `execlp`,
    # `spawnl`, `spawnSync`… La parenthèse est EXIGÉE ici (c'est un appel).
    r"\b(?:system|shell_exec|passthru|popen|Popen|exec\w*|spawn\w*|fork|qx|"
    r"proc_open|pcntl_exec|posix_spawn\w*|Open3\.\w+|pty\.spawn|"
    r"os\.(?:execute|exec\w*|spawn\w*|popen)|IO\.popen|child_process\.\w+|"
    r"subprocess\.\w+|check_output|check_call|getoutput|getstatusoutput)"
    # un niveau de parenthèses toléré : `run(("env",))` est un tuple, et
    # l'inversion `[]` → `()` suffisait à sortir de la classe de caractères.
    r"\s*\(\s*[\[(]?(?P<appel>[^()]*?)[\])]?\s*,?\s*\)",
    re.I,
)

#: Sous-commandes portées par un ARGUMENT, et non par la position de
#: programme. Le quoting ayant déjà été retiré, on ne sait pas où la
#: sous-commande s'arrête : on analyse tout ce qui suit, récursivement.
#: `trap -- 'env' EXIT` et `mapfile -C 'sh -c env' -c 1` échappaient à une
#: isolation qui ne retenait que le premier token.
#: Vocabulaire FERMÉ des spécifications de signal, qui closent un `trap`.
_SIGNAL_RE = re.compile(
    r"\d+|(SIG)?(EXIT|ERR|DEBUG|RETURN|HUP|INT|QUIT|ILL|TRAP|ABRT|BUS|FPE|"
    r"KILL|USR[12]|SEGV|PIPE|ALRM|TERM|CHLD|CONT|STOP|TSTP|TT(IN|OU)|WINCH)",
    re.I)

_SOUS_COMMANDES_RE = (
    (re.compile(r"\btrap\b([^|;&\n]*)"), True),
    (re.compile(r"\b(?:mapfile|readarray)\b[^|;&\n]*?\s-C\s+([^|;&\n]*)"), False),
)


def _sous_commande(texte: str, retire_signaux: bool) -> str:
    mots = texte.split()
    while mots and mots[0] == "--":
        mots.pop(0)
    while retire_signaux and mots and _SIGNAL_RE.fullmatch(mots[-1]):
        mots.pop()
    return " ".join(mots)

#: Ce qu'une région imbriquée laisse derrière elle. Son résultat n'est pas
#: connu avant l'exécution : le remplacer par un BLANC faisait disparaître un
#: argument que le shell, lui, fournira bel et bien
#: (`curl http://local/ $(echo http://tiers/)`).
_MARQUEUR_SUBSTITUTION = "substitution_non_evaluable"

#: Référence simple à une variable. Sa valeur n'est pas connue avant
#: l'exécution : en position de programme, `$SHELL -c env` lance un shell.
#: La tokenisation retirait le sigil et laissait le mot `SHELL`, que rien
#: ne reconnaît. Ce remplacement n'a lieu QUE pour l'analyse des positions
#: de programme — le contrôle des variables sensibles voit le texte entier.
_REF_SIMPLE_RE = re.compile(
    r"\$\{?(?:[A-Za-z_]\w*|\d+|[@*#?$!-])\}?")

#: Primitive d'exécution SANS parenthèses (`system "env"` en Perl/Ruby,
#: `qx/env/`, `%x[env]`) : `_NESTED_RE` ne voit que les formes parenthésées.
#: On n'inspecte QUE ce qui suit l'appel — inspecter tous les mots du
#: programme en ligne refusait `print("the curl command is useful")`, donc
#: toute prose citant un binaire réseau.
_APPEL_EXEC_RE = re.compile(
    r"\b(?:system|exec\w*|qx|popen|spawn\w*|shell_exec|passthru|"
    r"os\.execute|IO\.popen|subprocess\.\w+|check_output|check_call|"
    r"getoutput|getstatusoutput)\b(?P<args>[^;\n]*)"
    r"|%x[\[({<](?P<pcx>[^\])}>]*)",
    re.I,
)
_MOTS_DE_CODE_RE = re.compile(r"[A-Za-z0-9_.-]+")


def _interprete_execute(command: str) -> bool:
    """Un interpréteur est-il RÉELLEMENT lancé par cette commande ?

    Tester sa simple présence dans le texte refusait
    `git commit -m 'fix perl -e system(env)'` : le message CITE un one-liner,
    il n'en exécute aucun. Seule la position de programme fait foi.
    """
    # Un interpréteur dont le programme arrive par une substitution de PROCESSUS
    # l'exécute comme s'il était donné en ligne. Le fichier `/dev/fd/…` n'existe
    # qu'à l'exécution ; seul le texte qui le produit est lisible ici, et ce
    # texte n'est pas du shell — `python3 <(echo 'os.system("env")')` passait.
    procsub = "<(" in command
    for tokens in tokenize(command):
        programmes = [_basename(tokens[idx]) for idx in _program_positions(tokens)]
        if not any(p in _INTERPRETES for p in programmes):
            continue
        # `python3 --version` n'exécute aucun code : sans cette exigence, il
        # ouvrait l'analyse et un message de commit voisin devenait suspect.
        if any(t in ("-e", "-c", "-r", "-E", "-P") for t in tokens):
            return True
        if any(_basename(t) in ("awk", "gawk", "mawk") for t in tokens):
            return True
        if procsub and any(p in _LANGAGES for p in programmes):
            return True
    return False


def _par_segment(texte: str, transforme) -> str:
    """Applique `transforme` à chaque commande simple, séparateurs préservés."""
    morceaux = re.split(r"([|&\n]+)", texte)
    return "".join(m if i % 2 else transforme(m) for i, m in enumerate(morceaux))


def _regions_imbriquees(normalized: str) -> list[str]:
    """Contenus exécutables imbriqués, prêts à être ré-analysés.

    La virgule devient un séparateur : `subprocess.run(["curl", "http://x"])`
    est une commande dont les mots sont séparés par des virgules, pas par des
    espaces.
    """
    # Les primitives d'un langage ne comptent que dans la commande simple qui
    # lance l'interpréteur : tester la commande ENTIÈRE refusait
    # `git commit -m '…system(env)…' && python3 --version`.
    couples = [(_NESTED_RE, normalized)]
    for segment in re.split(r"[|&\n]+", normalized):
        if _interprete_execute(segment):
            couples.append((_APPEL_LANGAGE_RE, segment))
    regions = []
    for motif, texte in couples:
        for m in motif.finditer(texte):
            contenu = next((v for v in m.groupdict().values() if v is not None), "")
            if contenu.strip():
                # Virgules et crochets délimitent une LISTE d'arguments dans du
                # code : sans les neutraliser, `run(["env", "-0"])` donnait le
                # mot `[env`, que rien ne reconnaît.
                regions.append(re.sub(r"[,\[\]]", " ", contenu))
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
    # `re.M` : la fin de la CHAÎNE ne suffit pas. `cat <<EOF | python3` est
    # suivi du corps du heredoc, si bien que `| python3` n'était jamais en
    # dernière position et le montage passait.
    re.I | re.M,
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
#: L'expansion doit être BIEN FORMÉE : accolade fermante proche, et aucun
#: métacaractère de regex entre les deux. Se contenter du préfixe rendait
#: suspecte toute regex CITANT cette syntaxe — la prose redevenait du code,
#: le défaut que les rounds 5 et 8 avaient éliminé ailleurs.
_REF_INDIRECTE_RE = re.compile(
    r"\$\{!\s*([A-Za-z_]\w*|\d+|[@*])[^}\\\[(?]{0,32}\}")

#: `${!arr[@]}` et `${!arr[*]}` rendent les INDICES d'un tableau : aucune
#: valeur de variable n'en sort. C'est la seule forme d'indirection inoffensive.
#: La normalisation des classes de glob réduit `[@]` à `@` : les deux
#: formes doivent être reconnues.
_INDICES_TABLEAU_RE = re.compile(r"\$\{!\s*[A-Za-z_]\w*(?:\[[@*]\]|[@*])\}")

#: Référence par ALIAS : `declare -n r=AWS_SECRET_ACCESS_KEY; echo $r`. Même
#: mécanisme que la référence indirecte, autre syntaxe — et `$r` ne porte
#: aucun nom sensible, seul l'alias en désigne un.
#: `declare -n r=CIBLE` nomme sa cible tout de suite ; `declare -n r` la
#: recevra plus loin (`r=CIBLE`). Dans les deux cas le nom à suivre est
#: capturé, et la résolution des affectations fait le reste.
_NAMEREF_RE = re.compile(
    r"\b(?:declare|typeset|local)\b[^|;&\n]*?\s-[A-Za-z]*n[A-Za-z]*\s+"
    r"([A-Za-z_]\w*)(?:=(\$?\{?[\w@*]+\}?))?")

#: Les trois façons de poser une variable. `read` et `printf -v` échappaient
#: entièrement à l'index, qui n'admettait qu'un littéral en membre droit.
# La valeur s'arrête au séparateur : `\S*` avalait le `;` de
# `x=$y; echo ${!x}`, et le saut vers `y` se perdait.
_AFFECTATION_RE = re.compile(r"\b([A-Za-z_]\w*)=([^\s|;&]*)")
_PRINTF_V_RE = re.compile(r"\bprintf\b(?:\s+-\S+)*\s+-v\s+([A-Za-z_]\w*)\s+([^|;&\n]*)")
_READ_RE = re.compile(r"\bread\b(?:\s+-\S+)*\s+([A-Za-z_]\w*)\s*<<<\s*([^|;&\n]*)")

#: Membre droit dont la valeur n'est pas connue avant l'exécution.
_VALEUR_OPAQUE_RE = re.compile(r"\$\(|`|" + _MARQUEUR_SUBSTITUTION)

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


#: En contexte arithmétique, `$((PORT))` lit la variable sans dollar : le
#: contrôle des noms, qui exige le sigil, n'y voyait rien.
_ARITHMETIQUE_RE = re.compile(r"\$\(\((.*?)\)\)", re.S)


def _variable_sensible(normalized: str) -> str | None:
    for expression in _ARITHMETIQUE_RE.findall(normalized):
        for nom in re.findall(r"[A-Za-z_]\w*", expression):
            if _nom_sensible(nom):
                return nom
    # `${!arr[@]}` ne rend que des INDICES : le nom du tableau, même sensible,
    # n'expose aucune valeur.
    normalized = _INDICES_TABLEAU_RE.sub(" ", normalized)
    for nom in _NOM_VARIABLE_RE.findall(normalized):
        if _nom_sensible(nom):
            return nom
    # `${!x}` ne cite que `x` : le nom réellement lu est la VALEUR de `x`.
    # Un alias `declare -n r=CIBLE` désigne sa cible de la même façon, mais
    # celle-ci est écrite EN CLAIR — les deux cas ne se traitent donc pas
    # pareil : pour l'alias on lit la cible, pour l'indirection il faut la
    # PROUVER.
    indirections = _REF_INDIRECTE_RE.findall(normalized)
    alias = [(valeur or nom).lstrip("${")
             for nom, valeur in _NAMEREF_RE.findall(normalized)]
    if not indirections and not alias:
        return None
    # Index des affectations construit en UNE passe. Chercher chaque cible dans
    # toute la commande coûtait O(cibles x longueur) : cinq mille alias
    # faisaient pendre le hook plusieurs secondes, et vingt mille une minute —
    # avant CHAQUE appel d'outil, avec les seules primitives de bash.
    affectations: dict[str, list[str]] = {}
    for motif in (_AFFECTATION_RE, _PRINTF_V_RE, _READ_RE):
        for nom, valeur in motif.findall(normalized):
            affectations.setdefault(nom, []).extend(valeur.split() or [""])
    def _prouve_inoffensif(depart: str, exige_une_affectation: bool) -> bool:
        """Suit la chaîne d'affectations et prouve que le nom lu est anodin."""
        vus: set[str] = set()
        a_suivre = [depart]
        while a_suivre and len(vus) < 512:
            cible = a_suivre.pop()
            if cible in vus:
                continue
            vus.add(cible)
            if _nom_sensible(cible):
                return False
            valeurs = affectations.get(cible)
            if not valeurs:
                # Aucune affectation visible : on ne peut RIEN prouver.
                return not exige_une_affectation
            for valeur in valeurs:
                if _VALEUR_OPAQUE_RE.search(valeur) or _nom_sensible(valeur):
                    return False
                if (suivant := valeur.lstrip("$").strip("{}")) != valeur:
                    a_suivre.append(suivant)
        return not a_suivre

    # INDIRECTION : bash lit la variable NOMMÉE par la valeur de `x`. Cette
    # valeur peut venir d'une boucle `for`, d'un `select`, d'un paramètre
    # positionnel, d'un `set --`, d'un argument de fonction, d'un `read` dans
    # un bloc… Énumérer ces mécanismes est sans fin : chaque round en a trouvé
    # de nouveaux. La charge de la preuve est donc INVERSÉE — on refuse à
    # moins de démontrer que le nom lu est anodin. La liste des indirections
    # inoffensives est courte et bornable ; celle des dangereuses ne l'est pas.
    for cible in indirections:
        if not _prouve_inoffensif(cible, exige_une_affectation=True):
            return cible
    # ALIAS : la cible est normalement écrite EN CLAIR, on peut la lire. Mais
    # `declare -n r=$1` la fait venir d'un paramètre positionnel, dont la
    # valeur est aussi inconnue que celle d'une indirection — et la brancher
    # sur la lecture directe la déclarait anodine faute d'affectation visible.
    for cible in alias:
        litteral = re.fullmatch(r"[A-Za-z_]\w*", cible) is not None
        if not _prouve_inoffensif(cible, exige_une_affectation=not litteral):
            return cible
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
    (r"\bfc\b(\s+-[lnrs]\S*)+(\s|$)",
     "`fc -l` liste l'historique de shell, comme `history`"),
    (r"\bhistory\b(\s|$)|\$HISTFILE\b", "l'historique de shell contient des secrets saisis"),
    (r"\.(bash|zsh|sh)_history\b", "l'historique de shell contient des secrets saisis"),
    # Une affectation ne fait normalement rien exécuter. Ces noms-là font
    # charger du code depuis un chemin que le hook ne peut pas lire : bash
    # source `BASH_ENV` avant tout `-c`, l'éditeur de liens charge `LD_PRELOAD`,
    # l'interpréteur exécute `PYTHONSTARTUP`. `BASH_ENV=/tmp/x bash -c :` passait
    # pour un préfixe d'affectation légitime suivi d'un no-op.
    (r"\b(BASH_ENV|SHELLOPTS|BASH_FUNC_\w*|LD_PRELOAD|LD_AUDIT|PYTHONSTARTUP|"
     r"PERL5OPT|RUBYOPT)\s*=\s*\S",
     "affectation qui fait exécuter du code depuis un chemin non analysable"),
    # `ENV=production` est un idiome courant : seule une valeur de CHEMIN fait
    # sourcer un fichier.
    (r"\$\{[^}]*@P\}",
     "l'expansion de prompt (`@P`) exécute les substitutions que la variable "
     "contient : son contenu n'est pas analysable avant exécution"),
    (r"\bprintf\s+(?:-\S+\s+)*-v\s+(PS[0-9]|PROMPT_COMMAND)\b",
     "construction d'une variable dont la valeur est exécutée comme une commande"),
    (r"\b(PROMPT_COMMAND|command_not_found_handle)\s*=\s*\S",
     "affectation d'une variable dont la valeur est exécutée comme une commande"),
    (r"\bPS[04]\s*=[^|;&\n]*(\$\(|`)",
     "affectation d'une variable dont la valeur est exécutée comme une commande"),
    (r"\bENV\s*=\s*[^\s|;&]*/",
     "affectation qui fait exécuter du code depuis un chemin non analysable"),
    (r"\bNODE_OPTIONS\s*=[^|;&\n]*(--require|--import|\s-r\b)",
     "affectation qui fait exécuter du code depuis un chemin non analysable"),
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


#: Expansion de paramètre à opérateur : `${VAR:-def}`, `${VAR##x}`, `${#VAR}`…
#: Le nom peut être POSITIONNEL (`${1:-x}`) ou spécial (`${@:-x}`) :
#: les exiger alphabétiques laissait passer `${1:-env}`, que bash exécute.
_EXPANSION_RE = re.compile(
    r"\$\{(?P<pre>#?)(?P<nom>[A-Za-z_]\w*|\d+|[@*])(?P<reste>[^}]*)\}")

#: Une expansion d'accolades : `{env,}`, `{p,}rintenv`, `c{ur,ur}l`.
_ACCOLADES_RE = re.compile(r"\{(?P<alts>[^{}$\s]*,[^{}$\s]*)\}")


#: Nombre total d'alternatives émises pour UN mot. Borner la seule profondeur
#: laissait le produit des alternatives exploser : `20` alternatives sur `5`
#: groupes faisaient pendre le hook plus de huit secondes — de quoi noyer un
#: agent sans écrire la moindre commande interdite.
_BUDGET_ACCOLADES = 64


def _expanser_mot(mot: str, profondeur: int = 0,
                  budget: list[int] | None = None) -> str:
    """Expanse un mot en TOUTES ses alternatives, comme bash.

    Ne garder que la plus longue était faux : `{curl,autrechose} http://tiers/`
    donne `curl autrechose http://tiers/` — curl s'exécute bel et bien.
    """
    if budget is None:
        budget = [_BUDGET_ACCOLADES]
    trouve = _ACCOLADES_RE.search(mot)
    if not trouve or profondeur > 4 or budget[0] <= 0:
        return mot
    alternatives = trouve.group("alts").split(",")
    budget[0] -= len(alternatives)
    avant, apres = mot[:trouve.start()], mot[trouve.end():]
    return " ".join(
        _expanser_mot(avant + alt + apres, profondeur + 1, budget)
        for alt in alternatives
    )


def _expanser_accolades(texte: str) -> str:
    """Expanse chaque MOT porteur d'une expansion d'accolades.

    Le découpage se fait sur les ESPACES. Chercher le mot autour de l'accolade
    (`\\S*\\{…\\}\\S*`) faisait rétro-traquer la regex à chaque position d'un mot
    long qui n'en contient aucune : vingt mille caractères coûtaient sept
    secondes, de quoi noyer un agent sans écrire une seule commande interdite.
    """
    budget = [_BUDGET_ACCOLADES]
    morceaux = re.split(r"(\s+)", texte)
    return "".join(
        mot if i % 2 or "{" not in mot or "," not in mot
        else _expanser_mot(mot, 0, budget)
        for i, mot in enumerate(morceaux)
    )


#: Opérateurs qui rendent SOIT la valeur de la variable, SOIT le texte de
#: repli : les deux branches doivent être analysées.
_OP_REPLI = (":-", ":=", ":?", "-", "=", "?")

#: Expansion de repli, telle qu'elle s'écrit dans la commande BRUTE.
_REPLI_RE = re.compile(r"\$\{#?(?:[A-Za-z_]\w*|\d+|[@*]):?[-=?]([^}]*)\}")


def _variante_repli(command: str) -> str | None:
    """La commande telle que bash l'exécute quand les variables sont vides.

    C'est une COMMANDE à part entière, analysée comme telle : substituer le
    repli dans le texte normalisé briserait les motifs de refus, qui décrivent
    une commande simple d'un bout à l'autre.
    """
    variante = command
    for _ in range(12):
        # Un appel ne résout qu'UN niveau : `${A:-${B:-${C:-env}}}` en demande
        # autant qu'il y a d'imbrications, et la limite de récursion de
        # `check_bash` s'épuisait avant.
        suivante = _REPLI_RE.sub(lambda m: m.group(1), variante)
        if suivante == variante:
            break
        variante = suivante
    return variante if variante != command else None


#: Toute expansion, quelle que soit sa forme. Bash en tire parfois le VIDE
#: (`${IFS//?/}` remplace tout par rien, `${V:0:0}` est une tranche nulle) :
#: les caractères autour se recollent alors en un nom de commande. Plutôt que
#: d'énumérer les formes provablement vides, on émet la lecture « tout est
#: vide » et on l'analyse comme une commande à part entière — même remède que
#: pour la branche « variable non définie ».
_EXPANSION_QUELCONQUE_RE = re.compile(r"\$\{[^{}]*\}|\$[A-Za-z_]\w*")


def _variante_vide(command: str) -> str | None:
    """La commande telle que bash l'exécute quand les expansions rendent vide."""
    variante = _EXPANSION_QUELCONQUE_RE.sub("", command)
    return variante if variante != command else None


def _reduire_expansion(m: re.Match[str]) -> str:
    """Ce que bash tire d'une expansion, sans jamais perdre le nom de variable."""
    nom, reste = m.group("nom"), m.group("reste")
    # `${VAR@P}` interprète le prompt, donc EXÉCUTE les substitutions que la
    # variable contient. Le réduire à `$VAR` faisait disparaître l'opérateur
    # avant que le motif de refus ne puisse le voir.
    if reste.startswith("@P"):
        return m.group(0)
    if nom == "IFS":
        # IFS vaut un SÉPARATEUR — sauf avec `+` ou `:+`, qui rendent le texte
        # de droite : `e${IFS:+nv}` reconstruit bel et bien `env`. Tout
        # remplacer par une espace faisait disparaître ce texte.
        if reste.startswith(":+"):
            return reste[2:]
        if reste.startswith("+"):
            return reste[1:]
        return " "
    if not reste and not m.group("pre"):
        return m.group(0)  # `${VAR}` simple : inchangé
    # `${VAR+texte}` et `${VAR:+texte}` valent le TEXTE littéral quand VAR est
    # définie — et `_` ou `PATH` le sont toujours : c'est ainsi que `${_+env}`
    # reconstruit `env`.
    if reste.startswith(":+"):
        return reste[2:]
    if reste.startswith("+"):
        return reste[1:]
    # Les formes de repli rendent ICI la référence seule. La branche « variable
    # vide », que bash EXÉCUTE, est analysée à part par `_variante_repli` :
    # injecter le repli dans le texte (fût-ce derrière un `;`) coupait la
    # classe `[^|;&]*` de TOUS les motifs de `DENY_COMMAND_PATTERNS`, et
    # `kubectl ${UNDEF-get} secret x` passait.
    return f"${nom}"


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
    # `${IFS}` et ses variantes à opérateur (`${IFS/a/b}`, `${IFS##x}`,
    # `${IFS%%x}`, `${IFS,,}`, `${IFS^^}`) valent toutes IFS, c'est-à-dire un
    # SÉPARATEUR : les remplacer par du vide souderait `env${IFS}printenv` en
    # un seul mot inexistant, et les deux programmes disparaîtraient.
    out = command
    # Les autres expansions à opérateur sont RÉDUITES à ce que bash en tire,
    # jamais supprimées : les effacer emportait le NOM de la variable, et
    # `echo ${AWS_SECRET_ACCESS_KEY:-x}` passait alors qu'il imprime la vraie
    # valeur. `${!nom}` est exclu — il reste visible pour le contrôle des
    # références indirectes.
    out = _EXPANSION_RE.sub(_reduire_expansion, out)
    # `{env,}`, `{p,}rintenv`, `c{ur,ur}l` : l'expansion d'accolades reconstruit
    # un nom de commande. Bash produit PLUSIEURS mots, préfixe et suffixe
    # recollés à chaque alternative — on fait de même.
    # Budget PARTAGÉ par toute la commande : un budget par mot laissait le
    # volume total exploser, et c'est la TAILLE du texte produit qui coûte
    # ensuite (dix secondes d'analyse sur un mot de quatre cents octets).
    out = _expanser_accolades(out)
    # Une référence collée AU MILIEU d'un mot ne sert qu'à le découper —
    # y compris sous forme indirecte (`e${!q}nv`).
    out = re.sub(r"(?<=\w)\$\{!?[A-Za-z_]\w*\}(?=\w)", "", out)
    out = out.replace("''", "").replace('""', "")
    out = re.sub(r"\[([^\]/])\]", r"\1", out)     # glob [o] → o
    # `\$` est un dollar LITTÉRAL : bash n'y voit aucune expansion. Le
    # réduire à `$` transformait `grep '\${!x}'` en une vraie indirection.
    out = out.replace("\\$", "")
    out = re.sub(r"\\(.)", r"\1", out)            # \e → e
    out = out.replace("'", "").replace('"', "")
    # Un `#` en tête de MOT ouvre un commentaire : bash ignore la fin de ligne.
    # Le garder faisait passer `env # rien` pour `env` exécutant `#rien`, donc
    # pour un préfixe d'exécution légitime. Collé à un mot (`rapport#2.txt`),
    # ce n'est pas un commentaire.
    out = re.sub(r"(?<![^\s])#[^\n]*", " ", out)
    return out


def _retire_definitions(texte: str) -> str:
    """Retire l'EN-TÊTE d'une définition de fonction ; c'est son corps qui porte
    les programmes.

    `fn() { env; }; fn` ne montrait que `fn` en position de programme, et
    l'analyse s'arrêtait là — sur un mot que rien ne reconnaît.

    Le nom est retiré en remontant depuis la parenthèse, jamais par une regex
    qui le chercherait à gauche : `[\\w-]+\\s*\\(\\s*\\)` rétro-traque à chaque
    position d'un mot long, ce qui coûtait quinze secondes sur vingt mille
    caractères.
    """
    texte = re.sub(r"\bfunction\s+\S+", " ", texte)
    if "(" not in texte:
        return texte
    sortie, fin = [], 0
    for m in re.finditer(r"\(\s*\)", texte):
        debut = m.start()
        while debut > fin and texte[debut - 1] in " \t":
            debut -= 1
        # Bash accepte presque tout dans un nom de fonction : `my.fn`, `a+b`,
        # `a@b`, `a/b`, `1fn`. Se limiter aux caractères de mot laissait le
        # reste du nom en position de programme, où rien ne le reconnaît, et
        # l'analyse s'arrêtait avant le corps.
        while debut > fin and texte[debut - 1] not in " \t\n|;&<>(){}\"'":
            debut -= 1
        sortie.append(texte[fin:debut])
        fin = m.end()
    sortie.append(texte[fin:])
    return " ".join(sortie)


def tokenize(command: str) -> list[list[str]]:
    """Découpe en commandes simples, sur une base tolérante aux erreurs.

    On ne cherche pas à réimplémenter bash : seulement à voir CHAQUE mot en
    position de programme, y compris derrière `bash -c`, `xargs`, `nohup` ou
    une substitution `$(...)`.
    """
    cleaned = _retire_definitions(normalize(command))
    # `case X in MOTIF) CMD;; esac` : la commande suit la parenthèse fermante,
    # et l'analyse s'arrêtait sur `case`. On ne reconnaît `case` qu'en POSITION
    # DE COMMANDE — sinon un message de commit contenant « case … in … » verrait
    # ses parenthèses coupées, et la prose redeviendrait du code.
    if re.search(r"(?:^|[|;&\n])\s*case\s+\S+\s+in\b", cleaned):
        cleaned = re.sub(r"(?:^|[|;&\n])\s*case\s+\S+\s+in\b", " ; ", cleaned)
        cleaned = cleaned.replace(")", " ; ")
    # `coproc NOM cmd` : le nom est FACULTATIF, donc `cmd` occupe tantôt la
    # première position, tantôt la seconde. On isole la suite en commande
    # propre : les deux lectures sont couvertes.
    cleaned = re.sub(r"\bcoproc\s+([A-Za-z_]\w*)\s+(?=\S)", r"coproc \1 ; ", cleaned)
    # `alias e=env` puis `e` sur une AUTRE ligne : bash développe l'alias (les
    # alias ne valent pas dans la ligne où ils sont définis, mais valent dans
    # les suivantes). La valeur est analysée comme une commande à part entière.
    valeurs = [m.group(1) for m in
               re.finditer(r"\balias\s+[A-Za-z_]\w*=(\S+)", cleaned)]
    cleaned += "".join(f" ; {v}" for v in valeurs)
    # La valeur de `env -S` est une COMMANDE, jamais un token — c'est pourquoi
    # `-S` n'est pas une « option à valeur ». Sa forme longue COLLÉE
    # (`--split-string=printenv CLE`) commençait par `-` : elle passait pour
    # une option ordinaire et le programme qu'elle porte disparaissait.
    cleaned = re.sub(r"\benv\s+(?:--split-string=?|-S)\s*", "env -S ", cleaned)
    # Un GROUPE de commandes (`{ env; }`) n'est pas un programme : son corps
    # l'est, et l'accolade arrêtait l'analyse sur un mot que rien ne reconnaît.
    # Les accolades ne sont retirées que là où bash y voit le mot réservé —
    # `{` suivi d'un blanc, `}` précédé d'un blanc ou d'un `;`. Les retirer
    # partout emportait le remplaçant de `xargs -I{}`, dont l'option avalait
    # alors le programme suivant.
    cleaned = re.sub(r"\{(?=\s)|(?<=[\s;])\}", " ", cleaned)
    cleaned = re.sub(r"[$`()]", " ", cleaned)
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
    "strace", "ltrace", "expect", "pwsh", "powershell",
    # `trap 'CMD' SIGNAL` fait exécuter CMD au signal ; `coproc CMD` la lance
    # en tâche de fond. Dans les deux cas l'argument est un PROGRAMME.
    "trap", "coproc",
    # `source f` et `. f` exécutent le CONTENU de `f`. Alimenté par une
    # substitution de processus (`source <(echo env)`), ce contenu n'existe
    # qu'à l'exécution : le marqueur se retrouve en position de programme et
    # la commande est refusée. Un chemin littéral, lui, reste autorisé —
    # écrire-puis-exécuter est un non-but assumé.
    "source", ".",
    "fish", "csh", "tcsh", "mksh", "oksh", "posh", "yash",
    "do", "then", "else", "elif", "while", "until", "if", "for",
})

#: Options d'enveloppe dont la valeur occupe le token SUIVANT. Sans elles,
#: `sudo -u root env` faisait passer `root` pour le programme et `env`
#: n'était jamais examiné. `-c` en est exclu : sa valeur EST la commande.
#: PAR ENVELOPPE : un jeu global ne peut pas être juste. `nice -n 10` prend une
#: valeur, `sudo -n` (non interactif) n'en prend pas — et sauter le token
#: suivant faisait disparaître le programme réel.
_OPT_AVEC_VALEUR: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "--user", "-g", "--group", "-p", "--prompt",
                       "-h", "--host", "-R", "--chroot", "-U", "--other-user",
                       "-D", "--chdir", "-C", "--close-from", "-r", "--role",
                       "-T", "--command-timeout"}),
    "doas": frozenset({"-u", "-C"}),
    "su": frozenset({"-s", "--shell", "-g", "--group"}),
    "runuser": frozenset({"-u", "--user", "-g", "--group", "-s", "--shell"}),
    "xargs": frozenset({"-a", "--arg-file", "-d", "--delimiter", "-E", "E",
                        "-I", "--replace", "-L", "-n", "--max-args",
                        "-P", "--max-procs", "-s", "--max-chars"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "--class", "-n", "--classdata", "-p", "--pid"}),
    "timeout": frozenset({"-k", "--kill-after", "-s", "--signal"}),
    "flock": frozenset({"-w", "--timeout", "-E", "--conflict-exit-code"}),
    "chroot": frozenset({"--userspec", "--groups"}),
    "nsenter": frozenset({"-t", "--target", "-S", "--setuid", "-G", "--setgid"}),
    "unshare": frozenset({"-S", "--map-user", "-G", "--map-group"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    # `-S` en est ABSENT à dessein : sa valeur est une COMMANDE entière
    # (`env -S "printenv CLE"`), pas un token. La sauter masquait le programme.
    "env": frozenset({"-u", "--unset", "-C", "--chdir"}),
    "systemd-run": frozenset({"-p", "--property", "-u", "--unit"}),
    # `exec -a xxx env` : `xxx` est l'argv[0], pas le programme.
    "exec": frozenset({"-a", "--argv0"}),
    "script": frozenset({"-f", "--flush", "-t", "--timing"}),
    "strace": frozenset({"-o", "--output", "-E", "-P", "-s"}),
    "ltrace": frozenset({"-o", "--output", "-e", "-l"}),
    "watch": frozenset({"-n", "--interval"}),
    "parallel": frozenset({"-j", "--jobs", "-S"}),
}

#: Enveloppes de BAC À SABLE et de trace. Leurs options prennent un nombre
#: variable de valeurs, si bien que le programme réel peut se trouver
#: n'importe où après elles : `bwrap --dev-bind / / env`,
#: `gdb --batch --ex run --args env`.
_WRAPPERS_OUVERTS = frozenset({
    "bwrap", "firejail", "systemd-nspawn", "valgrind", "gdb", "lldb",
    "setpriv", "chpst", "perf", "catchsegv", "proot", "unshare", "nsenter",
})

#: Enveloppes pour lesquelles `-c` introduit une COMMANDE.
_WRAPPERS_SHELL = frozenset({
    "sh", "bash", "zsh", "ksh", "dash", "su", "runuser", "busybox", "script",
    "toybox", "fish", "csh", "tcsh", "mksh", "oksh", "posh", "yash",
    "pwsh", "powershell", "machinectl", "systemd-run",
})

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
    # On ANALYSE la sous-commande, on ne se contente pas d'en marquer le
    # premier mot : `-exec sudo curl …` et `-exec env printenv …` masquaient
    # sinon le programme réel derrière une enveloppe.
    for i, tok in enumerate(tokens):
        if tok in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(tokens):
            positions += [i + 1 + j for j in _program_positions(tokens[i + 1:])]
    i = 0
    enveloppe = ""  # dernière enveloppe dépliée : ses options ont leur grammaire
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-"):
            i += 2 if tok in _OPT_AVEC_VALEUR.get(enveloppe, frozenset()) else 1
            continue
        if "=" in tok or _DUREE_RE.fullmatch(tok):
            # `D=$(ls)` : le marqueur est COLLÉ à l'affectation, donc dans le
            # même token — il n'y a rien à sauter de plus. `A=x $V`, lui,
            # laisse le marqueur dans un token SÉPARÉ, qui occupe bien une
            # position de programme.
            i += 1
            continue
        base = _basename(tok)
        if base == "command" and any(t in ("-v", "-V") for t in tokens[i + 1:]):
            break  # `command -v env` : introspection, rien n'est exécuté
        positions.append(i)
        if base in _WRAPPERS_OUVERTS:
            # Le programme réel peut être n'importe où après : aucune grammaire
            # d'options ne tient pour ces enveloppes.
            positions += [j for j in range(i + 1, len(tokens))
                          if not tokens[j].startswith("-") and "=" not in tokens[j]]
            break
        if base not in _WRAPPERS:
            break  # premier programme réel atteint : la suite, ce sont ses arguments
        enveloppe = base
        i += 1
        if base in _WRAPPERS_AVEC_CIBLE:
            # la CIBLE (verrou, répertoire) n'est pas le programme ; les
            # options qui la précèdent peuvent elles-mêmes prendre une valeur
            options = _OPT_AVEC_VALEUR.get(base, frozenset())
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 2 if tokens[i] in options else 1
            i += 1
    # `su root -c env` : l'utilisateur occupe la position de programme et
    # arrêtait l'analyse ; la valeur de `-c` est pourtant une commande.
    # Réservé aux enveloppes de type SHELL : pour `git`, `docker` ou `xargs`,
    # `-c` veut dire autre chose, et un message de commit citant `sh -c curl`
    # était refusé.
    if positions and _basename(tokens[positions[0]]) in _WRAPPERS_SHELL \
            and "-c" in tokens:
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
    # `bash -c env _` : la valeur de `-c` est le SCRIPT ENTIER ; ce qui suit
    # occupe `$0`, `$1`… et n'est PAS un argument du programme. Le quoting ayant
    # déjà été retiré, `bash -c env _` et `bash -c 'env _'` sont indiscernables
    # ici : on émet les DEUX lectures, comme pour les branches d'une expansion.
    if idx and tokens[idx - 1] == "-c" and suite \
            and any(_basename(t) in _WRAPPERS_SHELL for t in tokens[:idx]) \
            and _est_deversement(base, tokens[:idx + 1], idx):
        return True
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
    if base in ("declare", "typeset", "export"):
        # Les options courtes se COMBINENT : `-px` vaut `-p -x`, et l'égalité
        # stricte les ratait toutes.
        courtes = [t for t in options if not t.startswith("--")]
        # `-f` et `-F` portent sur les FONCTIONS : `declare -pF` ne liste que
        # des noms de fonctions, aucune valeur.
        if any(set(t.lstrip("-")) & {"f", "F"} for t in courtes):
            return False
        return not options or any(
            set(t.lstrip("-")) & {"p", "x"} for t in courtes)
    if _MARQUEUR_SUBSTITUTION in suite:
        # Le nom de la variable est produit à l'exécution : il peut être
        # n'importe lequel. Fail-closed.
        return True
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

#: Options qui font LIRE un fichier à une commande de métadonnées : elles la
#: sortent de sa catégorie (`stat --files0-from=~/.aws/credentials`).
_OPT_LIT_UN_FICHIER_RE = re.compile(r"--(files0-from|reference)\b")


#: Sous-commandes d'`openssl` purement locales : chiffrement, empreinte, tirage
#: aléatoire. Rien n'y sort sur le réseau — contrairement à `s_client`.
#: Inversé en DENYLIST : `openssl` a des dizaines de sous-commandes locales
#: (`help`, `list`, `ciphers`, `asn1parse`, `verify`, `dhparam`…) et en
#: énumérer la liste blanche revenait à refuser du travail légitime.
_OPENSSL_RESEAU = frozenset({"s_client", "s_server", "s_time", "ocsp"})

#: Sorties d'AIDE : elles n'ouvrent aucune connexion.
_OPT_AIDE = frozenset({"--version", "-V", "--help", "-h", "--manual", "help"})


def _est_usage_local(base: str, suite: list[str]) -> bool:
    """Invocation d'un binaire réseau qui n'ouvre aucune connexion."""
    hors_options = [t for t in suite if not t.startswith("-")]
    # Une option d'aide ne vaut que SEULE : `curl --version http://tiers/`
    # désarmait le contrôle alors que le comportement dépend du binaire.
    if not hors_options and any(t in _OPT_AIDE for t in suite):
        return True
    if base == "openssl":
        return bool(hors_options) and hors_options[0] not in _OPENSSL_RESEAU
    return False


def _metadata_seule(command: str) -> bool:
    """Commande simple UNIQUE dont le programme ne lit aucun contenu.

    L'unicité est essentielle : `ls ~/.ssh && cat ~/.ssh/id_rsa` doit rester
    refusé, et une substitution pourrait cacher n'importe quel lecteur.
    """
    normalized = normalize(command)
    if _NESTED_RE.search(normalized) or _OPT_LIT_UN_FICHIER_RE.search(normalized):
        return False
    commandes = tokenize(command)
    if len(commandes) != 1:
        return False
    positions = _program_positions(commandes[0])
    return bool(positions) and all(
        _basename(commandes[0][i]) in _METADATA_PROGRAMS for i in positions)


#: Corps d'un heredoc CITÉ (`<<'FIN'`) : bash n'y interprète ni substitution
#: ni variable. C'est de la DONNÉE — sauf s'il alimente un interpréteur, qui
#: l'exécute.
_HEREDOC_CITE_RE = re.compile(
    r"<<-?\s*(['\"])(?P<mark>[A-Za-z_]\w*)\1(?P<corps>.*?)^\s*(?P=mark)\s*$",
    re.S | re.M,
)

_INTERPRETES = frozenset({
    "sh", "bash", "zsh", "ksh", "dash", "python", "python2", "python3",
    "pypy", "pypy3", "ipython", "ipython3", "bpython",
    "perl", "perl6", "raku", "ruby", "irb",
    "node", "deno", "bun", "php", "lua", "tclsh", "awk", "gawk", "mawk",
    "Rscript", "julia", "psql", "mysql", "sqlite3", "expect", "swift",
    "groovy", "kotlin", "kotlinc", "scala", "elixir", "iex", "erl",
    "crystal", "guile", "scheme", "racket", "clojure", "bb",
    "pwsh", "powershell", "fish", "csh", "tcsh", "mksh", "oksh", "posh",
    "yash", "elvish", "xonsh", "nu",
})


#: Interpréteurs qui ne sont PAS des shells. La distinction compte : le corps
#: livré à un shell est une suite de commandes, que le découpage aux sauts de
#: ligne traite correctement ; celui livré à un langage est du code, où un saut
#: de ligne ne sépare rien — `os.system(…)` doit rester dans le même segment
#: que l'interpréteur pour être vu.
_LANGAGES = frozenset({
    "python", "python2", "python3", "pypy", "pypy3", "ipython", "ipython3",
    "bpython", "perl", "perl6", "raku", "ruby", "irb", "node", "deno", "bun",
    "php", "lua", "tclsh", "awk", "gawk", "mawk", "Rscript", "julia", "expect",
    "swift", "groovy", "kotlin", "kotlinc", "scala", "elixir", "iex", "erl",
    "crystal", "guile", "scheme", "racket", "clojure", "bb",
})
_ALT_LANGAGES = "|".join(sorted(_LANGAGES, key=len, reverse=True))

#: Programme livré à un interpréteur AUTREMENT qu'en ligne : here-string
#: (`python3 <<< 'code'`) ou heredoc (`python3 <<EOF … EOF`). Bash le pousse sur
#: l'entrée standard et l'interpréteur l'exécute — exactement comme `-c`.
#: L'option est bornée à ce qui ne prend pas de valeur : `python3 script.py
#: <<EOF` alimente le script en DONNÉES, il ne reçoit pas de programme. Le
#: tiret NU en fait partie — `python3 - <<EOF` demande explicitement à lire
#: le programme sur l'entrée standard. Les options à VALEUR (`-X dev`,
#: `-W default`, `-I lib`) sont reconnues : les ignorer coupait la chaîne,
#: et l'interpréteur n'était plus vu comme recevant un programme.
_PROGRAMME_HERESTRING_RE = re.compile(
    rf"\b(?P<interp>{_ALT_LANGAGES})\b(?P<opts>(?:\s+(?:-[XWIMmrEK]\s+\S+|-[\w-]*))*)\s*"
    r"<<<\s*(?P<corps>'[^']*'|\"[^\"]*\"|\S+)")
_PROGRAMME_HEREDOC_RE = re.compile(
    rf"\b(?P<interp>{_ALT_LANGAGES})\b(?P<opts>(?:\s+(?:-[XWIMmrEK]\s+\S+|-[\w-]*))*)\s*"
    r"<<-?\s*(?P<q>['\"]?)(?P<mark>[A-Za-z_]\w*)(?P=q)[^\n]*\n"
    r"(?P<corps>.*?)^\s*(?P=mark)\s*$",
    re.S | re.M)


def _canonise_programme(command: str) -> str:
    """Ramène à la forme EN LIGNE un programme livré par heredoc ou here-string.

    Tout le contrôle du code d'interpréteur est adossé au drapeau `-c`/`-e` ;
    livré sur l'entrée standard, le même code n'était analysé que comme du
    shell, où `os.system("env")` n'est qu'un mot parmi d'autres.
    """
    def _remplace(m: re.Match[str]) -> str:
        # Les sauts de ligne d'un programme ne séparent pas des commandes :
        # les garder plaçait la primitive dans un segment sans interpréteur.
        corps = m.group("corps").strip("'\"").replace("\n", " ")
        return f"{m.group('interp')}{m.group('opts')} -c {corps} "

    return _PROGRAMME_HERESTRING_RE.sub(
        _remplace, _PROGRAMME_HEREDOC_RE.sub(_remplace, command))


def _neutralise_heredocs(command: str) -> str:
    """Retire le corps des heredocs cités qui ne sont pas exécutés.

    L'analyser comme du code refusait tout texte contenant des backticks
    markdown — pris pour des substitutions — alors que `cat <<'FIN' > f` ne
    fait qu'écrire un fichier.
    """
    def _remplace(m: re.Match[str]) -> str:
        tete = re.split(r"[|;&\n]", command[:m.start()])[-1]
        # Ce qui SUIT le marqueur sur la même ligne consomme le corps :
        # `cat <<'FIN' | bash` exécute bel et bien ce que le heredoc contient,
        # et ne regarder que la tête (`cat`) le rendait invisible.
        suite = m.group("corps").split("\n", 1)[0]
        # Découpage sur les opérateurs AVANT les espaces : `<<'FIN' |bash`
        # (pipe collé) donnait le token `|bash`, introuvable parmi les
        # interpréteurs, et le corps était retiré alors qu'il est exécuté.
        mots = re.split(r"[|;&<>()]+|\s+", f"{tete} {suite}")
        if {_basename(t) for t in mots if t} & _INTERPRETES:
            return m.group(0)  # le corps EST exécuté : on le garde
        return f"<<{m.group('mark')}\n{m.group('mark')}\n"

    return _HEREDOC_CITE_RE.sub(_remplace, command)


def check_bash(command: str, _profondeur: int = 0) -> str | None:
    command = _canonise_programme(_neutralise_heredocs(command))
    # La branche « variable vide » d'une expansion de repli est une commande
    # complète : on l'analyse entière, pas par morceaux.
    if _profondeur < 4:
        for variante in (_variante_repli(command), _variante_vide(command)):
            if variante and (reason := check_bash(variante, _profondeur + 1)):
                return reason
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
    if _INLINE_ENV_RE.search(normalized) or (
            _interprete_execute(normalized)
            and _CODE_ENV_RE.search(normalized)):
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
        for motif, signaux in _SOUS_COMMANDES_RE:
            for m in motif.finditer(normalized):
                sous = _sous_commande(m.group(1), signaux)
                # DEUX lectures : le quoting est déjà retiré, on ne sait pas si
                # la sous-commande tient en un mot (`-C env`, suivi des options
                # de mapfile) ou les prend tous (`-C 'sh -c env'`). N'en émettre
                # qu'une laissait passer l'autre.
                for lecture in {sous, sous.split(" ")[0] if sous else ""}:
                    if lecture and (reason := check_bash(lecture, _profondeur + 1)):
                        return reason
        for interne in _regions_imbriquees(normalized):
            if (reason := check_bash(interne, _profondeur + 1)):
                return reason

    # Ce qui suit une primitive d'exécution est une commande, même sans
    # parenthèses pour la délimiter. Réservé au CODE donné en ligne : sans
    # cette porte, `git commit -m 'fix subprocess.run for curl backend'`
    # était refusé — la prose redevenait du code, précisément le défaut que
    # la séparation avait éliminé. Les formes PARENTHÉSÉES restent couvertes
    # partout par `_NESTED_RE`.
    for segment in re.split(r"[|&\n]+", normalized):
      for appel in (_APPEL_EXEC_RE.finditer(segment)
                    if _interprete_execute(segment) else ()):
        mots = _MOTS_DE_CODE_RE.findall(appel.group("args") or appel.group("pcx") or "")
        for idx, mot in enumerate(mots):
            base = _basename(mot)
            if base in ENV_DUMP_PROGRAMS and _est_deversement(base, mots, idx):
                return "déversement de l'environnement depuis un interpréteur"
            if base in NETWORK_CAPABLE:
                return f"`{base}` appelé depuis un interpréteur : contourne le proxy (D9)"

    # Toute région imbriquée — substitution du shell comme appel de langage —
    # est RETIRÉE de la commande englobante après analyse : ses mots n'y sont
    # pas des arguments, et son résultat n'est pas connu d'avance.
    # Le marqueur n'est PAS entouré d'espaces : il doit rester COLLÉ là où la
    # substitution l'était. Les entourer rendait `A=x $V` (deux mots, le
    # second est le programme) identique à `A=x$V` (un seul mot, une valeur
    # d'affectation) — et l'exception faite pour la seconde couvrait la
    # première, qui exécute bel et bien.
    # Une substitution en ÉCRITURE (`> >(cmd)`) désigne une DESTINATION, pas un
    # programme : son consommateur est analysé à part.
    exterieur = _NESTED_RE.sub(
        lambda m: (" destination_de_flux "
                   if m.group(0).startswith(">") else _MARQUEUR_SUBSTITUTION),
        normalized)
    exterieur = _par_segment(
        exterieur,
        lambda seg: (_APPEL_LANGAGE_RE.sub(_MARQUEUR_SUBSTITUTION, seg)
                     if _interprete_execute(seg) else seg),
    )
    # Une variable en position de programme est opaque (`$SHELL -c env`).
    exterieur = _REF_SIMPLE_RE.sub(_MARQUEUR_SUBSTITUTION, exterieur)

    for tokens in tokenize(exterieur):
        # Le marqueur peut être COLLÉ à d'autres caractères (`a$(cmd)b`) :
        # l'appartenance exacte ne le voyait plus une fois le padding retiré.
        opaque = any(_MARQUEUR_SUBSTITUTION in t for t in tokens)
        for idx in _program_positions(tokens):
            base = _basename(tokens[idx])
            if _MARQUEUR_SUBSTITUTION in base:
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
        # Le nom du champ n'est pas prévisible (`exec`, `program`,
        # `bash_command`, `pipeline`…) : une liste blanche en ratait la
        # moitié. On inspecte TOUTES les valeurs, sauf `prompt` — c'est de la
        # prose, et l'analyser comme une commande refusait tout texte contenant
        # des backticks markdown. Le sous-agent qu'un prompt pilote a son
        # propre PreToolUse : ses commandes sont gardées à l'exécution.
        if reason is None and isinstance(payload, dict):
            for champ, valeur in payload.items():
                if champ == "prompt" or valeur is None:
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
