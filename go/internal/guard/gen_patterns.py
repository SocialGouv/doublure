#!/usr/bin/env python3
"""Generate the Go pattern tables from the Python hook — one source of truth.

Run with:  uv run python go/internal/guard/gen_patterns.py

## Why generate rather than retype

Two reasons, and the second is the one that matters.

The trivial one: the hook refuses to let an agent WRITE a file quoting the
paths it protects, so porting it by hand is impossible without composing every
literal. That is friction, not an argument.

The real one: a pattern list that exists twice diverges. This project already
settled that for the allowlist — "it is the list that matters, not the code
that reads it" — and the same holds here. Until the Python side is retired,
the patterns live in ONE place and Go reads them from there.

## Lookaround cannot be lost silently

RE2 has no lookaround; the Python patterns use it in twelve places. This
generator STRIPS each assertion and records what it stripped. A stripped
pattern must have a named verifier on the Go side (`verifiers` below); if it
does not, generation FAILS rather than emitting a weaker rule.

That is the whole safety property of this file: you cannot drop a condition by
accident, only by editing this list and saying so.
"""
from __future__ import annotations

import ast
import inspect
import re
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "hooks"))

import pretooluse_guard as py  # noqa: E402

#: Patterns whose lookaround is re-implemented in Go, by verifier name.
#: A pattern that loses an assertion and is NOT listed here aborts generation.
#: (fragment expected in the ASSERTION, fragment of the PATTERN, Go verifier).
#:
#: Keying on the assertion alone is not enough: the two `.env` rules share the
#: SAME template exclusion, so the pattern disambiguates. Keying on the pattern
#: alone was worse — it attached `sshPrivate` to `print-identity-token` and
#: `envFile` to `.envrc`, neither of which has any lookaround.
VERIFIERS: list[tuple[str, str, str]] = [
    # JavaScript `process.env` / `import.meta.env` is code, not a secrets file;
    # and the variant suffix must not name a public template.
    ("(?<!process)", "", "envFile"),
    # `env.production` (Compose convention), same template exclusion.
    ("(example|sample|template", ")env\\.", "envDotFile"),
    # `terraform output -json NAME` asks for ONE output and is allowed.
    ("-json", "", "terraformOutput"),
    # reading or setting the commit identity is ordinary.
    ("user\\.(name|email)", "", "gitConfig"),
    # a public key file is not a private one, and the assertion sits on the
    # extension: only the suffix decides.
    ("\\.pub", "", "sshPrivateExcludingPub"),
]

#: How many patterns are EXPECTED to lose an assertion. A new lookaround in
#: the Python source changes this number, and generation stops until someone
#: has looked at it — the point is that lookaround never appears unnoticed.
LOOKAROUND_ATTENDUS = 5

_LOOKAROUND = re.compile(r"\(\?<?[=!][^()]*(?:\([^()]*\)[^()]*)*\)")
_INLINE_FLAGS = re.compile(r"\(\?-?[aiLmsux]+:")


def strip_lookaround(pattern: str) -> tuple[str, list[str], list[int]]:
    """Replace each lookaround by an empty MARKER group, at its own place.

    The marker records WHERE the assertion stood, so the Go verifier reads the
    text at that exact position instead of counting back from a group
    boundary. That counting is what made `envDotFile` read the closing
    delimiter instead of the suffix — a rule that blocked `env.sample`, which
    Python allows.

    The group NUMBER is read from Python's own parser rather than by counting
    parentheses here: miscounting them is the same defect one level down.
    """
    removed: list[str] = []

    def take(match: re.Match[str]) -> str:
        removed.append(match.group(0))
        return f"(?P<mark{len(removed) - 1}>)"

    marked = _LOOKAROUND.sub(take, pattern)
    if not removed:
        return marked, [], []
    try:
        index = re.compile(marked).groupindex
    except re.error as err:
        raise SystemExit(f"ABANDON : le motif {pattern!r} privé de ses "
                         f"assertions ne compile plus ({err}).")
    return marked, removed, [index[f"mark{i}"] for i in range(len(removed))]


def to_re2(pattern: str) -> str:
    """Python regex → RE2 source, or raise if the difference is not mechanical."""
    # Python's `(?-i:…)` disables case folding for a group; RE2 spells it
    # `(?-i:…)` too, so only the unsupported constructs need care.
    out = pattern
    if "(?P<" in out:
        out = re.sub(r"\(\?P<\w+>", "(", out)
    if "\\Z" in out or "(?#" in out:
        raise ValueError(f"construction non portable : {pattern!r}")
    return out


def verifier_for(removed: list[str], pattern: str) -> str:
    """Choisi sur l'ASSERTION retirée, jamais sur le motif entier.

    Chercher dans le motif attachait `sshPrivate` à
    `print-identity-token` et `envFile` à `.envrc` — deux règles qui n'ont
    aucun lookaround. Un vérificateur inutile n'affaiblit rien ici, mais il
    ment sur ce que la règle fait.
    """
    for assertion in removed:
        for besoin_assertion, besoin_motif, name in VERIFIERS:
            if besoin_assertion in assertion and besoin_motif in pattern:
                return name
    return ""


def verifier_or_abort(removed: list[str], pattern: str) -> str:
    """Le vérificateur nommé d'un motif amputé, ou l'arrêt de la génération."""
    verifier = verifier_for(removed, pattern)
    if not verifier:
        raise SystemExit(
            f"ABANDON : le motif {pattern!r} perd {removed!r} et n'a aucun "
            f"vérificateur. Ajouter une entrée à VERIFIERS et l'implémenter "
            f"en Go, ou la règle sortirait AFFAIBLIE.")
    return verifier


def _corps(nom: str) -> ast.FunctionDef:
    """L'AST d'une fonction du hook, lu depuis sa propre source."""
    return ast.parse(textwrap.dedent(inspect.getsource(getattr(py, nom)))).body[0]


def _seul(trouves: list[str], quoi: str, ou: str) -> str:
    if len(trouves) != 1:
        raise SystemExit(
            f"ABANDON : {len(trouves)} {quoi} dans {ou}(), 1 attendu. La forme "
            f"de la fonction a changé — relire ce qu'elle fait AVANT d'adapter "
            f"l'extraction.")
    return trouves[0]


def literal_regex(nom: str) -> str:
    """Le motif écrit EN LIGNE dans une fonction du hook.

    N'étant pas une constante de module, il ne se lit pas comme un attribut :
    la source est analysée plutôt que le motif retapé, parce qu'un motif qui
    existe deux fois diverge — c'est la prémisse de ce fichier.
    """
    trouves = [n.args[0].value for n in ast.walk(_corps(nom))
               if isinstance(n, ast.Call)
               and isinstance(n.func, ast.Attribute)
               and n.func.attr in ("search", "match", "compile")
               and n.args and isinstance(n.args[0], ast.Constant)
               and isinstance(n.args[0].value, str)]
    return _seul(trouves, "motif(s) littéral(aux)", nom)


def reason_of(nom: str) -> str:
    """La raison qu'une fonction du hook renvoie quand elle refuse."""
    trouves = [n.value.value for n in ast.walk(_corps(nom))
               if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)
               and isinstance(n.value.value, str)]
    return _seul(trouves, "raison(s)", nom)


def emit_regex(name: str, pattern: str, verifier_var: str = "") -> str:
    """Un motif isolé, avec son assertion réimplémentée s'il en avait une."""
    stripped, removed, marks = strip_lookaround(pattern)
    lines = [f"var {name} = regexp.MustCompile({go_quote(to_re2(stripped))})"]
    if removed:
        emit.vus += 1
        # Un simple commentaire laisserait la fonction Go disparaître sans que
        # la compilation le voie : la référencer fait porter l'obligation au
        # compilateur.
        lines += ["",
                  f"// lookaround réimplémenté : {' '.join(removed)}",
                  f"var {verifier_var} = {verifier_or_abort(removed, pattern)}",
                  f"var {verifier_var}Marks = []int{{{', '.join(map(str, marks))}}}"]
    return "\n".join(lines)


def emit(name: str, entries: list[tuple[str, str]]) -> str:
    """entries: (pattern, reason). reason may be empty."""
    # Compteur porté par la fonction : le total se vérifie après coup.
    lines = [f"var {name} = []rule{{"]
    for pattern, reason in entries:
        stripped, removed, marks = strip_lookaround(pattern)
        verifier = ""
        if removed:
            emit.vus += 1
            verifier = verifier_or_abort(removed, pattern)
        go_pattern = to_re2(stripped)
        lines.append(f"\t{{")
        lines.append(f"\t\tre: regexp.MustCompile({go_quote(go_pattern)}),")
        if verifier:
            lines.append(f"\t\tverify: {verifier},")
            lines.append(f"\t\tmarks: []int{{{', '.join(map(str, marks))}}},")
            lines.append(f"\t\t// lookaround réimplémenté : {' '.join(removed)}")
        if reason:
            lines.append(f"\t\treason: {go_quote(reason)},")
        lines.append("\t},")
    lines.append("}")
    return "\n".join(lines)


def gofmt(source: str) -> str:
    """Format the emitted Go — and, doing so, PARSE it.

    gofmt refuses source it cannot parse, so a malformed emission stops here
    instead of being written and discovered at build time.
    """
    fini = subprocess.run(["gofmt"], input=source, capture_output=True,
                          text=True)
    if fini.returncode:
        raise SystemExit(f"ABANDON : le Go émis ne se lit pas — "
                         f"{fini.stderr.strip()}")
    return fini.stdout


def go_quote(s: str) -> str:
    """Go raw string when possible — a regex is unreadable once escaped."""
    if "`" not in s:
        return "`" + s + "`"
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


emit.vus = 0


def main() -> int:
    # `re.I` is applied by the Python caller, not carried in the pattern.
    vault = [(f"(?i){p}", "") for p in py.VAULT_PATTERNS]
    files = [(f"(?i){p}", "") for p in py.SENSITIVE_FILE_PATTERNS]
    deny = [(f"(?i){p}", reason) for p, reason in py.DENY_COMMAND_PATTERNS]

    # L'exemption ssh est sensible à la CASSE côté Python : lui ajouter `(?i)`
    # élargirait ce qui est exempté, la seule direction qui fuit.
    exemption = "\n\n".join((
        emit_regex("sshPublicRe", py._SSH_PUBLIC_RE.pattern),
        emit_regex("sshPrivateRe", literal_regex("check_sensitive_files"),
                   "sshPrivateVerify"),
    ))
    raisons = "\n".join((
        "const (",
        f"\tvaultReason         = {go_quote(reason_of('check_vault_access'))}",
        f"\tsensitiveFileReason = {go_quote(reason_of('check_sensitive_files'))}",
        ")",
    ))

    corps = f'''// Code generated by gen_patterns.py — DO NOT EDIT.
//
// The patterns come from the Python hook, which stays the single source of
// truth until it is retired. Regenerate with:
//
//	uv run python go/internal/guard/gen_patterns.py
//
// Lookaround assertions were stripped (RE2 has none) and re-implemented as
// named verifiers in patterns.go. The generator ABORTS if a pattern loses an
// assertion without a verifier, so a condition cannot be dropped silently.
package guard

import "regexp"

// rule is a pattern plus the conditions RE2 cannot express.
//
// marks holds the capture-group number of each stripped assertion, in the
// order they appeared. The group matches empty AT the assertion's position, so
// a verifier reads the text exactly where the assertion looked instead of
// counting characters back from a group boundary.
type rule struct {{
	re     *regexp.Regexp
	verify func(text string, loc, marks []int) bool
	marks  []int
	reason string
}}

{raisons}

// Files of the ssh key directory that are PUBLIC by nature: refusing them
// stopped an agent from listing a fingerprint or reading a known-hosts file.
{exemption}

{emit("vaultRules", vault)}

{emit("sensitiveFileRules", files)}

{emit("denyRules", deny)}
'''
    if emit.vus != LOOKAROUND_ATTENDUS:
        raise SystemExit(
            f"ABANDON : {emit.vus} motif(s) à lookaround, "
            f"{LOOKAROUND_ATTENDUS} attendu(s). Un lookaround est apparu ou a "
            f"disparu côté Python — vérifier ce qu'il faisait AVANT de mettre "
            f"LOOKAROUND_ATTENDUS à jour.")
    cible = Path(__file__).parent / "patterns_gen.go"
    cible.write_text(gofmt(corps), encoding="utf-8")
    print(f"écrit {cible} — {len(vault)} coffre, {len(files)} fichiers, "
          f"{len(deny)} commandes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
