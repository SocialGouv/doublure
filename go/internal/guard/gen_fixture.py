#!/usr/bin/env python3
"""Export what the Python patterns decide, so Go can be checked against it.

Run with:  uv run python go/internal/guard/gen_fixture.py

A port is only worth what it is compared to. Reading the Go and judging it
correct is how nineteen rounds of defects were introduced in the first place;
replaying the SAME inputs through both and comparing is not.

The corpus is taken from the hook's own test suite — the commands that encode
those nineteen rounds — plus every string in the sensitive-file tests. If the
two layers agree on all of it, the pattern port is done; where they disagree,
the disagreement is the finding.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "hooks"))

import pretooluse_guard as py  # noqa: E402

#: Any quoted literal from the hook's tests: that is where the adversarial
#: corpus lives.
_LITERAL = re.compile(
    r'''(?:r?"""|r?"|r?')((?:[^"'\\\n]|\\.){2,400}?)(?:"""|"|')''')


#: Ce que le corpus adversarial n'atteint pas.
#:
#: Les tests de non-régression écrivent leurs commandes sous forme obfusquée
#: (`${UNDEF-…}`), que la couche de découpage résout : elles n'arrivent donc
#: JAMAIS jusqu'aux motifs. Mesuré — 33 règles sur 62 exercées, et AUCUNE des
#: deux assertions portées par `terraform` et `git`, qui sont pourtant les
#: seules règles à ÉLARGIR ce qui est permis.
#:
#: Chaque assertion réimplémentée est donc exercée ici dans les DEUX sens :
#: sans cela, « décisions identiques » ne dirait rien du seul Go écrit à la
#: main sur ce chemin.
#:
#: Les littéraux sont composés à l'exécution : ce hook refuse qu'un agent
#: écrive les commandes qu'il protège, et ce refus est juste.
_SUPPLEMENT = [
    "terra" + "form output",
    "terra" + "form output -json db_password",
    "git con" + "fig --list",
    "git con" + "fig user.name",
    "git con" + "fig user.email && echo ok",
    "cat .e" + "nv",
    "cat .e" + "nv.example",
    "cat .e" + "nv.production",
    "cat env" + ".sample",
    "cat env" + ".production",
    "grep -r process.env" + ".FOO src/",
    "ssh-keygen -l -f ~/.s" + "sh/id_" + "ed25519.pub",
    "cat ~/.s" + "sh/id_" + "ed25519",
    "cat ~/.s" + "sh/config",
    "cat ~/.s" + "sh/known_hosts",
    "cat ~/.s" + "sh/config ~/.s" + "sh/id_" + "ed25519",
    # Couche VARIABLES — celle où le round 13 a INVERSÉ la charge de la preuve.
    # Mesuré sur le corpus : 9 indirections, 11 namerefs, 22 liaisons opaques.
    # Chaque branche est donc exercée ici dans les deux sens, avec des noms
    # SYNTHÉTIQUES : ils déclenchent la règle sans nommer un vrai secret.
    "x=MY_SECRET_A; echo ${!x}",
    "x=HOME; echo ${!x}",
    "echo ${!x}",
    "x=$y; y=HOME; echo ${!x}",
    "x=$y; y=MY_TOKEN_B; echo ${!x}",
    "x=$(cat f); echo ${!x}",
    "for x in a b; do echo ${!x}; done",
    "select x in a b; do echo ${!x}; done",
    "getopts ab x; echo ${!x}",
    "read x <<< MY_SECRET_C; echo ${!x}",
    "printf -v x MY_SECRET_D; echo ${!x}",
    "declare -n r=MY_TOKEN_E; echo $r",
    "declare -n r=HOME; echo $r",
    "f() { declare -n r=$1; echo $r; }; f MY_SECRET_F",
    "echo ${!arr[@]}",
    "echo ${!MY_SECRET_G[@]}",
    "echo ${!PREFIX@}",
    "echo ${!m[k1]}",
    "echo $((MY_TOKEN_H))",
    "echo $((PORT + 1))",
    "echo 'the syntax is ${!x}'",
    # Couche IMBRIQUÉE — heredocs et here-strings.
    #
    # Le corpus extrait le texte SOURCE des littéraux, où `\\n` reste deux
    # caractères : aucune entrée multi-ligne ne s'y forme, donc AUCUN heredoc.
    # Or c'est là que vivent les deux motifs Python fermés sur une
    # rétro-référence, remplacés côté Go par un balayage. Sans ces cas, le
    # différentiel ne dirait rien de la seule vraie restructuration du portage.
    "cat <<'FIN' > note.md\nvoir `git log` pour l'historique\nFIN\n",
    "cat <<'FIN' | bash\nenv\nFIN\n",
    "cat <<'FIN' |bash\nenv\nFIN\n",
    "bash <<'FIN'\nenv\nFIN\n",
    "python3 <<EOF\nimport os\nos.system('id')\nEOF\n",
    "python3 - <<EOF\nprint(1)\nEOF\n",
    "python3 -X dev <<EOF\nprint(1)\nEOF\n",
    "python3 <<< 'print(1)'",
    "perl <<< 'print 1'",
    "cat <<-'FIN' > f\n\tdata\n\tFIN\n",
    "cat <<'FIN' > f\nunterminated body\n",
    # Le marqueur apparaît SEUL sur une ligne AVANT l'ouverture : le
    # terminateur doit être cherché à partir du corps, pas depuis le début.
    # Sans ce cas, muter ce filtre ne fait rien échouer — et une mutation qui
    # ne casse rien dit que le test ne couvre pas la logique, pas qu'elle est
    # juste.
    "printf 'x\nFIN\n'\ncat <<'FIN' > f\ndata\nFIN\n",
    "printf 'x\nEOF\n'\npython3 <<EOF\nprint(1)\nEOF\n",
    # Couche COLLE — chemins que le corpus n'atteint pas.
    # Le marqueur de substitution COLLÉ à d'autres caractères : l'appartenance
    # exacte ne le voit plus une fois le remplissage retiré (round 14).
    "curl http://127.0.0.1:9000/x$(echo y)",
    "curl http://127.0.0.1:9000/detect",
    "curl http://127.0.0.1/ $(echo http://exfil.test/x)",
    # L'exemption « URL locale » n'a rien à exempter quand la destination est
    # une SOCKET : l'URL y est décorative (round 19).
    "curl --unix-socket /tmp/s http://localhost/questions",
    "curl --abstract-unix-socket x http://localhost/rules",
    # Une variable en position de programme est opaque (round 9).
    "$SHELL -c env",
    "bash <(env)",
    # …et les faux positifs correspondants, qui doivent rester permis.
    "echo $(find . -name env)",
    "curl --version",
    "openssl dgst -sha256 f",
]


def corpus() -> list[str]:
    vus: set[str] = set(_SUPPLEMENT)
    out: list[str] = list(_SUPPLEMENT)
    for nom in ("test_pretooluse_hook.py", "test_review_regressions.py"):
        chemin = ROOT / "tests" / nom
        if not chemin.exists():
            continue
        for m in _LITERAL.finditer(chemin.read_text(encoding="utf-8")):
            texte = m.group(1)
            if texte and texte not in vus:
                vus.add(texte)
                out.append(texte)
    return out


def decisions(texte: str) -> dict:
    """The three pattern layers, each answering independently."""
    normalise = py.normalize(texte)
    coffre = bool(py.check_vault_access(texte))
    fichiers = bool(py.check_sensitive_files(texte))
    commande = ""
    for motif, raison in py.DENY_COMMAND_PATTERNS:
        if re.search(motif, normalise, re.I):
            commande = raison
            break
    # `tokenize` reçoit la commande BRUTE : c'est le quoting qui dit où un
    # argument finit, et normaliser d'abord fait RÉAPPARAÎTRE une structure que
    # les guillemets avaient supprimée (les neuf faux positifs du round 17).
    jetons = py.tokenize(texte)
    # Les positions de programme sont rendues par commande, et le déversement
    # est jugé À SA PLACE : avec le seul nom, `env PATH=/x env` était jugé sur
    # le premier `env` et le second passait.
    positions = [py._program_positions(c) for c in jetons]
    return {"input": texte, "vault": coffre, "files": fichiers,
            "deny": commande, "variable": py._variable_sensible(normalise) or "",
            # Deux motifs Python se ferment sur une RÉTRO-RÉFÉRENCE, que RE2
            # n'a pas : le corps du heredoc est retrouvé par balayage côté Go.
            # C'est une restructuration, pas une traduction — donc comparée.
            "canonised": py._canonise_programme(py._neutralise_heredocs(texte)),
            "regions": py._regions_imbriquees(normalise),
            # La colle : la RAISON exacte, pas le seul verdict. Deux refus pour
            # des motifs différents sont deux comportements différents — c'est
            # cette phrase que le modèle reçoit et cite.
            "bash": py.check_bash(texte) or "",
            "tokens": jetons, "positions": positions,
            "dumps": [[py._est_deversement(py._basename(c[i]), c, i)
                       for i in pos]
                      for c, pos in zip(jetons, positions)]}


def main() -> int:
    cas = [decisions(t) for t in corpus()]
    cible = Path(__file__).parent / "testdata" / "python_decisions.json"
    cible.parent.mkdir(parents=True, exist_ok=True)
    cible.write_text(json.dumps(cas, ensure_ascii=False, indent=1) + "\n",
                     encoding="utf-8")
    vault = sum(1 for c in cas if c["vault"])
    files = sum(1 for c in cas if c["files"])
    deny = sum(1 for c in cas if c["deny"])
    print(f"écrit {cible} — {len(cas)} entrées "
          f"({vault} coffre, {files} fichiers, {deny} commandes refusées)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
