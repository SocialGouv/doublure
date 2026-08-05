"""A/B : le découpage par GRAMMAIRE contre les heuristiques du hook.

Outil de DÉ-RISQUE, pas un test : il ne juge pas, il CLASSE les
divergences pour qu'aucune ne soit remplacée sans être expliquée.
C'est lui qui a montré que les builtins de déclaration ne sont pas des
nœuds `command` mais des `declaration_command` — un remplacement à
l'aveugle aurait rouvert toute cette famille d'un coup.

Usage : uv run python tests/ab_decoupage.py

On ne remplace rien tant qu'on n'a pas vu, sur le corpus entier des tests, où
les deux divergent — et pourquoi.
"""
import re
import sys
import pathlib

sys.path.insert(0, "hooks")
import pretooluse_guard as g  # noqa: E402

from tree_sitter import Language, Parser  # noqa: E402
import tree_sitter_bash  # noqa: E402

PARSEUR = Parser(Language(tree_sitter_bash.language()))


def commandes_ast(source: str) -> list[list[str]]:
    """Commandes simples vues par la grammaire, tokens TELS QU'ÉCRITS."""
    octets = source.encode("utf-8")
    arbre = PARSEUR.parse(octets)
    sorties: list[list[str]] = []

    def texte(n):
        return octets[n.start_byte:n.end_byte].decode("utf-8", "replace")

    pile = [arbre.root_node]
    while pile:
        n = pile.pop()
        if n.type in ("command", "declaration_command", "unset_command"):
            mots = [texte(e) for e in n.children
                    if e.type not in ("file_redirect", "heredoc_redirect",
                                      "herestring_redirect", "comment")]
            if mots:
                sorties.append(mots)
        pile.extend(n.children)
    return sorties


def corpus() -> list[str]:
    """Toutes les commandes citées par les tests du hook."""
    src = pathlib.Path("tests/test_pretooluse_hook.py").read_text()
    vus, out = set(), []
    for m in re.finditer(r'(?:f?"""|f?"|f?\')((?:[^"\'\\\n]|\\.){6,400}?)(?:"""|"|\')',
                         src):
        cmd = m.group(1)
        if any(c in cmd for c in "|;&$(){}<>") or " " in cmd:
            if cmd not in vus:
                vus.add(cmd)
                out.append(cmd)
    return out


if __name__ == "__main__":
    cas = corpus()
    print(f"{len(cas)} commandes extraites des tests\n")
    divergences = []
    for cmd in cas:
        try:
            ancien = g.tokenize(cmd)
            nouveau = commandes_ast(cmd)
        except Exception as exc:  # noqa: BLE001
            divergences.append((cmd, f"EXCEPTION {type(exc).__name__}", ""))
            continue
        prog_ancien = {t[i] for t in ancien for i in g._program_positions(t)}
        prog_nouveau = {t[0] for t in nouveau if t}
        if prog_ancien != prog_nouveau:
            divergences.append((cmd, sorted(prog_ancien), sorted(prog_nouveau)))

    # Classement des divergences plutôt qu'un déversement.
    classes = {"grammaire voit MOINS (enveloppe non dépliée)": [],
               "grammaire voit MOINS (autre)": [],
               "grammaire voit PLUS": [],
               "les deux diffèrent": []}
    enveloppes = g._WRAPPERS
    for cmd, a, n in divergences:
        if not isinstance(a, list):
            classes["les deux diffèrent"].append((cmd, a, n))
            continue
        sa, sn = set(a), set(n)
        if sn < sa:
            manquants = sa - sn
            cle = ("grammaire voit MOINS (enveloppe non dépliée)"
                   if any(g._basename(x) in enveloppes for x in sn)
                   else "grammaire voit MOINS (autre)")
            classes[cle].append((cmd, sorted(manquants), n))
        elif sa < sn:
            classes["grammaire voit PLUS"].append((cmd, sorted(sn - sa), n))
        else:
            classes["les deux diffèrent"].append((cmd, a, n))

    for nom, items in classes.items():
        print(f"\n### {nom} : {len(items)}")
        for cmd, detail, n in items[:6]:
            print(f"  {cmd[:64]!r}\n     {detail}  →  {n}")
