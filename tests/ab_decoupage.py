"""Ce que la grammaire ne comprend PAS — là où se cachent les contournements.

Outil de diagnostic, pas un test : il ne juge pas, il SIGNALE.

Il a d'abord servi de différentiel entre les heuristiques et la grammaire, le
temps du remplacement — c'est lui qui a montré que les builtins de déclaration
ne sont pas des nœuds `command` mais des `declaration_command`, ce qu'un
remplacement à l'aveugle aurait rouvert d'un coup.

Une fois le remplacement fait, la question utile a changé. Un nœud `ERROR`
signifie que la grammaire n'a pas su lire l'entrée : le sous-arbre est alors
plat, et un programme peut y disparaître. Les deux contournements du round 17
(`{env,}` non expansé, `a@b() { env; }` au nom de fonction refusé) étaient
exactement cela. D'où ce balayage : il liste les commandes du corpus de tests
que la grammaire refuse encore, et celles qu'elle réduit à rien.

Usage : uv run python tests/ab_decoupage.py
"""
import pathlib
import re
import sys

sys.path.insert(0, "hooks")
import pretooluse_guard as g  # noqa: E402


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


def erreurs(source: str) -> int:
    """Nombre de nœuds ERROR après les réécritures que le hook applique."""
    prepare = g._reecritures_semantiques(source)
    racine = g._PARSEUR.parse(prepare.encode("utf-8", "surrogateescape")).root_node
    if not racine.has_error:
        return 0
    total, pile = 0, [racine]
    while pile:
        noeud = pile.pop()
        total += noeud.type in ("ERROR", "MISSING")
        pile.extend(noeud.children)
    return total


if __name__ == "__main__":
    cas = corpus()
    print(f"{len(cas)} commandes extraites des tests\n")
    en_erreur, sans_commande = [], []
    for cmd in cas:
        if erreurs(cmd):
            en_erreur.append(cmd)
        if not g.tokenize(cmd):
            sans_commande.append(cmd)

    print(f"### la grammaire tombe en ERREUR : {len(en_erreur)}")
    for cmd in en_erreur[:20]:
        print(f"  {cmd[:72]!r}")
    print(f"\n### aucune commande extraite : {len(sans_commande)}")
    for cmd in sans_commande[:20]:
        print(f"  {cmd[:72]!r}")
    print("\nUne entrée listée ici n'est pas forcément un défaut — un fragment "
          "de commande\nn'est pas du bash complet. Mais toute entrée qui EST "
          "une commande entière\ndoit être expliquée avant d'être ignorée.")
