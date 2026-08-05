# Remplacer les heuristiques du hook par un PARSEUR

Ce document existe pour qu'une session neuve n'ait rien à re-dériver. Il porte
l'architecture validée, le **code exact** de l'essai de branchement, les faits
mesurés, et les échecs qui spécifient le reste.

Contexte : `REPRISE.md` §3 bis. Arbitrage de jo le 2026-08-05 — arrêter la
boucle adversariale sur le hook, attaquer le parseur.

## Pourquoi

Seize rounds de revue adversariale sur `hooks/pretooluse_guard.py`. Le moteur
s'est stabilisé (deux rounds sans finding) ; le hook produit environ un
contournement par round, et **chacun vient d'un mécanisme de bash jamais
modélisé ou du trou laissé entre deux gardes voisines** : `trap`, `case`,
`coproc`, `mapfile -C`, les noms de fonction à caractères étendus, le
commentaire pris pour un programme, l'indirection par élément de tableau.

Tous sont GRATUITS avec un arbre syntaxique. Une denylist qui approxime la
grammaire de bash ne converge pas vers zéro par la seule méthode adversariale.

## Ce qui est mesuré

| | |
|---|---|
| commande réaliste | **0,00 ms** |
| 500 Ko de texte | 70 ms |
| processus + import | 21 ms |
| relance sous l'interpréteur du projet | +30 ms |
| timeout du hook (`.claude/settings.json`) | 10 s |

Les vingt mécanismes qui ont coûté un round chacun sont analysés **sans erreur**
par la grammaire (`root_node.has_error` faux partout).

Dépendances déclarées dans `pyproject.toml` : `tree-sitter`, `tree-sitter-bash`.

## Ce que la grammaire apporte — et ce qu'elle n'apporte PAS

Elle donne la **structure** : `case`, définitions de fonction, groupes,
heredocs, commentaires, substitutions. Tout ce que quatorze rounds
d'heuristiques approximaient.

Elle **n'évalue pas**. `e${IFS//?/}nv` reste un seul nœud, `${!m[k1]}` reste
une expansion. La logique d'expansion, d'enveloppe et d'indirection reste
NÉCESSAIRE — c'est de la sémantique de bash, pas de la syntaxe.

Le vrai gain : les arguments arrivent **avec leur quoting intact**. Toute la
difficulté « le quoting est déjà retiré, on ne sait pas où la sous-commande
s'arrête » — qui a forcé des doubles lectures pour `trap`, `mapfile -C` et
`bash -c` — disparaît.

## Faits de grammaire, vérifiés

```
export -p          → declaration_command      (PAS command)
declare -x | head  → command + declaration_command
readonly -p        → declaration_command
local -n r=X       → declaration_command
unset FOO          → unset_command
env                → command
```

```
bash <<'FIN'\nls\nFIN
  redirected_statement
    command → command_name → word
    heredoc_redirect → << , heredoc_start , heredoc_body , heredoc_end

coproc { ls; }
  command → command_name(word=coproc), word({), word(ls)
  ; command → command_name(word=})        ← la grammaire NE connaît PAS cette forme

bash -c 'f() { ls; }; f'
  command → command_name(word=bash), word(-c), raw_string  ← non ouvert
```

## Le code de l'essai (architecture validée)

À reprendre tel quel. Il manque UNIQUEMENT la ré-analyse des sous-commandes.

### Amorçage — le hook tourne sous le python SYSTÈME

```python
_RACINE = Path(__file__).resolve().parents[1]
_PYTHON_PROJET = _RACINE / ".venv" / "bin" / "python"


def _charger_grammaire():
    try:
        import tree_sitter_bash
        from tree_sitter import Language, Parser
        return Parser(Language(tree_sitter_bash.language()))
    except Exception:      # import, ABI, version : tout vaut échec
        return None


_PARSEUR = _charger_grammaire()
if _PARSEUR is None and _PYTHON_PROJET.exists() \
        and Path(sys.executable).resolve() != _PYTHON_PROJET.resolve():
    os.execv(str(_PYTHON_PROJET),
             [str(_PYTHON_PROJET), str(Path(__file__).resolve())])


class GrammaireIndisponible(RuntimeError):
    """Sans grammaire, aucune analyse n'est fiable : on refuse."""
```

`os.execv` PRÉSERVE stdin, donc l'événement JSON reste lisible après la
relance. Vérifié depuis les trois points d'entrée (python système, python du
projet, exécutable direct).

### Réduction MOT À MOT plutôt que sur toute la chaîne

C'est le point dur : `normalize()` détruit le quoting dont la grammaire a
besoin. La réduction se fait donc par mot, APRÈS que la grammaire a découpé.

```python
def _reduire_token(mot: str) -> str:
    out = _EXPANSION_RE.sub(_reduire_expansion, mot)
    out = re.sub(r"(?<=\w)\$\{!?[A-Za-z_]\w*\}(?=\w)", "", out)
    out = out.replace("''", "").replace('""', "")
    out = re.sub(r"\[([^\]/@*])\]", r"\1", out)
    out = out.replace("\\$", "")
    out = re.sub(r"\\(.)", r"\1", out)
    return out.replace("'", "").replace('"', "")
```

### Découpage par la grammaire

```python
_NOEUDS_COMMANDE = ("command", "declaration_command", "unset_command")
_ENFANTS_HORS_MOT = ("file_redirect", "heredoc_redirect",
                     "herestring_redirect", "comment")


def _commandes_ast(source: str) -> list[list[str]]:
    octets = source.encode("utf-8", "surrogateescape")
    racine = _PARSEUR.parse(octets).root_node
    sorties, pile = [], [racine]
    while pile:
        noeud = pile.pop()
        if noeud.type in _NOEUDS_COMMANDE:
            mots = [_reduire_token(
                        octets[e.start_byte:e.end_byte].decode("utf-8", "replace"))
                    for e in noeud.children if e.type not in _ENFANTS_HORS_MOT]
            mots = [m for m in mots if m]
            if mots:
                sorties.append(mots)
        pile.extend(reversed(noeud.children))
    return sorties
```

### Réécritures sémantiques, conservées

Ce que bash FAIT et que la grammaire ne montre pas.

```python
def _reecritures_semantiques(command: str) -> str:
    out = re.sub(r"\bcoproc\s+([A-Za-z_]\w*)\s+(?=\S)", r"coproc \1 ; ", command)
    valeurs = [m.group(1)
               for m in re.finditer(r"\balias\s+[A-Za-z_]\w*=(\S+)", out)]
    out += "".join(f" ; {v}" for v in valeurs)
    return re.sub(r"\benv\s+(?:--split-string=?|-S)\s*", "env -S ", out)
```

## Les 15 échecs, et ce qu'ils spécifient

Branché tel quel : **15 tests rouges sur ~700**. Reverté — un contrôle de
sécurité ne se laisse pas à moitié échangé. Les échecs sont la spécification.

### 1. Ré-analyser les sous-commandes CITÉES — le travail principal
`bash -c 'f() { env; }; f'` rend un `raw_string` que la grammaire n'ouvre pas.
Avant, le quoting était détruit globalement et l'intérieur devenait visible
PAR ACCIDENT. Il faut désormais ré-analyser explicitement :
- la valeur de `-c` d'une enveloppe SHELL (`_WRAPPERS_SHELL`) ;
- l'argument de `trap` (moins les spécifications de signal, cf. `_SIGNAL_RE`) ;
- la valeur de `mapfile -C` / `readarray -C` ;
- la valeur de `env -S`.

C'est le gain recherché : il s'implémente, il ne s'hérite pas.

### 2. Router le corps des heredocs
`heredoc_body` pend sous `heredoc_redirect`, donc écarté par
`_ENFANTS_HORS_MOT`. `bash <<'FIN'\nenv\nFIN` passait. Un corps livré à un
interpréteur est du CODE ; livré à `cat > f`, c'est de la donnée (règle déjà
acquise, cf. `_neutralise_heredocs`).

### 3. `coproc { cmd; }`
La grammaire ne connaît pas cette forme : elle rend `coproc` avec les mots `{`
et `cmd`, puis une commande `}`. Le corps est visible comme MOT, pas comme
programme.

### 4. Noms de fonction à caractères étendus
`a@b() { env; }`, `a%b() { env; }` : à vérifier, la grammaire ne les reconnaît
probablement pas comme `function_definition`.

### 5. Deux faux positifs à COMPRENDRE, pas à faire taire
```
git commit -m 'handle case in parser(env)'
python3 -c "env = 42; print(env)"
```

## Méthode de dé-risque, à refaire à chaque étape

`uv run python tests/ab_decoupage.py` — extrait les ~650 commandes citées par
les tests, fait tourner ANCIEN et NOUVEAU découpage, et **classe** les
divergences (la grammaire voit moins / plus / autre chose).

C'est lui qui a sorti le piège des `declaration_command` AVANT le
remplacement : sans lui, toute la famille des déverseurs durcie au round 15
était rouverte d'un coup.

Ne remplacer que quand chaque classe de divergence est expliquée.

## Invariant à ne pas casser

Le hook est **fail-closed** depuis `f1e00f8` : une exception dans l'analyse
écrit un refus au lieu de planter. C'est le prérequis de tout ce chantier — un
hook qui plante n'écrit AUCUNE décision, et l'outil s'exécute. Si la grammaire
manque, il faut REFUSER, jamais laisser passer.
