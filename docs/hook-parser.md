# Le découpage du hook repose sur une GRAMMAIRE

Fait le 2026-08-05 (round 17). Ce document dit ce que la grammaire apporte, ce
qu'elle n'apporte pas, et les quatre pièges qui ont coûté une itération chacun —
pour qu'ils ne soient pas re-découverts.

Arbitrage de jo, 2026-08-05 : arrêter la boucle adversariale sur le hook,
attaquer le parseur. Raison énoncée : les findings du hook sont gratuits avec
un AST.

## Pourquoi

Seize rounds de revue adversariale sur `hooks/pretooluse_guard.py`. Le moteur
s'est stabilisé (deux rounds sans finding) ; le hook produisait environ un
contournement par round, et **chacun venait d'un mécanisme de bash jamais
modélisé ou du trou laissé entre deux gardes voisines** : `trap`, `case`,
`coproc`, `mapfile -C`, les noms de fonction à caractères étendus, le
commentaire pris pour un programme, l'indirection par élément de tableau.

Tous sont gratuits avec un arbre syntaxique. Une denylist qui approxime la
grammaire de bash ne converge pas vers zéro par la seule méthode adversariale.

## Ce que la grammaire apporte — et ce qu'elle n'apporte PAS

Elle donne la **structure** : `case`, définitions de fonction, groupes,
heredocs, commentaires, substitutions, concaténations. Tout ce que quatorze
rounds d'heuristiques approximaient.

Elle **n'évalue pas**. `e${IFS//?/}nv` reste un seul nœud, `${!m[k1]}` reste une
expansion. La logique d'expansion, d'enveloppe et d'indirection reste
NÉCESSAIRE — c'est de la sémantique de bash, pas de la syntaxe. Elle vit dans
`_reduire_token` (mot à mot) et dans `_reecritures_semantiques`.

Le vrai gain : les arguments arrivent **avec leur quoting intact**. Toute la
difficulté « le quoting est déjà retiré, on ne sait pas où la sous-commande
s'arrête » — qui imposait des doubles lectures pour `trap`, `mapfile -C` et
`bash -c` — disparaît.

## L'ordre des passes, qui est tout le sujet

```
commande BRUTE
  │
  ├─► normalize()          quoting/globs détruits  ──► contrôles par REGEX
  │                                                    (coffre, fichiers,
  │                                                     DENY_COMMAND_PATTERNS,
  │                                                     variables sensibles)
  │
  └─► _NESTED_RE / _REF_SIMPLE_RE (marqueurs)
        └─► tokenize()  =  _reecritures_semantiques  ──►  grammaire
                                                            └─► _reduire_token
```

**Le découpage travaille sur la commande BRUTE.** Normaliser d'abord faisait
RENAÎTRE une structure que les guillemets avaient supprimée : `git commit -m
'handle case in parser(env)'` redevenait un sous-shell exécutant `env`. Les
neuf faux positifs du premier branchement venaient tous de là, et ils
ressuscitaient exactement le défaut que les rounds 5, 8 et 9 avaient éliminé.

Les contrôles par regex, eux, gardent le texte normalisé : c'est là que
l'obfuscation (`an[o]nproxy`, `an''onproxy`) se neutralise.

## Les quatre pièges, chacun payé une fois

### 1. Une expansion d'accolades doit précéder la grammaire
`{env,}` n'est pas du bash valide tant que l'expansion n'a pas eu lieu :
l'arbre part en `ERROR`, et le mot reconstruit (`env`) n'apparaît nulle part.
L'expansion se fait donc AVANT l'analyse — mais seulement **hors guillemets**
(`_expanse_hors_quotes`), sinon un corps JSON (`'{"a":1,"b":2}'`) est expansé
et l'appariement des guillemets, dont la grammaire dépend, est rompu.

Corollaire trouvé en corrigeant : `${IFS,,}` n'est PAS une alternative, c'est
un opérateur de casse. Sans le `(?<!\$)` de `_ACCOLADES_RE`,
`env${IFS,,}> /tmp/dump.txt` était réécrit en `env$IFS> env$> env$>`.

### 2. La grammaire refuse des noms de fonction que bash accepte
`my.fn()` passe, `a@b()`, `a%b()`, `1fn()` non : l'arbre part en `ERROR` et le
CORPS disparaît — or c'est lui qui porte les programmes. Seul le NOM est
remplacé par un identifiant neutre (`_canonise_noms_de_fonction`), la structure
redevient lisible. Le nom est délimité en remontant depuis la parenthèse,
jamais par une regex qui le chercherait à gauche : une classe libre en tête
rétro-traque à chaque position d'un mot long (quinze secondes sur vingt mille
caractères, round 10).

### 3. Un argument CITÉ ne se lit plus par accident
C'est le gain, et c'est ce qui casse si on ne fait rien : `bash -c 'f() { env;
}; f'` rend un `raw_string` que la grammaire n'ouvre pas. Il faut ré-analyser
EXPLICITEMENT (`_sous_scripts`) : la valeur de `-c` d'une enveloppe SHELL,
l'argument de `trap` (moins les spécifications de signal), la valeur de
`mapfile -C` / `readarray -C`, la valeur de `env -S`, et le corps d'un heredoc
(qui pend sous `heredoc_redirect`, donc hors des mots de la commande).

Chaque niveau repasse par `_reecritures_semantiques` : un script imbriqué peut
lui aussi porter un `coproc`, un alias ou une accolade.

### 4. La grammaire concatène, comme bash — la lecture des options aussi
`bash -c"env"` donne un nœud `concatenation` (`word` + `string`), réduit en
`-cenv`. Ni la règle `-c` ni la ré-analyse ne le voyaient : **contournement
introduit par mon propre correctif**, trouvé en attaquant le code neuf. Le
découper au tokeniseur serait faux (bash produit bien UN mot, et
`/usr/"bin"/env` doit rester `/usr/bin/env`) : c'est à la couche qui lit les
options de séparer `-c` de sa valeur attachée (`_OPT_C_ATTACHEE_RE`).

## Faits de grammaire, vérifiés

```
export -p          → declaration_command      (PAS command)
readonly -p        → declaration_command
local -n r=X       → declaration_command
unset FOO          → unset_command
env                → command
bash <<'FIN'…      → heredoc_redirect → heredoc_start, heredoc_body, heredoc_end
bash -c 'f() {…}'  → command_name, word(-c), raw_string      (non ouvert)
bash -c"env"       → command_name, concatenation(word(-c), string)
coproc { ls; }     → coproc/{/ls en MOTS, puis une commande `}`
                     (la grammaire ne connaît PAS cette forme)
```

`find … -exec env \;` : le terminateur arrive comme un mot ordinaire, et
l'échappement qui le distinguait tombe à la réduction — le garder faisait
passer `env` pour un préfixe exécutant `;`.

## Amorçage

Claude Code lance le hook comme un exécutable, donc sous le python SYSTÈME, qui
n'a pas la grammaire. `_relance_sous_interpreteur_du_projet` le rejoue sous
`.venv/bin/python` ; `os.execv` PRÉSERVE stdin, l'événement reste lisible.

La relance a lieu depuis `main`, **jamais à l'import** : une suite de tests
lancée sans la grammaire verrait sinon son propre processus remplacé. Un
marqueur d'environnement empêche la boucle si le second interpréteur ne l'a pas
non plus.

## Invariant

Le hook est **fail-closed** depuis `f1e00f8`. La grammaire est devenue un
prérequis de l'analyse : sans elle, `tokenize` lève `GrammaireIndisponible`,
`main` écrit un REFUS. Un hook qui plante n'écrit aucune décision, et l'outil
s'exécute — c'est le seul mode d'échec qui ouvre le canal au lieu de le fermer.
Figé par `test_sans_grammaire_le_hook_refuse`.

## Outil de diagnostic

`uv run python tests/ab_decoupage.py` — liste les commandes du corpus de tests
que la grammaire refuse encore (`ERROR`) ou réduit à rien. Un nœud `ERROR`
signifie que le sous-arbre est plat, donc qu'un programme peut y disparaître :
c'est ainsi que `{env,}` et `a@b()` ont été trouvés.

Il a d'abord servi de différentiel entre les heuristiques et la grammaire, le
temps du remplacement — c'est lui qui a montré le piège des
`declaration_command` AVANT le remplacement, ce qui aurait sinon rouvert d'un
coup toute la famille des déverseurs durcie au round 15.

## Mesures (2026-08-05)

| | |
|---|---|
| commande réaliste | 0,003 s |
| mot de 20 000 caractères | 0,016 s |
| 500 Ko de texte | 0,42 s |
| 100 groupes d'accolades | 0,010 s |
| 5 000 `declare -n` | 0,47 s |
| 1 000 lignes | 0,08 s |
| relance sous l'interpréteur du projet | +30 ms |
| timeout du hook (`.claude/settings.json`) | 10 s |
