# Reprise de session — état au 2026-08-02

> Ce fichier complète `CLAUDE.md` (qui porte l'état des phases et les décisions
> verrouillées). Ici : **le travail EN COURS**, ce qui reste à faire, et les
> pièges qui ont coûté du temps.
> Ordre de lecture à la reprise : `CLAUDE.md` → ce fichier → `git log`.

## 1. Consigne en cours (non terminée)

> « Relance une revue adversariale agent opus 5 effort max sur l'ensemble du
> repo et traite les findings, recommence jusqu'à ce qu'il n'y ait plus aucun
> finding high/critical (et qui soit non assumé) »

**Boucle en cours. Round 2 traité, round 3 PAS ENCORE LANCÉ.**

Protocole appliqué à chaque round :
1. Lancer 2-3 agents `general-purpose`, `model: opus`, en parallèle, sur des
   angles distincts (fuites / crypto-invariants / hook + tests complaisants).
2. Leur DONNER la liste de ce qui est déjà corrigé et de ce qui est assumé
   (sinon ils re-signalent la même chose) — voir §4 et §5.
3. Exiger : preuve exécutée, gravité, correctif minimal, et « dis-le
   explicitement si tu ne trouves rien de haut/critique ».
4. Corriger, ajouter une non-régression par finding, revalider E2E, committer.
5. Recommencer sur le code corrigé — **c'est là que se cachent les régressions
   de mes propres correctifs** : les rounds 1 et 2 en ont produit chacun deux.

Critère d'arrêt : plus aucun finding critique/haut qui ne soit dans la liste
des points assumés (§5).

## 2. Où en est le code

**374 tests + 18 egress**, tous verts. Les six phases ont leur critère de
sortie prouvé (détail et preuves : `CLAUDE.md`).

Revalidation complète après tout changement :
```bash
uv run pytest tests/ --ignore=tests/egress   # 374
uv run pytest tests/egress/test_report.py    # 18
uv run python tests/corpus_eval.py           # 6 critères durs
bash tests/phase3_e2e.sh                     # session réelle + capture
bash tests/phase4_e2e.sh                     # commande interdite bloquée
uv run python tests/detect_latency.py        # P95 < 150 ms
```
Prérequis : le détecteur doit tourner (`services/anonshield/wrapper/run.sh`).

## 3. À FAIRE au prochain round

1. **Lancer le round 3** (rien n'a encore été relu depuis les correctifs du
   round 2 : hook fortement remanié, `_aad`, allowlist cloud, `detect()`).
2. Points du round 2 **non corrigés**, à re-arbitrer ou à traiter :
   - **M3 — fragmentation de substituts** : le détecteur renvoie parfois un
     span URL tronqué (`https://acme.int`) qui chevauche un span HOSTNAME ;
     l'arbitrage garde le plus long et le reste devient une entité distincte.
     Résultat : une même machine réelle peut recevoir DEUX noms fictifs.
     Ce n'est pas une fuite mais une régression du déterminisme (§9 du plan :
     l'analyse de topologie devient fausse). Piste : fusionner les spans
     URL/HOSTNAME chevauchants avant substitution.
   - **B2 — `container` / `stop_sequences`** : traversés par le walker, mais
     le détecteur ne classe pas des valeurs comme `INTERNAL_STOP_TOKEN_acme`.
     À documenter comme risque, ou custom pattern.
   - **T2 — test d'entropie du coffre** : ne détecte pas seul un XOR dérivé du
     nonce ; ce sont les tests voisins (mauvaise clé, bit-flip) qui rattrapent.
     Acceptable mais à renforcer si l'occasion se présente.
   - **T3 — `test_la_liste_suit_le_detecteur`** est *skipped* sans le service :
     retirer un type de `CLASS_OF` ET de `TYPES_EMIS` passerait inaperçu.
     Piste : figer aussi le CARDINAL attendu.
   - **T4 — `sensitive_from_fixture`** ne reconnaît que quelques TLD ; un hôte
     en `.dev`/`.app` dans une future fixture ne serait pas recherché.
   - **Hook, contournements assumés faute de mieux** (le rapport les liste,
     ils relèvent structurellement de D9) : écrire-puis-exécuter
     (`printf … > /tmp/x && bash /tmp/x`), scripts par chemin
     (`tclsh /tmp/x.tcl`), gestionnaires de paquets (`pip`/`npm`/`cargo`),
     `git clone` vers un remote arbitraire, `docker pull/push`, `helm pull`.
     **Ne pas empiler des motifs pour ceux-là** : le hook est un rideau, pas
     un mur, et c'est écrit dans son en-tête.
3. Le reste du backlog produit : `corpus/real/` non annoté (matière de jo),
   KMS/rotation/journal d'accès immuable (Phase 6, hors MVP).

## 4. Déjà corrigé — NE PAS re-signaler aux agents

Fuites du proxy : passthrough sur chemins non modélisés · `walk_request`
limité à 4 surfaces · seuil `MIN_LEN` · mode `regex` sur gros volumes ·
chemin d'URL en clair · cache non porté · userinfo/mot de passe d'URL ·
fragment d'URL · IPv6 sans crochets · hôte nu d'URL · hôte d'URL non
enregistré au coffre · `document.source[type=text].data` · blocs PEM (courts
ET longs) · sous-arbres de clés de contrôle · `walk_response` limité à
`content` · écho de `stop_sequence` en SSE.

Moteur : attribut partagé se substituant à lui-même · spans invalides ·
recouvrement partiel · tag d'image · type interne forgeable · identités
multiples par type/casse · mot du lexique reprenant le réel · fragments sans
alphanumérique · `FILE_PATH` dégénéré · plausibilité (UUID, MAC Cisco,
préfixe de hash, `PERSON`, IPv6).

Coffre : chiffrement au repos, AAD à préfixe de longueur, rembourrage,
unicité `(scope, real_idx)`, refus du format en clair, symlink de migration.

Classification : les vrais types du détecteur (`CERTIFICATE`,
`CRYPTOGRAPHIC_KEY`, `PASSWORD`, `USERNAME`) n'étaient PAS classés → secrets
réversibles. Corrigé + `tests/test_classes_contract.py`.

Hook : préfixe/quoting/glob · décodage-puis-shell · `$ENV` d'interpréteur ·
`ps auxe` · variables sensibles · `~/.ssh` en bloc · outils MCP · hôte d'URL ·
`bash <(curl)` · backticks · `busybox` · `terraform show` · `port-forward` ·
`gh api` · `docker run -v` · expansions `${…}` en milieu de mot.

Tests complaisants : compteur de collisions tautologique · recherche aveugle
aux échappements · garde-fou FakeDetector à couverture partielle · `or` de
repli · base64 accepté comme chiffrement · code retour de `claude` ignoré ·
restauration partielle acceptée.

## 5. Assumé et documenté — ce ne sont PAS des findings

- Coffre local, même utilisateur (réponse §3.5) — fermé par la conteneurisation.
- **D9 non tenue sur un poste** : arbitrage jo du 2026-08-02, pas de pare-feu
  local. Voir `docs/d9-blocage-reseau.md`.
- Les QUATRE attributs préservés (environnement, /24, humain/service,
  interne/externe) sont des fuites volontaires (réponse §3.4).
- Hook en **denylist** et non allowlist : arbitrage acté, le plan sous-estime
  le coût d'une allowlist pour un agent DevOps.
- Dépendance à l'ordre d'insertion bornée à ~4 % (test dédié).
- `SERVICE` classé PUBLIC (faux positifs sur de la prose).
- Corpus réel non annoté.
- Télémétrie : coupée par les réglages de jo ; contenu jamais inspecté.

## 6. Pièges qui ont coûté du temps

- **`uv run` re-synchronise le venv** de `services/anonshield/upstream` sur le
  lock (torch CPU) et retire fastapi. Toujours relancer
  `services/anonshield/wrapper/install-cuda.sh` après, et lancer le service
  par `.venv/bin/python` direct (c'est ce que fait `run.sh`).
- **Le détecteur doit être REDÉMARRÉ** après toute modification de
  `config/allowlist.txt` ou `config/custom_patterns.json` : la config est lue
  au démarrage.
- **Deux régressions ont été attrapées par `phase3_e2e.sh`, pas par les tests
  unitaires** (503 en pleine session). Toujours rejouer l'E2E réel après une
  modification du moteur ou du coffre.
- `_SCHEMA` n'est pas une chaîne brute : y écrire `ESCAPE '\'` donne un
  échappement VIDE. Utiliser `'\\'`.
- Les agents de revue doivent recevoir la liste §4/§5, sinon ils passent leur
  temps sur du déjà-corrigé.
- Ne jamais lire ni afficher `~/.local/state/anonproxy/` (règle secrets).

## 7. Repères

- Commits : uniquement sur demande de jo, conventional commits, en anglais.
- `PLAN-proxy-pseudonymisation.md` : **jamais modifié**.
- `anthropic_walker.py` : fourni par jo ; sept défauts corrigés, chacun prouvé
  par un test écrit AVANT (`tests/test_walker_defects.py`).
- Données synthétiques uniquement.
