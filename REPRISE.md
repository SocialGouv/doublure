# Reprise de session — état au 2026-08-04

> Ce fichier complète `CLAUDE.md` (qui porte l'état des phases et les décisions
> verrouillées). Ici : **le travail EN COURS**, ce qui reste à faire, les
> pièges déjà payés, et ce que neuf rounds de revue ont appris.
> Ordre de lecture à la reprise : `CLAUDE.md` → ce fichier → `git log`.

## 1. Consigne en cours (non terminée)

> « Relance une revue adversariale agent opus 5 effort max sur l'ensemble du
> repo et traite les findings, recommence jusqu'à ce qu'il n'y ait plus aucun
> finding high/critical (et qui soit non assumé) »

**Rounds 3 à 14 traités. Round 15 à lancer.** jo a validé la poursuite deux
fois (`::g`). Critère d'arrêt : plus aucun finding critique/haut hors §5.
**Il n'est pas atteint : les dix rounds ont TOUS produit des findings hauts ou
critiques.** Jusqu'au round 9 c'étaient surtout des régressions du round
précédent ; le round 10 a rompu ce motif, et le round 11 a produit LES DEUX à
la fois — quatre mécanismes de bash jamais modélisés (`trap`, `case`, `coproc`,
`mapfile -C`) ET trois régressions de mes correctifs du round 10, dont un déni
de service. La consigne « chercher aussi ce qui n'a jamais été modélisé » a
payé : c'est elle qui a sorti les quatre familles.

### Protocole appliqué à chaque round
1. Deux agents `general-purpose`, `model: opus`, en parallèle : un sur le hook,
   un sur walker + moteur + proxy.
2. Leur DONNER §4 (déjà corrigé) et §5 (assumé), sinon ils repassent leur temps
   sur du déjà-traité.
3. Exiger : preuve EXÉCUTÉE, gravité, correctif minimal, et « dis-le
   explicitement si tu ne trouves rien de haut/critique ».
4. Vérifier chaque finding MOI-MÊME avant de corriger — plusieurs se sont
   révélés faux ou non reproductibles (cf. §8).
5. Corriger, une non-régression par finding, revalider E2E, committer.

### Contraintes de rédaction des prompts d'agent (apprises à la dure)
- Ne pas écrire le chemin du coffre en toutes lettres : **mon propre hook
  refuse alors le lancement de l'agent**. Dire « le répertoire d'état de
  l'utilisateur ».
- Éviter les backticks autour de code contenant une substitution : même effet.
- Demander à l'agent d'écrire ses scripts avec l'outil Write, **pas** par
  heredoc (le hook analyse le corps d'un heredoc alimentant un interpréteur).
- **Imposer un rendu par LOTS.** Demander « un rapport partiel tôt » ne suffit
  pas : au round 13, les DEUX agents sont morts d'un « stream idle timeout »
  sans rien rendre du tout. La consigne qui marche est explicite — un script
  par lot, une synthèse écrite après CHAQUE lot, six lots maximum, puis rendu
  final même incomplet. Découper le prompt en lots numérotés donne à l'agent
  la structure qui l'empêche d'explorer en silence.
- Un agent mort ne rend RIEN d'exploitable : relancer, ne pas essayer de
  récupérer sa trace (le fichier de transcription déborde le contexte).

## 2. Où en est le code

**918 tests verts** (900 unitaires + 18 egress). Les six phases ont leur
critère de sortie prouvé (détail : `CLAUDE.md`).

```bash
uv run pytest tests/ --ignore=tests/egress   # 900
uv run pytest tests/egress/test_report.py    # 18
uv run python tests/corpus_eval.py           # 6 critères durs
bash tests/phase3_e2e.sh                     # session RÉELLE + capture
bash tests/phase4_e2e.sh                     # commande interdite bloquée
uv run python tests/detect_latency.py        # P95 < 150 ms
```
Prérequis : le détecteur doit tourner (`services/anonshield/wrapper/run.sh`).

**Toujours rejouer `phase3_e2e.sh` après une modification du walker, du moteur
ou de l'allowlist.** Trois défauts n'ont été vus QUE par lui (§7).

## 3. À FAIRE au round 15

1. **Chercher la JUMELLE de chaque correctif.** C'est le motif des rounds 12 à
   14, sans exception : je durcis une branche et laisse l'autre ouverte —
   l'indirection sans l'alias, le premier niveau d'un `media_type` sans son
   sous-type, `${!x}` sans `declare -n r=$1`. Poser la question directement
   (« où est la jumelle ? ») a marché à chaque fois ; l'oublier a coûté un
   round à chaque fois.
2. **Vérifier les voisins, ne pas les supposer inoffensifs.** `@P` exécute ;
   `@Q`, `@E`, `@A`, `@K`, `@L`, `@U` n'ont jamais été testés. Même chose pour
   toute famille d'opérateurs dont un seul membre a été traité.
3. **Chercher ce qui n'a JAMAIS été modélisé.** La moitié des findings des
   rounds 11 à 13 venaient de mécanismes absents du modèle, pas de
   régressions. Côté bash, restent non explorés : `select`, `exec` sur
   descripteurs, `local -x`, tableaux, `GLOBIGNORE`, `CDPATH`, `wait`,
   `builtin`, `shopt`, `complete -F`, `caller`, `hash`, `type -P`.
4. **Mesurer le COÛT, pas seulement la décision.** Tout motif dont la tête est
   une classe libre est un déni de service en attente.
5. **Surfaces à faible couverture, à attaquer avant les autres** : le PROXY
   lui-même (en-têtes, `Content-Length` après réécriture, annulation du client
   en plein flux, requêtes concurrentes) et le SERVICE DE DÉTECTION — dont une
   question jamais posée : que fait le proxy quand le détecteur est
   INDISPONIBLE ? Si ce n'est pas fail-closed, une panne ouvre une fuite.
   (Coffre et concurrence : attaqués au round 14, RAS — ne pas y revenir.)
6. Points **non corrigés**, à re-arbitrer :
   - **M3 — fragmentation de spans** : un span URL tronqué qui chevauche un
     span HOSTNAME donne DEUX noms fictifs à une machine. Pas une fuite ; une
     régression du déterminisme (§9 du plan). Piste : fusionner les spans
     chevauchants avant substitution.
   - **`container` / `stop_sequences`** : traversés, mais le détecteur ne
     classe pas une valeur comme `INTERNAL_STOP_TOKEN_acme`. Documenter ou
     ajouter un custom pattern.
   - **Test d'entropie du coffre** : ne détecte pas seul un XOR dérivé du
     nonce ; ce sont les tests voisins qui rattrapent.
   - **`test_la_liste_suit_le_detecteur`** *skipped* sans le service : figer
     aussi le CARDINAL attendu.
   - **`sensitive_from_fixture`** ne reconnaît que quelques TLD.
   - **Résidu connu** : un message de commit citant une primitive, suivi d'un
     point-virgule puis d'un interpréteur en ligne, reste un faux positif. Le
     point-virgule sépare des INSTRUCTIONS dans un programme en ligne : le
     traiter comme une frontière de commande casserait les one-liners.
7. Backlog hors boucle : `corpus/real/` non annoté (matière de jo),
   KMS/rotation/journal d'accès immuable (Phase 6, hors MVP).

## 4. Déjà corrigé — DONNER cette liste aux agents

**Proxy / walker** : passthrough sur chemin non modélisé · surfaces sortantes
énumérées · seuil de longueur · mode regex sur gros volumes · chemin et query
d'URL · cache non porté par la portée · écho de séquence d'arrêt · source de
document en texte · blocs PEM · type non hachable · branche `properties` morte
· mots-clés de schéma (motif de validation, format, type en union, ancres,
références dynamiques, dépendances) · clés de propriétés à motif · sous-arbre
non scalaire sous une clé ignorée · scalaire arbitraire sous les betas ·
contrôle de cache et son vocabulaire · bloc de démarrage non restauré · delta
de citations · corps d'erreur streamé · séparateurs SSE et formes mixtes ·
delta orphelin · clés ignorées dans les arguments d'outil et les métadonnées ·
opacité forgeable · nom de ressource MCP · types de média `x-` et `vnd.` ·
événements mal typés · delta signé futur · corps non-objet (requête et
réponse) · démarrage de message · conteneur scalaire · tampon SSE non borné ·
heuristique de schéma d'entrée · liste d'outils autorisés · exemples de schéma ·
émission après la fin du message · **opacité forgeable hors des données
utilisateur** (message utilisateur, sortie d'outil relayée, prompt système,
définition d'outil).

**Moteur / coffre** : attribut partagé se substituant à lui-même · spans
invalides ou mal formés · recouvrement partiel · tag d'image · type interne
forgeable · identités multiples par type ou casse · mot du lexique reprenant le
réel · chemin dégénéré · plausibilité (UUID, MAC, préfixe de hash, personne,
IPv6) · identifiants d'URL (forme web ET forme secure shell) · fragment ·
IPv6 sans crochets · hôte nu · Unicode NFC · chiffrement au repos, AAD,
rembourrage, unicité par portée · classification des types de secret · span
PUBLIC masquant une classe substituable · nom de paramètre de requête (vide,
encodé) · libellé de mot de passe · extraction de dépôt (casse mixte, hôte
hostile, port) · hôte nu avec barre oblique finale · préfixe de hachage sans
corps · **radical de l'allowlist acceptant les points** · **règle de forme
appliquée aux sous-parties**.

**Hook** : quoting, globs, backslashes · décodage puis shell · `ps auxe` ·
répertoire ssh · outils MCP · substitution de processus · backticks ·
`busybox` · `terraform show` · `port-forward` · `gh api` · `docker run` avec
montage · socket du shell · `kubectl exec` · `helm get values` · tfstate ·
jetons cloud · domaine commençant par `127.` · `perl -e system` avec et sans
parenthèses · `qx`, `%x` · tuple `subprocess` · accès à l'environnement par
crochets · import de la table d'environnement · `ENV` de Ruby · IFS sous toutes
ses formes, y compris la forme `plus` · variable commençant par IFS ·
référence indirecte · `find -exec` y compris derrière une enveloppe · `strace` ·
substitution dont la sortie devient un argument · variables de base de données
et de session · expansion perdant le nom de variable · repli exécuté · repli
cassant les motifs de refus · repli imbriqué · nom d'expansion positionnel ·
accolade en plusieurs mots · `env` avec découpage de chaîne · préfixe
d'affectation vide ou concaténé · heredoc au pipe collé ou consommé par un
pipeline · famille `exec` et `spawn` · options d'enveloppe par programme ·
champs d'outil non énumérés · `openssl` en liste noire · options d'aide seules ·
programme désigné par une variable · expansion d'accolades non bornée ·
**programme livré hors ligne** (here-string, heredoc, tiret nu, substitution de
processus, heredoc consommé par un pipe) · **corps d'une fonction et d'un
groupe de commandes** · **alias `declare -n`** · **affectation qui fait
exécuter** (`BASH_ENV`, `LD_PRELOAD`, `ENV` de chemin, `NODE_OPTIONS
--require`) · **valeur de `-c` prise pour un préfixe d'exécution**
(`bash -c env _`) · **forme longue collée de `env -S`** · **motifs dont la tête
est une classe libre** (déni de service, sept secondes sur un mot long).

**Faux positifs corrigés** (un agent bloqué est aussi cassé qu'un agent qui
fuit) : `set +e` · `env -i` et `-u` · `command -v` · `compgen -A function` ·
substitution dans un `echo` · variable de configuration Anthropic · `printenv`
d'une région AWS · listage du répertoire ssh · `grep -r curl src/` · `openssl
rand|dgst|passwd|help|ciphers` · `ssh -V` · `wget --help` · `python3 -m venv
env` · prose citant un binaire réseau · message de commit citant une primitive
ou un one-liner · prompt de sous-agent avec backticks · heredoc cité écrivant
un fichier · code JavaScript cherché par `grep` · `nice -n 10` · affectation
depuis une substitution · accolade qui n'exécute rien · nom de fichier Markdown
pris pour un domaine.

## 5. Assumé et documenté — ce ne sont PAS des findings

- Coffre local, même utilisateur (réponse §3.5) — fermé par la conteneurisation.
- **D9 non tenue sur un poste** : arbitrage jo du 2026-08-02, pas de pare-feu
  local. Voir `docs/d9-blocage-reseau.md`.
- Les QUATRE attributs préservés (environnement, /24, humain/service,
  interne/externe) sont des fuites volontaires (réponse §3.4).
- Hook en **denylist**, et « rideau, pas mur » : écrire-puis-exécuter, script
  par chemin, gestionnaires de paquets, clone vers un remote arbitraire,
  `docker pull/push`, `helm pull`. **Ne pas empiler des motifs pour ceux-là.**
- Écrire dans le fichier des clés autorisées n'est pas couvert : le hook vise
  l'exfiltration, pas la persistance.
- Dépendance à l'ordre d'insertion bornée à ~4 % (test dédié).
- `SERVICE` classé PUBLIC (faux positifs sur de la prose technique).
- Les noms d'outils, de serveurs MCP, de choix d'outil et la liste d'outils
  autorisés restent verbatim : ce sont des clés de ROUTAGE, les substituer
  casserait l'outil en silence.
- Une valeur de contrôle en forme de jeton nu n'est pas traversée.
- Une zone nue ne rejoint pas la zone fictive de ses hôtes : corriger en ferait
  un attribut PARTAGÉ, donc non restaurable.
- Un nom de paramètre de requête court, sans point ni arobase, n'est pas
  substitué : indiscernable d'un nom d'API.
- **Un domaine externe d'un SEUL label sur un ccTLD qui est aussi une extension
  de fichier** (`partenaire.md`, `billing.py`) reste public. Le type du span ne
  distingue pas un fichier d'un hôte — mesuré. Prix payé pour que `main.py`,
  `lib.rs` et `README.md` restent lisibles par l'agent. Les hôtes internes,
  multi-labels, restent couverts. Arbitrage de jo du 2026-08-04 : `.pl` et
  `.ml` RETIRÉS (vrai volume de domaines, valeur d'extension nulle ici) ;
  la liste se rejuge extension par extension, pas en bloc. Le résidu n'est
  plus silencieux : `/detect` renvoie `public_by_shape`. Trois tests figent
  les trois côtés (résidu, ccTLD retirés, hôtes multi-labels).
- Les clés de définitions restent verbatim ; un substitut peut théoriquement
  déséquilibrer une expression de validation.
- Une coupure de chunk peut laisser un saut de ligne en tête d'un bloc SSE.
- Corpus réel non annoté ; télémétrie coupée par les réglages de jo.

## 6. Déviations à faire valider par jo
- **Allowlist cloud resserrée** à `<service>[.<région>].<cloud>` (le littéral
  couvrant tout le domaine laissait fuir un endpoint de ressource).
- **Règle d'extensions de fichiers** dans `config/allowlist.txt` : rend publics
  les noms de fichiers d'un SEUL label. `.io`, `.ai`, `.dev`, `.app`, `.co` et
  `.sh` en sont volontairement ABSENTS — ce sont des domaines réels.
- **`SERVICE` classé PUBLIC**, à réévaluer sur le corpus réel.
- **Attributs partagés exclus de la vue de restauration.**

## 7. Pièges qui ont coûté du temps

- **`uv run` re-synchronise le venv** de `services/anonshield/upstream` sur le
  lock (torch CPU) et retire fastapi. Relancer `wrapper/install-cuda.sh`, et
  lancer le service par `.venv/bin/python` (ce que fait `run.sh`).
- **Le détecteur doit être REDÉMARRÉ** après toute modification de
  `config/allowlist.txt` ou `config/custom_patterns.json`. Un `pkill` sur le
  nom du module NE L'ATTRAPE PAS (il tourne sous `uvicorn`) : identifier le PID
  par le port 9000 (`ss -lptn | grep 9000`) puis `kill`. Redémarrage ~2 min.
- **`phase3_e2e.sh` a trouvé trois défauts que rien d'autre ne voyait** : un
  schéma invalide (API 400), une collision de substitut (503), et un faux
  positif du hook qui faisait atteindre la limite de tours SANS erreur ni test
  rouge. Le harnais est borné à 6 tours et la session en consomme 6 : elle est
  à la limite, donc parfois instable. Vérifier le nombre de requêtes dans
  `captures/*/bodies/` avant de conclure à une régression.
- **Le hook s'applique à MOI.** Blocages rencontrés en travaillant : prompt de
  sous-agent citant le chemin du coffre ; fichier de test ou de documentation
  dont le CONTENU cite un chemin sensible — les composer par concaténation ;
  heredoc alimentant `python3` dont le corps lit l'environnement (blocage
  CORRECT). Écrire les fichiers par l'outil Write.
- `_SCHEMA` n'est pas une chaîne brute : y écrire un échappement simple donne
  un échappement VIDE. Doubler le backslash.
- Ne jamais lire ni afficher le répertoire d'état du coffre (règle secrets).

## 8. Ce que dix rounds ont appris — à appliquer au round 11

1. **Une approximation à UNE valeur est un contournement en attente.** Chaque
   fois que j'ai modélisé un mécanisme de bash par une seule valeur (une
   alternative d'accolade, une branche d'expansion, un token sauté, la première
   occurrence d'un programme), le round suivant a trouvé le cas où bash en
   produit plusieurs. Émettre TOUTES les possibilités coûte un faux positif
   visible ; en émettre une seule coûte un contournement silencieux.
2. **Énumérer, c'est reporter le défaut.** Les correctifs qui ont tenu sont
   ceux qui changent la STRUCTURE de l'analyse : région imbriquée traitée comme
   une commande, positions de programme au lieu de noms, table d'options PAR
   enveloppe, périmètre des données utilisateur, drapeau hérité. Les listes
   (de motifs, de mots, d'options) ont toutes fini par être prises en défaut.
3. **Une règle qui rend des valeurs PUBLIQUES est la seule dont l'échec soit
   silencieux.** Tout le reste échoue bruyamment (400, 500, 503, commande
   refusée). Une telle règle doit naître avec son test, et son périmètre doit
   être explicite : une entrée EXACTE vaut partout, une règle de FORME suppose
   un contexte.
4. **Un faux positif est aussi grave qu'une fuite.** Un agent qui ne peut plus
   écrire un script, lire un fichier ou committer est cassé. Un faux positif a
   déjà fait échouer une session réelle sans produire ni erreur ni test rouge.
5. **Vérifier les findings soi-même.** Plusieurs rapports contenaient des cas
   faux (une obfuscation citée qui ne reconstruit pas le binaire annoncé) ou
   non reproductibles (moteur construit sans l'allowlist). Corriger sur une
   preuve fausse aurait introduit un vrai défaut.
6. **Les tests aussi peuvent avoir tort**, et les rapports d'agent aussi.
   Trois de mes assertions étaient fausses (une accolade qui n'exécute rien ;
   deux deltas de texte qui sont le tampon de queue, pas un doublon ;
   `printenv HOME`, donné comme contournement, qui n'expose rien). Corriger
   dans le sens du comportement RÉEL, pas dans celui qui arrange — et vérifier
   un « contournement » sur une charge NOCIVE, pas sur l'exemple bénin du
   rapport.
7. **Chercher aussi ce qui n'a jamais été modélisé.** Neuf rounds durant, les
   findings étaient des régressions du round précédent ; au dixième, tous les
   correctifs ont tenu et les dix contournements venaient de mécanismes absents
   du modèle. Relire ses propres correctifs ne suffit plus : il faut relire la
   SPEC de l'objet analysé (ici bash) et cocher ce qu'on n'a jamais traité.
8. **Un motif dont la tête est une classe libre est un déni de service en
   attente.** `\S*\{`, `[\w-]*\.env`, `[\w./-]*secrets?` rétro-traquent à
   chaque position d'un mot long : sept secondes pour vingt mille caractères,
   de quoi noyer un agent sans écrire une commande interdite. Deux des trois
   étaient là depuis le début, jamais chronométrés. Ancrer sur le littéral, et
   MESURER le coût, pas seulement la décision.

## 9. Repères
- Commits : uniquement sur demande de jo, conventional commits, en anglais.
- `PLAN-proxy-pseudonymisation.md` : **jamais modifié**.
- `anthropic_walker.py` : fourni par jo ; seize défauts corrigés, chacun prouvé
  par un test écrit AVANT (`tests/test_walker_defects.py`).
- Données synthétiques uniquement.
