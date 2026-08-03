# Proxy de pseudonymisation Claude Code ↔ API Anthropic

Proxy bidirectionnel : identifiants sensibles → substituts plausibles en sortie,
restauration transparente au retour. L'opérateur voit le réel ; Anthropic n'en
voit rien.

## Documents d'autorité — ordre de préséance
1. `PLAN-proxy-pseudonymisation.md` — spec complète. **NE JAMAIS LE MODIFIER.**
   S'il est faux ou incomplet : le signaler à jo et ATTENDRE.
2. `anthropic_walker.py` — fourni tel quel, intégré en Phase 3. Modifiable
   UNIQUEMENT si un test le met en défaut, test montré à jo AVANT la correction.
3. Ce fichier — réponses verrouillées + état. C'est lui qui survit à la
   compaction : le tenir à jour à chaque fin de phase.
4. `REPRISE.md` — le travail EN COURS, ce qui reste à faire, et les pièges
   déjà payés. **À lire juste après ce fichier à toute reprise de session** :
   une boucle de revue adversariale est en cours et n'est pas terminée.

## Réponses §3 (verrouillées par jo le 2026-08-01 — ne pas re-demander)
1. **Déterminisme : par PROJET par défaut, configurable** (session/projet/
   tenant/global). Le moteur (Phase 2) prend un `scope_key` explicite ; le sel
   HMAC en dérive.
2. **Outils MVP** : kubectl/helm, terraform, gh/git, CLI cloud (aws/OVH/gcloud)
   + outils non encore cadrés → rien de codé en dur par outil ; générique +
   custom patterns (§6 du plan).
3. **Corpus doré** : matière réelle ARCHIVÉE existante (logs/tickets/CI).
   Annotation en Phase 5 seulement.
4. **Attributs préservés** (fuites assumées, à documenter §9) : environnement,
   co-appartenance /24, humain vs service, interne vs externe — les QUATRE.
5. **Coffre : local, même utilisateur** — gap assumé et documenté. Il vit HORS
   du repo (`~/.local/state/anonproxy/` : vault.db + ANON_SECRET_KEY). Ce
   chemin est un SECRET : l'agent ne le lit ni ne l'affiche JAMAIS (règle
   secrets de jo). Mitigation : deny PreToolUse sur ce chemin (Phase 4),
   durcissement Phase 6.

## Règles de travail (non négociables)
- **Une phase à la fois.** Critère de sortie PROUVÉ (commande + sortie
  montrées à jo), puis rendre la main. Jamais deux phases sans accord explicite.
- **Test-first** sur injectivité, fail-closed, streaming SSE — ces trois-là ne
  se déboguent pas après coup.
- **Relire la §7 du plan avant chaque commit** : liste d'interdictions, pas de
  recommandations.
- **Données synthétiques uniquement jusqu'à la fin de la Phase 3** : tout ce
  que lit l'agent part chez Anthropic, fixtures de test comprises. Ne JAMAIS
  demander de logs, configs, kubeconfig ou sorties kubectl réels avant.
- Désaccord avec le plan → argumenter auprès de jo ; ne jamais contourner.
- Commits : uniquement à la demande de jo (conventional commits).

## Décisions verrouillées (résumé — le détail §2 du plan fait foi)
D1 substituts plausibles, JAMAIS de sentinelles `[HOST_1]`/`<IP_3>` ·
D2 zéro résolution dans les partial_json (accumuler → stop → parser → résoudre
atomiquement) · D3 thinking/redacted_thinking opaques (signés) · D4 un secret
est une référence, jamais restauré dans une sortie modèle · D5 fail-closed :
substitut inconnu jamais deviné · D6 injectivité stricte (unicité en base +
CI) · D7 AnonShield en PROCESSUS SÉPARÉ derrière HTTP (GPL-3.0) · D8 MVP
lecture seule (pas de SCIM/RBAC, §8) · D9 le proxy est le seul chemin réseau.

## Frontière GPL
`services/anonshield/**` = côté GPL-3.0 : clone upstream (gitignoré) + notre
wrapper HTTP `/detect` (GPL lui aussi, LICENSE propre). Communication avec le
reste par HTTP uniquement. `src/anonproxy/**` n'importe JAMAIS depuis
`services/anonshield/`.

## Anti-patterns — rappel condensé (§7 du plan fait foi, la relire avant commit)
sentinelles · résoudre en streaming · toucher thinking · ne traiter que le
dernier message · oublier tools[] (descriptions ET input_schema) · deviner un
substitut inconnu · importer AnonShield · restaurer un secret · compter sur les
hooks pour la réversibilité · anonymize en serveur MCP « volontaire » ·
SCIM/RBAC dans le MVP · valider sans capture egress complète.

## État des phases
**775 tests verts** (757 + 18 egress) : `uv run pytest tests/ --ignore=tests/egress`
puis `uv run pytest tests/egress/test_report.py`.

| Phase | État | Preuve |
|---|---|---|
| 0 — Harnais d'egress | critère atteint | `tests/egress_capture.sh` → `captures/*/report.md` code 0 ; 18 tests |
| 1 — AnonShield local | critère atteint | `tests/detect_latency.py` : P95 **100,6 ms** < 150 ms (GPU cu130), regex 2,1 ms, zéro rechargement |
| 2 — Moteur de substituts | critère atteint | `tests/test_surrogate_properties.py` : **10 000 valeurs**, 0 collision, déterminisme octet pour octet, env + /24 + humain/service + interne préservés |
| 3 — Proxy + walker | critère atteint | `tests/phase3_e2e.sh` : session Claude Code RÉELLE, rc=0, **0 valeur réelle sur 427 Ko** capturés (mitmproxy), restauration 3/3 côté opérateur |
| 4 — Hooks PreToolUse | critère atteint | `tests/phase4_e2e.sh` : commande interdite bloquée AVANT exécution, tracée, raison citée par le modèle |
| 5 — Corpus doré | critère atteint (corpus synthétique) | `tests/corpus_eval.py` : 0 fuite, secrets **100 %**, 0 faux positif, variance 0, 0 collision ; 16 scénarios adversariaux (`test_adversarial.py`) |
| 6 — Durcissement | coffre CHIFFRÉ au repos + fail-closed ; KMS/rotation restent à faire | `tests/test_vault_at_rest.py` (7) + `test_hardening.py` (11) + `docs/analyse-re-identification.md` |

## Coffre chiffré au repos (2026-08-02)
La doc affirmait que « la clé + la base sont les deux moitiés du secret » —
c'était FAUX : les valeurs réelles étaient stockées en clair, la base seule
suffisait à tout lire. Corrigé :
- `real_enc` = AES-256-GCM, clé dérivée de la clé maître (HMAC de domaine).
- Recherche par index HMAC (`key_idx`, `real_idx`) : le chiffrement
  authentifié utilise un nonce aléatoire, une recherche directe serait
  impossible. L'index ne révèle qu'une égalité.
- Clé fausse ⇒ `VaultUnavailableError`, jamais une valeur devinée (D5).
- Un coffre au format antérieur est REFUSÉ, pas lu silencieusement.
  Migration : `scripts/migrate_vault.py ANCIEN.db NOUVEAU.db` (n'écrase rien,
  clé lue par référence, jamais affichée). Le recréer à vide ferait perdre la
  restauration des substituts DÉJÀ envoyés à Anthropic.
- Fichiers du coffre remis à 0600 à chaque ouverture (y compris `-wal`/`-shm`).
- Reste hors MVP : chiffrement d'enveloppe KMS/HSM, rotation de clé, journal
  d'accès immuable, protection contre l'énumération.

## D9 — arbitrage jo (2026-08-02) : PAS de pare-feu local
D9 se traite au **déploiement**, pas sur le poste : environnement
conteneurisé, et/ou intégration dans un système plus vaste doté d'un bac à
sable. Ne pas reproposer de règles `nft`/`ufw` locales.

Fait qui invalide toute règle par IP : `api.anthropic.com` et
`mcp-proxy.anthropic.com` résolvent vers **la même adresse** (160.79.104.10).
Un pare-feu ne voit pas les noms d'hôtes → impossible d'autoriser l'API modèle
en bloquant les connecteurs à ce niveau. Les connecteurs se désactivent CÔTÉ
CLIENT (réglages claude.ai), gratuitement.

Forme cible : réseau `internal: true` pour l'agent, le proxy seul à cheval sur
les deux réseaux. Ce n'est pas une règle à maintenir mais une **absence de
route** — rien à contourner, et le problème du « même IP » disparaît. Détail,
variante Kubernetes et points d'attention (DNS, MCP distants, isolation du
coffre) : `docs/d9-blocage-reseau.md`.

**Tant que ce n'est pas déployé ainsi, D9 n'est pas tenue** : le harnais
d'egress détecte, il n'empêche pas. À énoncer tel quel au DPO.

## Comment lancer (ordre)
```bash
services/anonshield/wrapper/install-cuda.sh   # après tout uv sync dans upstream/
services/anonshield/wrapper/run.sh            # détecteur :9000 (GPU)
scripts/run-proxy.sh                          # proxy :8090
ANTHROPIC_BASE_URL=http://127.0.0.1:8090 claude
```

## Quatrième revue adversariale (2026-08-03, round 3 — 3 agents opus effort max)
Deux fuites SORTANTES et deux fuites du hook, toutes corrigées avec
non-régression. Le round a aussi produit **deux régressions de mes propres
correctifs**, attrapées par `phase3_e2e.sh` et pas par les 470 tests unitaires.

**Walker** — `SKIP_KEYS` recopiait VERBATIM tout sous-arbre non scalaire
(`cache_control` enrichi, `metadata.type` structuré) : fail-open silencieux,
requête acceptée en 200 · `_is_known_control` renvoyait `True` pour tout
scalaire, donc n'importe quelle chaîne passait sous `betas` — surface la pire,
l'API IGNORE un nom de beta inconnu et traite quand même la requête.

**Moteur** — un span PUBLIC (`SERVICE`, `PORT`) qui recouvrait un span
substituable GAGNAIT l'arbitrage par sa longueur, et la zone sortait EN CLAIR :
`db-master.acme.internal` intact. `PUBLIC` passe désormais en DERNIER, par
symétrie avec `SECRET` qui passe en premier · le NOM d'un paramètre de query
n'était jamais substitué (`?db-01.acme.internal=1`) ; il l'est quand il porte
un point, une arobase ou deux-points, jamais pour `page`/`limit`/`cursor`.

**Hook** — `_is_local_url` testait le PRÉFIXE `127.` sur un nom d'hôte :
`127.evil.test` résout où son propriétaire veut et passait, avec `curl`,
`wget` et `WebFetch`. L'hôte est comparé comme ADRESSE (`ipaddress`) · les
régions imbriquées (`$(…)`, `` ` ``, `<(…)`, `system(…)`, `subprocess.run([…])`)
sont analysées RÉCURSIVEMENT puis retirées de la commande englobante — c'est ce
qui laissait passer `perl -e 'system("env")'` et `bash <(env)` · enveloppes
`su`/`runuser` et options à valeur (`sudo -u root env`) · l'index pointait
toujours sur la PREMIÈRE occurrence (`env PATH=/x env` passait).

**Faux positifs mesurés et corrigés** (un agent bloqué est aussi cassé qu'un
agent qui fuit) : `set +e` · `env -i`/`env -u` · `command -v env` ·
`compgen -A function` · `echo $(find . -name env)` · `echo $ANTHROPIC_BASE_URL`
· `ls ~/.ssh` · et surtout `grep -r curl src/` — le scan « tous les tokens »
refusait toute MENTION d'un programme réseau.

**Régressions introduites puis corrigées** (les deux via l'E2E réel) :
substituer `"type": ["string","null"]` rend le schéma invalide → API 400,
session interrompue ; `cache_control.ttl` n'accepte que `5m` ou `1h` → 400.
D'où `SCHEMA_STRUCTURAL_KEYS` élargi (`type`, `format`, `pattern`) et
`STRUCTURED_SKIP_KEYS`. Au passage, `"format": "int64"` était substitué DEPUIS
LE DÉBUT sans que rien ne casse : `format` est une annotation, l'API l'ignore.

**Non corrigé, assumé** : `HOSTNAME "acme.internal"` (zone nue) reçoit une
identité propre au lieu de rejoindre la zone fictive de `db-01.acme.internal`.
Le « correctif » évident passerait par `_zone_for`, donc par un attribut
PARTAGÉ — exclu de la vue de restauration : l'hôte deviendrait non
restaurable. La co-appartenance vaut moins que la restauration.

## Cinquième revue adversariale (2026-08-03, round 4 — 3 agents opus effort max)
Le round 3 avait durci des SURFACES ; le round 4 a trouvé que le durcissement
s'appliquait au mauvais PÉRIMÈTRE, plus deux plantages que j'avais introduits.

**Fuite critique — SKIP_KEYS appliqué aux données utilisateur.** `name`, `id`,
`type`, `role`, `data`… étaient recopiés verbatim à CHAQUE niveau, y compris
dans `tool_use.input` et `metadata`, où ce sont des noms de paramètres
ordinaires (kubectl, Terraform, tout CRUD). Double effet : la valeur SORTAIT en
clair, et elle n'était pas RESTAURÉE au retour — l'outil s'exécutait sur l'hôte
FICTIF. Corollaire trouvé en vérifiant : l'opacité était FORGEABLE, un
`{"type": "thinking"}` dans un argument rendait le sous-arbre verbatim. D'où
`USER_DATA_KEYS` : sous `input`/`metadata`, ni SKIP_KEYS ni les blocs opaques
ne s'appliquent.

**Deux plantages introduits au round 3** (aucun test unitaire ne les voyait) :
`_extract_repo` comparait une autorité minuscule avec un `re.split` sensible à
la casse — `https://GitHub.com/…` levait `IndexError`, non rattrapé par le
proxy, donc **500** ; et `https://github.com` seul n'avait rien à découper.
Écrire « visite GitHub.com/torvalds/linux » cassait la session.

**Collision insoluble → 503.** `example.com/` (hôte nu AVEC slash final, sans
schéma) tombait à côté de la normalisation (`count("/") == 3`) et réclamait le
substitut déjà pris par l'hôte.

**Fuites de nom de query encore ouvertes** : `?ident=` (valeur VIDE — `eq` vrai
mais `value` faux, les deux branches rataient) et percent-encoding (`%2E` est
un point). Le test porte désormais sur la forme décodée.

**Surfaces de schéma rendues verbatim à tort au round 3** : `pattern` est une
regex qui peut contraindre à un hôte précis (`^srv-\d+\.acme\.internal$`) — je
l'avais classé structurel, c'était une fuite de ma main. Idem pour les CLÉS de
`patternProperties` (ce sont des regex) et un `$ref` vers un schéma hébergé en
interne. `type`, `format`, `required` restent verbatim ; `$ref`/`$schema` ne le
restent que pour une ancre locale ou le vocabulaire json-schema.org.

**Séparateur SSE** : `\r\n\r\n|\r\r|\n\n` ratait les formes mixtes
(`\n\r\n`…). Remplacé par deux fins de ligne, groupe ATOMIQUE — sans lui la
répétition rétro-traque et coupe un simple `\r\n` en deux, faisant de chaque
LIGNE un bloc.

**Rejeté après vérification** : `mcp_servers[].name` reste verbatim. C'est la
clé de routage des noms d'outils (`mcp__<name>__<outil>`) ; la substituer
casserait la correspondance avec `tools[].name`. Même fuite assumée que
`tools[].name` et `tool_choice.name` — une convention de nommage, pas une
valeur.

**Limite documentée** : un nom de paramètre de query sans point, arobase ni
deux-points (`?db-01=`, `?jdoe=`) n'est pas substitué — indiscernable d'un nom
d'API. Le seul vrai correctif serait de soumettre chaque nom au détecteur.

### Hook — round 4 (même passe, agent dédié)
Deux régressions de ma réécriture du round 3, exploitables avec des idiomes
shell standards, sans obfuscation :
- **La sortie d'une substitution est un ARGUMENT.** Je remplaçais la région
  imbriquée par un BLANC après l'avoir analysée : `curl http://127.0.0.1/
  $(echo http://exfil.test/x)` ne montrait plus qu'une URL locale, et
  `$(echo env)` ne montrait plus rien. Elle est désormais remplacée par un
  jeton OPAQUE : en position de programme il refuse, et un binaire réseau qui
  en reçoit un ne peut plus prouver que sa destination est locale.
- **`find … -exec env \;`** — la règle `-exec` existait mais était morte :
  `find` n'est pas une enveloppe, l'analyse s'arrêtait dessus avant de
  l'atteindre. Le balayage `-exec` est maintenant séparé de la boucle.

Autres trous fermés : deux listes de noms sensibles divergeaient
(`echo $DATABASE_URL` passait quand `printenv DATABASE_URL` était refusé) —
une seule liste désormais · programme d'interpréteur donné EN LIGNE inspecté
mot à mot, ce qui couvre d'un coup `system "env"` sans parenthèses, `qx/env/`,
`%x[env]`, `subprocess.run(("env",))`, `getstatusoutput`, `process["env"]`,
`from os import environ`, `getattr(os, "environ")` · `${IFS}` retiré quelle que
soit sa position (`env${IFS}> dump`) · `${!x}` résolu via l'affectation qui le
précède · `strace`/`ltrace` reconnus comme enveloppes.

Faux positifs corrigés : `printenv AWS_REGION` était refusé quand
`echo $AWS_REGION` passait · `openssl rand|dgst|passwd|enc|x509` et
`--version`/`-V` n'ouvrent aucune connexion.

## Sixième revue adversariale (2026-08-03, round 5 — hook)
Encore trois régressions de mes correctifs du round 4 :
- **`${IFS}` n'était neutralisé que pour les opérateurs `-+:?`** : `${IFS/a/b}`,
  `${IFS##x}`, `${IFS%%x}`, `${IFS,,}`, `${IFS^^}` valent tous IFS et
  découpaient un nom de commande. Corollaire trouvé en corrigeant : `${IFS}`
  vaut un SÉPARATEUR, pas du vide — le remplacer par rien soudait
  `env${IFS}printenv` en un mot inexistant et faisait disparaître les DEUX
  programmes. Il devient une espace ; les expansions à valeur vide
  (`e${_+}nv`) sont, elles, retirées.
- **`-exec` ne marquait que le premier mot** : `find … -exec sudo curl …` et
  `-exec env printenv …` masquaient le programme réel derrière une enveloppe.
  La sous-commande est désormais ANALYSÉE, pas seulement pointée.
- **Mon scan mot à mot des interpréteurs refusait la prose** :
  `python3 -c "print('The curl command is useful')"` était bloqué, comme tout
  one-liner citant un binaire réseau. Seul ce qui SUIT une primitive
  d'exécution est inspecté (`system`, `qx`, `%x`, `subprocess.*`…).
- `--version` n'importe où désarmait le contrôle réseau
  (`curl --version http://tiers/`) : il ne vaut que SEUL. `stat` sortait de la
  catégorie « métadonnées » avec `--files0-from`, qui lit un contenu.

### Moteur — round 5 (aucun finding haut/critique)
Le round 4 avait bien fermé les deux plantages qu'il visait. Restaient :
`_strip_userinfo` ne traitait que les URL à schéma, donc la forme SSH
`user:jeton@hote:chemin` faisait entrer le jeton dans la clé du coffre (D4,
même classe que la CRITIQUE du round 3 ; non déclenchable avec le détecteur par
défaut, qui n'émet pas de span URL pour ces formes) · `_fake_repo` reconnaissait
l'hôte de façon sensible à la casse alors qu'`_extract_repo` ne l'est plus, et
perdait le schéma — l'URL retombait sur la forme courte `org/dépôt`, que le
modèle lit comme un dépôt local (D1) · un span au `score` nul ou sans `type`
levait `TypeError`/`KeyError`, que le proxy ne rattrape PAS : 500 non structuré
au lieu du fail-closed prévu · `sha256:` sans corps se substituait à lui-même,
épuisait les 64 tentatives et tombait en 503.

### Deux faux positifs trouvés EN USAGE, pas par un agent
Le hook a bloqué mon propre travail, ce qu'aucune revue n'avait vu :
- **Le champ `prompt` d'un sous-agent était analysé comme une commande shell** :
  toute prose contenant des backticks markdown passait pour une substitution.
  Le sous-agent a son PROPRE PreToolUse — ses commandes sont gardées à
  l'exécution. `prompt` sort donc de la liste des champs-commandes ; le reste
  de la charge reste soumis aux contrôles coffre et fichiers sensibles.
- **Le corps d'un heredoc CITÉ (`<<'FIN'`) est de la donnée littérale** : bash
  n'y interprète ni substitution ni variable. Il n'est analysé comme du code
  que s'il alimente un interpréteur (`bash <<'FIN'`), pas quand il écrit un
  fichier (`cat > f <<'FIN'`). La cible de la redirection, elle, reste
  contrôlée.

Note d'usage : écrire un test QUI PORTE sur des chemins sensibles demande de
composer ces chemins (`"~/." + "ssh/id_" + "rsa"`), sinon le hook refuse
d'écrire le fichier. C'est cohérent, mais il faut le savoir.

### Walker et proxy — round 5
Le correctif `USER_DATA_KEYS` du round 4 arrêtait la fuite dans `input` et
`metadata`, mais **la même faiblesse restait partout ailleurs** : `SKIP_KEYS`
s'appliquait à CHAQUE dict imbriqué. Un bloc `resource` renvoyé par un serveur
MCP a la forme `{"type":…, "name":…, "uri":…}` — `name` y est une donnée. Fuite
sortante ET échec de restauration au retour. `name` et `id` ne sont désormais
un contrat que dans un nœud de PROTOCOLE (bloc d'outil, définition d'outil,
entrée `mcp_servers`, `tool_choice`, racine de réponse).

Autres correctifs :
- `application/x-` et `application/vnd.` étaient classés BINAIRES, donc
  `x-yaml`, `x-www-form-urlencoded` et `vnd.api+json` — du TEXTE — sortaient en
  clair. Les préfixes binaires sont maintenant énumérés précisément.
- Quatre entrées SSE mal typées (`delta: null`, `content_block: null`,
  `text: null`, `partial_json: null`) tuaient la génératrice SANS émettre
  d'événement `error` : le client perdait le flux en silence. Le générateur
  attrape aussi `TypeError`/`AttributeError`/`ValueError`/`KeyError` et rend
  une erreur SSE exploitable.
- `cache_control` était validé par un jeton générique, qui acceptait
  `{"type": "db-prod01"}`. Chaque sous-clé a maintenant la FORME de sa valeur ;
  une forme inconnue est traversée en mode données.
- Mots-clés JSON Schema 2020-12 substitués donc schéma cassé : `$anchor`,
  `$dynamicAnchor`, `$dynamicRef`, `dependencies`, `dependentRequired`,
  `dependentSchemas`.
- **D3, inversion de la liste des deltas** : `_OPAQUE_DELTAS` était une liste
  d'EXCLUSION, donc un futur `redacted_thinking_delta` aurait été modifié et sa
  signature invalidée — panne dure. C'est maintenant une liste POSITIVE de
  deltas à résoudre. D3 est verrouillée ; la restauration d'un delta inconnu ne
  l'est pas : entre les deux, on protège l'invariant.
- `walk_response` sur un corps JSON non-objet levait `TypeError` (500 non
  structuré) → `ValueError`, rattrapée par le proxy · `message_start` et
  `message_stop` sont restaurés · un `container` SCALAIRE est préservé, sinon
  l'amont ne peut plus réutiliser le conteneur · le tampon SSE est borné à
  16 Mio, au-delà le flux est déclaré invalide.

**Non corrigé, assumé** : une coupure de chunk au milieu d'un `\r\n` peut
laisser un `\n` en tête du bloc suivant — sans effet, `splitlines` ignore une
ligne vide. Retenir le `\r` en attendant la suite ferait PERDRE le dernier bloc
d'un flux se terminant par `\r\r` : le correctif était pire que le défaut.

## Septième revue adversariale (2026-08-04, round 6)
Encore des régressions de mes correctifs du round 5, dont une CRITIQUE.

**Hook — l'expansion emportait le nom de la variable.** En réduisant
`${VAR:-x}` à du vide, je supprimais le NOM : `echo ${AWS_SECRET_ACCESS_KEY:-x}`
passait, alors que bash imprime la vraie valeur. Une expansion est désormais
RÉDUITE à ce que bash en tire — `$VAR` pour les formes dérivées, le texte
littéral pour `${VAR+texte}` (c'est ainsi que `${_+env}` reconstruit `env`).
Ajouté au passage : l'expansion d'accolades (`{env,}`, `c{ur,ur}l`), qui
reconstruit elle aussi un nom de commande.

**Hook — le heredoc consommé par un pipeline.** `cat <<'FIN' | bash` exécute
bien le corps : je ne regardais que la tête (`cat`). Ce qui SUIT le marqueur
sur la même ligne compte aussi.

**Hook — la famille `exec*`/`spawn*`.** Le `\b` de droite ratait `execvp`,
`execlp`, `spawnl`, `pty.spawn`, `pcntl_exec`… La parenthèse est exigée pour
ces formes, sinon le mot « execute » d'une phrase déclencherait l'analyse.

**Hook — la grammaire des options d'enveloppe.** Un jeu global ne peut pas être
juste : `nice -n 10` prend une valeur, `sudo -n` non. Sauter le token suivant
faisait disparaître le programme réel (`sudo -n env`, `flock -w 5 /tmp/l env`).
La table est maintenant PAR enveloppe.

**Hook — les champs d'un outil MCP.** La liste blanche
(`command`/`cmd`/`code`/`script`/`shell`/`args`) ratait `exec`, `program`,
`bash_command`, `pipeline`… Toutes les valeurs sont inspectées, sauf `prompt`.

**Walker — l'heuristique de nœud protocolaire était trop lâche.** Je déduisais
« protocole » de la simple présence d'`input_schema` : or un serveur MCP renvoie
ses définitions d'outils DANS un `tool_result`, où `name` et `id` sont des
données. Le drapeau est désormais HÉRITÉ d'un conteneur de protocole, ce qui
corrige aussi `mcp_servers[].tool_configuration.allowed_tools`, deux crans plus
bas.

**Faux positif trouvé par l'E2E, pas par une revue** : `D=$(ls …)` était REFUSÉ
— une affectation n'exécute pas le résultat de la substitution. La session
réelle a atteint sa limite de tours à force de réessayer, sans aucune fuite ni
erreur d'API. C'est le troisième mode d'échec distinct que seul l'E2E révèle.

**Fuite assumée ajoutée** : `mcp_servers[].tool_configuration.allowed_tools`
reste verbatim. C'est un FILTRE évalué contre les noms exposés par le serveur
MCP — le substituer casserait l'outil en silence. Même arbitrage que
`tools[].name`.

## Huitième revue adversariale (2026-08-04, round 7 — hook)
Cinq contournements, TOUS issus de mes correctifs du round 6. Le pire ratio de
la boucle, et il tient à une même erreur répétée : j'ai modélisé chaque
mécanisme de bash par une approximation à une seule valeur, là où bash en
produit plusieurs ou choisit entre deux branches.

- **Expansion d'accolades** : je gardais l'alternative la plus longue. Bash en
  produit PLUSIEURS mots, préfixe et suffixe recollés — `{curl,autrechose} URL`
  lance bel et bien `curl`. Le mot entier est désormais expansé.
- **Repli d'expansion** : `${x:-env}` vaut le REPLI quand `x` est vide, et bash
  l'EXÉCUTE ; je ne rendais que `$x`. Les deux branches sont maintenant émises,
  séparées par `;` — sans ce séparateur, `$x` occupait la position de programme
  et masquait le repli. Cela referme aussi `${x:-$(env)}`, dont la substitution
  était jetée avec le repli.
- **`env -S`** : sa valeur est une COMMANDE entière, pas un token. Le déclarer
  « option à valeur » faisait sauter le programme.
- **`X= env`** : mon saut de token après une affectation confondait le préfixe
  d'affectation VIDE avec le marqueur d'une substitution. On ne saute plus que
  le marqueur.
- **Heredoc au pipe collé** (`<<'FIN' |bash`) : le découpage sur les espaces
  donnait le token `|bash`, absent des interpréteurs.

**Faux positif réintroduit puis re-corrigé** : `_APPEL_EXEC_RE` balayait la
commande ENTIÈRE, si bien que
`git commit -m 'fix subprocess.run for curl backend'` était refusé — exactement
le défaut que le round 5 venait d'éliminer. La règle est de nouveau réservée au
code donné EN LIGNE ; les formes parenthésées restent couvertes partout par
`_NESTED_RE`.

**Attente de test corrigée** : `{env,foolong}` donne `env foolong`, qui EXÉCUTE
`foolong` au lieu de déverser l'environnement — j'attendais un refus à tort.

### Walker — round 7
- **Le drapeau `protocole` se propageait dans le SCHÉMA.** Posé par `tools`, il
  descendait jusqu'aux clés d'un `input_schema` autres que `properties` :
  `default`, `example`, `const` portent des valeurs d'exemple, où `name` et
  `id` sont des DONNÉES. Un schéma est structurel — aucun nom n'y est une clé
  de routage. Encore une conséquence de mon correctif du round 6.
- **`close()` émettait APRÈS `message_stop`** : ces deltas sont hors protocole,
  donc ignorés en silence par le client ou fatals selon son parseur. Les
  accumulateurs sont désormais vidés à l'arrivée de `message_delta`.
- `walk_request` sur un corps non-objet levait `AttributeError`/`TypeError`,
  que le proxy ne rattrape pas → `ValueError`.

### Faux positif du DÉTECTEUR trouvé par l'E2E — déviation à valider par jo
`tests/phase3_e2e.sh` a commencé à échouer par « limite de tours atteinte ».
Cause : le détecteur classe `infra.md` en URL — `.md` est le TLD de la
Moldavie. **Tout fichier Markdown nommé dans un prompt voyait son extension
muée en faux domaine**, l'agent ne retrouvait plus le fichier désigné et
brûlait ses tours à le chercher. `README.md`, `CLAUDE.md`, un plan : c'est
constant dans un contexte d'agent.

Ajouté à `config/allowlist.txt` : une regex couvrant les extensions dont
l'usage comme nom d'hôte interne est invraisemblable. `.io`, `.ai`, `.dev`,
`.app`, `.co` et `.sh` en sont volontairement ABSENTS — ce sont des domaines
réellement utilisés. **Le détecteur doit être redémarré** après ce changement.

## Défauts corrigés dans `anthropic_walker.py` (règle 6 — tests fournis AVANT)
`tests/test_walker_defects.py` prouve les quatre, corrections minimales
(le 4ᵉ vient de la revue adversariale) :
0. **Fail-open sur les surfaces** — seules `system`/`messages`/`tools`/
   `metadata` étaient traversées ; `stop_sequences`, `mcp_servers`,
   `container`, `tool_choice` fuyaient, et la capture réelle montre déjà
   `context_management`/`output_config`/`thinking` au premier niveau. Fix :
   traverser TOUT sauf `REQUEST_CONTROL_KEYS`.
1. **Plantage** `TypeError: unhashable type: 'dict'` — `node.get("type")` testé
   sur un frozenset alors qu'une propriété de schéma peut s'appeler « type ».
   Observé en session réelle → 500, Claude Code s'arrête. Fix : garde `isinstance(str)`.
2. **Fuite** — la branche `properties` était morte (« properties » figurait
   dans `SCHEMA_STRUCTURAL_KEYS`, testé avant) : la description d'une propriété
   nommée `name`/`id`/`data` n'était PAS substituée (SKIP_KEYS s'appliquait aux
   noms de propriétés). Fix : brancher `properties` d'abord.
3. **Corruption** — `$schema`, `$ref`, `required` étaient substitués →
   API 400 « JSON schema is invalid », et `required` ne correspondait plus aux
   noms de propriétés. Fix : ces clés sont recopiées verbatim ; nouveau
   `SCHEMA_NESTED_KEYS` pour `additionalProperties`/`items`.

## Revue adversariale (2026-08-02, 3 agents opus effort max)
Findings prouvés, corrigés, avec non-régression dans
`tests/test_review_regressions.py` et `test_pretooluse_hook.py` :

**Fuites du proxy** — passthrough transmettait le corps brut sur tout chemin
non modélisé (`/v1/messages/batches`, `/v1/complete`) → 501 fail-closed ·
`walk_request` n'énumérait que 4 surfaces alors que l'API en a d'autres
(`stop_sequences`, `mcp_servers`, `container`, `tool_choice`) → traversée
inversée (tout sauf `REQUEST_CONTROL_KEYS`) · `MIN_LEN=7` laissait passer
`db01`, `jdoe`, tout identifiant court → supprimé · le mode `regex` sur gros
volumes désactivait le NER → découpage avec recouvrement à la place ·
chemin d'URL laissé en clair (`registry.X/payments/api` → hôte masqué,
chemin nu) → segments et valeurs de query substitués.

**Moteur** — un attribut partagé pouvait se substituer à LUI-MÊME (zone
`lamna.internal`, préfixe `172.22.96.0` en clair) : garde `candidat == réel`
manquante dans `_alloc_shared` · spans invalides (inversés, hors bornes)
dupliquaient la valeur réelle → validation stricte, fail-closed · un même
hôte vu comme HOSTNAME/FQDN/CERT_CN ou en casses différentes recevait
jusqu'à 4 identités fictives → clé de coffre canonique · recouvrement
partiel laissait la fin d'un domaine en clair → les fragments non couverts
sont conservés · tag d'image préservé (SHA, branche, nom de client) →
substitué sauf version publique · type interne `_SUBNET_V4` forgeable →
refusé.

**Hook** — la détection était POSITIONNELLE : `/usr/bin/env`, `command env`,
`bash -c env`, `printenv VAR`, `an[o]nproxy`, `cat .env|xxd` passaient tous.
Remplacé par normalisation (quoting, globs, backslashes) + tokenisation.
Ajout : `/dev/tcp`, réseau embarqué (python/node/perl), `k`/`oc`,
`kubectl exec|cp`, `helm get values`, tfstate, jetons cloud, WebFetch sortant,
outils non énumérés (MultiEdit, LS, Task, MCP), charges non-string.

**Tests complaisants** — le compteur de collisions était tautologique
(itérait les clés d'un dict, uniques par construction) → lignes brutes +
sonde active d'injectivité · la recherche de fuite ratait `\uXXXX` et `%XX`
(donc tout accent) → normalisation avant recherche · dictionnaire de valeurs
sensibles complété et dérivé de la fixture · assertions affaiblies par des
`or` de repli supprimées.

## Suites de la revue (2026-08-02, second passage)
- `walk_response` ne restaurait que `content` → tout le corps, plus les
  événements SSE `message_delta` / `error` (écho de `stop_sequence`).
- Cache du pipeline **clé par portée** (sinon un Pseudonymizer réutilisé entre
  deux portées servait le substitut de la première).
- Query params relayés sur `/v1/messages` et `count_tokens` (`?beta=true`).
- Plausibilité (D1) : version et variante d'UUID recopiées, notation MAC Cisco
  préservée, préfixe `sha256:` conservé, `PERSON` garde son nombre de mots,
  littéral IPv6 dans une URL géré, espace d'hôte IPv6 porté à 64 bits.
- Unicode NFC en canonicalisation (`café` composé ≡ décomposé) — les
  homoglyphes cyrilliques restent DISTINCTS, sinon deux réels partageraient un
  substitut.
- Journal d'audit : les `allow` sont désormais tracés par empreinte SHA-256
  tronquée (chronologie post-incident sans copier l'activité).
- Preuve Phase 4 : marqueur unique par exécution (`ANONPROXY_DENY_MARKER`) au
  lieu d'un grep sur des mots-clés que la prose du modèle pouvait satisfaire.
- Corpus de propriété étendu à 10 300 valeurs : IPv6 denses, IP publiques,
  hôtes hors `.internal`, noms très courts/longs, échappements JSON, Unicode,
  préfixes stricts, UUID de versions variées, MAC des trois notations.
- Garde-fou anti-complaisance dans `test_proxy_e2e.py` : le faux détecteur
  ÉCHOUE bruyamment s'il ne couvre pas une valeur de la fixture, au lieu de
  rendre le test vert pour la mauvaise raison.

**Résiduel documenté** : l'allocation dépend de l'ordre d'insertion pour les
substituts qui entrent en collision de tirage — ramené de **40 % à ~4 %** en
composant deux mots dès la première tentative. Sans effet en pratique (un
projet n'a qu'un coffre, créé une fois) ; compte pour la reproductibilité
d'une reconstruction de coffre. Borné par `test_ordre_d_insertion_effet_borne`.

## Troisième revue adversariale (2026-08-02, après /simplify)
Failles trouvées APRÈS deux passes de revue — toutes corrigées, toutes avec
non-régression dans `tests/test_review_regressions.py` :
- **CRITIQUE — mot de passe d'URL en clair.** `_fake_authority` découpait sur
  le premier « : » : `https://alice:motdepasse@hôte.réel/` donnait `alice`
  pour hôte et recopiait `:motdepasse@hôte.réel` en guise de port. Le mot de
  passe ET le domaine réel partaient. RFC 3986 appliquée ; les identifiants
  sont désormais traités comme des secrets (D4).
- **CRITIQUE — jeton restaurable via le coffre.** Une URL de dépôt portant un
  jeton (`https://oauth2:ghp_…@github.com/org/repo`) stockait le jeton dans la
  colonne `real` : il redevenait restaurable, violation de D4. L'userinfo est
  retiré avant la canonicalisation.
- **CRITIQUE — hôte d'URL non enregistré.** `_fake_authority` appelait
  `_fake_host` directement, hors coffre : le substitut restait libre et un
  AUTRE hôte réel pouvait l'obtenir → la restauration désignait la mauvaise
  machine (D6). Passe désormais par `substitute_value`.
- **MAJEUR — fragment d'URL (`#…`) jamais substitué** : traité comme une paire
  `nom=valeur`, donc ignoré. `#tenant-acme-nda` partait en clair.
- **MAJEUR — IPv6 sans crochets** : tout ce qui suivait le premier « : » était
  recopié tel quel.
- **MAJEUR — une URL réduite à un hôte recevait sa propre identité**, donc
  deux machines fictives pour un seul serveur réel.
- **MODÉRÉ — un mot du lexique pouvait coïncider avec un mot du réel**
  (`gateway-021` → `gateway-registry-021`, ~2 % des cas) : le tirage évite
  maintenant les mots présents dans l'entrée.
- **Tests complaisants** : le garde-fou du FakeDetector acceptait une
  couverture PARTIELLE (`c in reel`) — un motif e-mail affaibli laissait fuir
  `alice.dupont` sans qu'aucun test ne bronche ; l'assertion de recouvrement
  ne cherchait qu'une seule sous-chaîne ; le test d'identité unique oubliait
  le type URL. Les trois sont durcis, plus des assertions de fuite PARTIELLE.

**Régression introduite puis corrigée pendant ces correctifs** : unifier
l'hôte nu a fait entrer en conflit deux entrées de coffre pour un même
substitut (`https://x` vs `https://x/`, spans avec points de troncature) —
503 en pleine session, attrapé par `phase3_e2e.sh`, pas par les tests
unitaires. C'est l'argument pour garder les preuves E2E réelles.

## Déviations assumées à valider par jo
- **Allowlist cloud resserrée vs §6 du plan** : `*.amazonaws.com` littéral
  laissait fuir `db-prod.cluster-abc123.eu-west-3.rds.amazonaws.com` (endpoint
  de RESSOURCE, porte l'identifiant du compte). Seule la forme
  `<service>[.<région>].<cloud>` est allowlistée. Mesuré par `corpus_eval.py`.
- **`SERVICE` (modèle cyber) classé PUBLIC** : se déclenche massivement sur de
  la prose technique. À réévaluer sur le corpus réel.
- **Attributs partagés exclus de la vue de restauration** : sinon un substitut
  halluciné (`canyon-02-prod.<zone connue>`) était partiellement résolu en
  `canyon-02-prod.<zone RÉELLE>` — hôte fictif déguisé en hôte réel (D5).

## Découvertes Phase 0 (2026-08-01) — mises à jour le 2026-08-02
- **Datadog** : le 2026-08-01, ~343 Ko partaient vers
  `http-intake.logs.us5.datadoghq.com` (feature-flag statsig
  `tengu_log_datadog_events`, flush ~15 s). Le 2026-08-02, `tests/datadog_probe.sh`
  ne capte plus rien — mais **ce n'est pas une preuve** : jo a depuis posé
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `DISABLE_TELEMETRY=1`,
  `DISABLE_ERROR_REPORTING=1` et `DO_NOT_TRACK` dans `~/.claude/settings.json`.
  Ces variables sont injectées par Claude Code indépendamment de
  l'environnement du script : la sonde tournait donc télémétrie DÉJÀ coupée.
  Conclusion tenable : la coupure fonctionne. Le CONTENU des payloads reste
  non inspecté. Pour le mesurer un jour, il faut neutraliser ces variables au
  niveau des settings (`--settings` sur un fichier temporaire), pas de l'env.
  Datadog reste volontairement ABSENTE de `known_destinations.json` : sa
  réapparition doit faire ÉCHOUER le garde-fou.
- **Quatre destinations sur cinq échappent au proxy** (mesuré) :
  `mcp-proxy.anthropic.com` ×12, `mcp.context7.com` ×11, `registry.npmjs.org`
  ×4, `api.githubcopilot.com` ×2 — contre `api.anthropic.com` ×5 qui est le
  seul canal 1. Détail et politique pare-feu : `docs/d9-blocage-reseau.md`.
- `mcp-proxy.anthropic.com` (connecteurs claude.ai Gmail/Calendar/Drive) ne
  passe PAS par `ANTHROPIC_BASE_URL` → il échappera au proxy de la Phase 3.
  Surface canal 2, à traiter par PreToolUse en Phase 4.
- `api.githubcopilot.com` = serveur MCP distant du plugin github officiel.
- La télémétrie passe aussi PAR `api.anthropic.com` (`/api/event_logging/…`,
  `/api/claude_cli/bootstrap`…) → en Phase 3, le proxy ne réécrit que
  `/v1/messages` et `count_tokens` ; le reste transite tel quel et reste
  surveillé par ce harnais.
- Limite du harnais : proxy explicite (`HTTPS_PROXY`) — un processus en
  sockets bruts le contourne ; réponse définitive = D9 (pare-feu, Phase 6).

## Notes d'intégration AnonShield (Phase 1 — API lue le 2026-08-01)
- Upstream épinglé `d82f917` (2026-07-27), cloné dans
  `services/anonshield/upstream/` (gitignoré) depuis `.repos/anonshield`.
  Wrapper : `services/anonshield/wrapper/` (GPL-3.0), port 9000, `run.sh`.
- **Clé** : `ANON_SECRET_KEY_FILE` est supporté nativement par
  `src/anon/security.py` (priorité sur `ANON_SECRET_KEY`). Persistée par
  run.sh dans `~/.local/state/anonproxy/anon_secret_key` (0600), JAMAIS
  affichée. Sauvegarder ce dossier : clé + base = les deux moitiés du secret.
- **Chemin API retenu** : `AnonymizationOrchestrator(strategy_name="filtered",
  transformer_model=…)` puis `.analyzer_engine.analyzer_engine.analyze()`
  (l'`AnalyzerEngine` presidio interne — seul chemin qui renvoie les SCORES).
  Mode `regex` (gros volumes) : `EntityDetector.extract_regex_entities()`,
  zéro NER. Périmètre d'entités : `get_supported_entities("filtered")` =
  types custom + mapping du modèle, PAS les builtins presidio (faux positifs).
- **Pièges** : (1) `import src.anon.config` lit la clé À L'IMPORT → run.sh pose
  l'env AVANT ; (2) `orchestrator.detect_entities()` ne renvoie pas les scores
  et saute les textes sans entités → ne pas l'utiliser ; (3) `engine.py` patche
  `HFTokenPipe` à l'import (fenêtre glissante >400 tokens) — le warm-up doit
  passer un texte long pour chauffer ce chemin ; (4) fastapi/uvicorn ne sont
  PAS dans les deps de base et torch est épinglé CPU dans le lock →
  `wrapper/install-cuda.sh` après CHAQUE `uv sync`/`uv run` dans upstream/
  (uv run re-sync le lock !) ; lancement service via `.venv/bin/python`
  direct uniquement (run.sh). Évite aussi celery/redis/pt_core du groupe web.
- Mapping SecureModernBERT : DOMAIN→HOSTNAME, IPV4/6→IP_ADDRESS,
  MD5/SHA1/SHA256→HASH, FILEPATH→FILE_PATH, + ORG/LOC/EMAIL/URL/CVE….
- Recognizers regex fournis couvrant la future classe SECRET (Phase 2) :
  `AUTH_TOKEN`, `JWT`, `PRIVATE_KEY_PEM`, `PASSWORD_CONTEXT`,
  `COOKIE_SESSION`, `CERT_*`, `RSA_MODULUS`, `PGP_BLOCK`.
- Config en TERRAIN NEUTRE : `config/allowlist.txt` (§6, exact + `re:`
  full-match) et `config/custom_patterns.json` (exemples synthétiques — les
  conventions RÉELLES s'écrivent avec jo, de préférence après Phase 3). Le
  service de détection ET le moteur de substituts les lisent : « ce token est
  public » ne se maintient qu'à un seul endroit. Le PARSEUR est dupliqué de
  part et d'autre de la frontière D7 (dix lignes, contre une dépendance de
  licence) — c'est la liste qui compte, pas le code de lecture.

## Latence Phase 1 — RÉSOLUE (2026-08-02, décision jo : option a, reboot + CUDA)
- Historique : en CPU le critère <150 ms était inatteignable (fp32 ~800 ms,
  int8 567 ms, spaCy 22 ms — il manquait ~6×). Le reboot a réparé le mismatch
  pilote NVIDIA ; RTX 4090 Laptop 16 Go opérationnelle.
- **Déviation CUDA documentée et scriptée** : `wrapper/install-cuda.sh`
  installe torch 2.13.0+cu130 (`--reinstall` obligatoire : sinon uv considère
  le wheel +cpu du lock comme satisfaisant) + fastapi/uvicorn.
- **PIÈGE uv critique** : `uv sync` ET `uv run` (sync implicite) restaurent
  les wheels CPU du lock et retirent fastapi/uvicorn → ré-exécuter
  `install-cuda.sh` après tout `uv sync`/`uv run` dans upstream/ ; le service
  se lance UNIQUEMENT via `.venv/bin/python` direct (fait par run.sh).
- Index cu128 sans torch 2.13.0 ; cu130/cu129/cu126 l'ont (pilote 580 =
  famille CUDA 13 → cu130 retenu).
- Résultat final : P95 100,6 ms (min 94,5 / p50 99,3 / max 101,5) sur 2 Ko,
  30 requêtes, stabilité 99,6/97,6 ms entre moitiés ; regex 2,1 ms ;
  chargement 12,3 s (cache HF).
- Fait notable (à réévaluer en Phase 5) : sur le texte de log synthétique, le
  NER brut renvoie 0 entité — TOUTES les détections viennent des recognizers
  regex. Le rapport coût/valeur du modèle sur des logs infra reste à mesurer
  sur le corpus doré.

## Environnement (relevé 2026-08-01)
uv 0.11.32 · Python 3.12.3 · node 24 · claude 2.1.220 · kubectl + kind +
docker présents · mitmproxy via `uv tool install mitmproxy` · Phase 0 sans
pyproject (stdlib seul) ; le packaging uv arrive avec les Phases 1-2.
