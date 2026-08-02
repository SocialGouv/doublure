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
**337 tests verts** (319 + 18 egress) : `uv run pytest tests/ --ignore=tests/egress`
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

## Comment lancer (ordre)
```bash
services/anonshield/wrapper/install-cuda.sh   # après tout uv sync dans upstream/
services/anonshield/wrapper/run.sh            # détecteur :9000 (GPU)
scripts/run-proxy.sh                          # proxy :8090
ANTHROPIC_BASE_URL=http://127.0.0.1:8090 claude
```

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
