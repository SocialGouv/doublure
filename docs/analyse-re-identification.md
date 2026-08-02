# Analyse du risque de ré-identification

> Livrable attendu par le DPO (plan §9). État : **MVP** — à compléter avec le
> DPO avant toute mise en service sur des données réelles.

## 1. Ce que le proxy garantit

Aucun identifiant détecté (hôte, IP, e-mail, dépôt, image, compte de service,
secret) ne quitte la machine en clair par le canal 1. Vérifié par capture
mitmproxy en session réelle : `tests/phase3_e2e.sh` → 0 occurrence sur
427 Ko sortants, et par `tests/corpus_eval.py` sur le corpus annoté.

## 2. Fuites ASSUMÉES — les quatre attributs préservés

Réponse §3.4 de jo : les quatre attributs sont conservés parce que le modèle
en a besoin pour raisonner juste. Chacun est une fuite d'information, ici
documentée pour ce qu'elle est.

| Attribut préservé | Ce qu'Anthropic peut en déduire | Pourquoi on l'accepte |
|---|---|---|
| **Environnement** (`-prod`, `-staging`) | La répartition prod/staging/dev de l'infrastructure, et donc sa taille relative | Sans lui, le modèle ne peut pas calibrer le risque d'une action : il traiterait la prod comme un bac à sable |
| **Co-appartenance /24** | La topologie réseau : combien de sous-réseaux, combien d'hôtes par sous-réseau, quels hôtes cohabitent | Le raisonnement réseau (routage, pare-feu, blast radius) est inopérant sans elle |
| **Humain vs service** | Le ratio comptes humains / comptes techniques, donc un ordre de grandeur de la taille d'équipe | Un incident de compte de service ne se traite pas comme un incident de compte humain |
| **Interne vs externe** | La frontière du périmètre : ce qui est à nous, ce qui est chez un tiers | Distinguer une dépendance publique d'un service interne est la base de l'analyse de surface d'attaque |

## 3. La limite structurelle (plan §9)

**Une substitution parfaite ne rend pas anonyme.** Ce qui identifie n'est plus
le nom mais la **structure** :

- qui commite sur quoi, à quelle fréquence, avec qui ;
- quels rôles, quelle taille d'équipe, quels horaires ;
- la forme du graphe de dépendances entre services.

Un graphe pseudonymisé se ré-identifie dès qu'existe une information
auxiliaire : activité GitHub publique, organigramme, offres d'emploi,
conférences. Aucune amélioration de la tokenisation ne corrige cela.

### Mitigation réelle : la minimisation à la frontière des outils

C'est le levier efficace, et il n'est PAS dans le proxy :

- ne pas envoyer 4 000 lignes de `git log` quand un agrégat répond ;
- ne pas envoyer la liste nominative quand « 12 principals portent ce rôle,
  dont 3 comptes de service » suffit ;
- préférer `kubectl get pods -o name | wc -l` à un dump complet.

**Statut : non implémenté dans le MVP.** Ce serait un broker d'outils typé
(cf. AgentWall, plan §5 Phase 4, tâche 3), qui agrège avant d'envoyer. À
arbitrer avec jo : c'est le chantier à plus fort rendement pour la vie privée
une fois le MVP en service.

## 4. Autres risques résiduels

| Risque | Statut | Mitigation |
|---|---|---|
| **Coffre lisible par l'agent** (réponse §3.5 : local, même utilisateur) | Assumé | Hook PreToolUse (`hooks/pretooluse_guard.py`) refuse tout accès au chemin du coffre et à la clé ; testé (`test_pretooluse_hook.py`). Un compte Unix dédié fermerait le gap. |
| **Canal 2** (Bash, WebFetch, MCP appelant le réseau) | Partiellement traité | Le hook bloque les sorties réseau directes et les dumps de secrets. Il ne pseudonymise pas : par construction (§7), il n'y a pas de chemin de retour. Réponse définitive = D9 (pare-feu). |
| **Serveurs MCP distants et connecteurs** ne passent pas par `ANTHROPIC_BASE_URL` | Ouvert | Mesuré : `mcp-proxy.anthropic.com` ×12, `mcp.context7.com` ×11, `registry.npmjs.org` ×4, `api.githubcopilot.com` ×2 sur une seule session — soit 4 destinations sur 5 hors du proxy. Ils ne portent pas la conversation, mais portent des requêtes formulées par l'agent. À arbitrer : `docs/d9-blocage-reseau.md`. |
| **Télémétrie Datadog** du binaire Claude Code | Coupée, contenu inconnu | Observée à ~343 Ko/session le 2026-08-01 ; absente le 2026-08-02 après ajout de `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` / `DISABLE_TELEMETRY=1` / `DISABLE_ERROR_REPORTING=1` dans `~/.claude/settings.json` (`tests/datadog_probe.sh`, 34 autres flux capturés au même moment). La coupure est donc efficace. Le CONTENU des payloads n'a jamais pu être inspecté : pour le faire il faut lancer la session avec un fichier de settings temporaire sans ces variables — l'environnement du script ne suffit pas à les neutraliser. |
| **Volume et rythme des requêtes** | Non mitigé | Même pseudonymisé, le PROFIL temporel d'activité est visible côté fournisseur (nombre de tours, taille des contextes, heures de travail). |
| **Noms d'outils MCP** (`payments_api__query`) | Ouvert | `SKIP_KEYS` du walker préserve `name` : un nom d'outil encodant un service interne fuite. À traiter au niveau du serveur MCP (renommer en cours de route casserait la correspondance au retour). |
| **Déterminisme par projet** (réponse §3.1) | Assumé | Un substitut est stable dans le projet : deux sessions du même projet sont corrélables entre elles côté fournisseur. C'est le prix du cache de prompt. Passer en `session:` supprime la corrélation et le cache. |

## 5. Ce qui reste à faire avant une mise en service réelle

1. Annoter le corpus réel et rejouer `tests/corpus_eval.py --real` (Phase 5).
2. Fixer avec jo les seuils de rappel par classe d'identifiant.
3. Trancher la politique Datadog et `mcp-proxy.anthropic.com`.
4. Déployer en environnement conteneurisé ou sous bac à sable : c'est la seule
   forme où D9 est tenue (arbitrage jo du 2026-08-02 — pas de pare-feu sur le
   poste). Tant que ce n'est pas fait, **le proxy réduit la surface, il ne la
   ferme pas** : cf. `docs/d9-blocage-reseau.md`.
5. Revue juridique / DPO sur la base du présent document.
6. Chiffrement d'enveloppe du coffre (KMS/HSM), rotation de clé, journal
   d'accès immuable — non implémentés dans le MVP.
