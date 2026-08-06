# D9 — le proxy comme seul chemin réseau

> « Un contrôle contournable n'est pas un contrôle. » (plan §2, décision D9)

Le proxy (canal 1) et le hook `PreToolUse` (canal 2) protègent le chemin
NORMAL. Ni l'un ni l'autre n'empêche un processus déterminé d'ouvrir une
socket directe. D9 exige donc une contrainte que l'agent ne peut pas lever
lui-même.

**Arbitrage jo (2026-08-02) : pas de mise en place sur le poste.** D9 se
traite au niveau du DÉPLOIEMENT — environnement conteneurisé, et/ou intégration
dans un système plus vaste disposant déjà d'un bac à sable. Ce document décrit
la contrainte à satisfaire, pas une procédure à exécuter localement.

## Ce qui échappe au proxy, mesuré

`tests/datadog_probe.sh`, session synthétique du 2026-08-02, 34 flux :

| Destination | Flux | Passe par `ANTHROPIC_BASE_URL` ? |
|---|---|---|
| `mcp-proxy.anthropic.com` | 12 | **non** — connecteurs claude.ai |
| `mcp.context7.com` | 11 | **non** — serveur MCP distant |
| `api.anthropic.com` | 5 | oui — c'est le canal 1 |
| `registry.npmjs.org` | 4 | **non** — installation de serveurs MCP |
| `api.githubcopilot.com` | 2 | **non** — serveur MCP du plugin github |

**Quatre destinations sur cinq échappent au proxy.** Aucune ne transporte la
conversation modèle, mais toutes transportent des requêtes formulées par
l'agent — donc potentiellement des identifiants internes dans une requête MCP.

## Pourquoi une règle par IP ne peut pas marcher

```
api.anthropic.com        → 160.79.104.10
mcp-proxy.anthropic.com  → 160.79.104.10
```

**Même adresse.** Un pare-feu réseau ne voit pas les noms d'hôtes : il est donc
impossible d'autoriser l'API modèle tout en bloquant les connecteurs par une
règle IP. Toute politique qui prétend séparer les deux à ce niveau est fausse.

Deux conséquences :

1. **Les connecteurs claude.ai se désactivent côté client**, dans les réglages
   de connecteurs — pas au réseau. C'est gratuit, réversible, et ça retire 12
   flux sur 34.
2. La contrainte réseau utile n'est pas « bloquer telle destination » mais
   **« l'agent n'a aucun chemin de sortie, sauf le proxy »**. Formulée ainsi,
   elle ne dépend ni des IP (qui changent), ni du DNS, ni du SNI.

## La forme cible : une absence de route, pas une règle

Dans un environnement conteneurisé, D9 ne s'exprime pas par une règle de
filtrage à maintenir mais par une **topologie** : l'agent vit sur un réseau
sans route vers l'extérieur ; le proxy est le seul à avoir un pied des deux
côtés.

```yaml
# docker compose — la forme canonique
services:
  agent:                     # Claude Code
    networks: [interne]      # aucune route sortante
    environment:
      ANTHROPIC_BASE_URL: http://proxy:8090
  proxy:
    networks: [interne, externe]
    depends_on: [detecteur]
  detecteur:                 # AnonShield, côté GPL
    networks: [interne]      # n'a jamais besoin de sortir

networks:
  interne:
    internal: true           # ← c'est TOUTE la politique
  externe: {}
```

C'est strictement plus fort qu'une règle `drop` : il n'y a rien à contourner,
puisqu'il n'y a pas de route. Le problème du « même IP » disparaît de lui-même
— l'agent ne joint ni `api.anthropic.com` ni `mcp-proxy.anthropic.com`, et le
proxy ne relaie que ce qu'il sait pseudonymiser.

Points d'attention pour cette forme :

- **DNS** : sur un réseau `internal`, l'agent ne résout plus les noms publics.
  C'est cohérent (il n'a rien à joindre publiquement) mais certains outils
  échouent bruyamment plutôt que proprement. À vérifier au cas par cas.
- **Serveurs MCP distants et `npm install`** cessent de fonctionner depuis
  l'agent. C'est l'effet recherché ; s'il faut en garder, ils passent par le
  réseau externe via un relais explicite, ce qui les rend visibles et
  arbitrables au lieu d'être implicites.
- Le **coffre** doit rester hors du conteneur de l'agent (volume monté côté
  proxy uniquement) : c'est ce qui ferme enfin le gap « coffre local, même
  utilisateur » de la réponse §3.5.

### Kubernetes

Même principe : `NetworkPolicy` d'egress sur le pod agent, n'autorisant que le
service du proxy ; le proxy porte sa propre politique d'egress vers
`api.anthropic.com`. La séparation des identités (ServiceAccount distinct pour
le proxy) donne au passage l'isolation du coffre.

### Intégration dans un système à bac à sable

Si l'hôte dispose déjà d'un mécanisme de sandbox avec contrôle d'egress, D9 se
réduit à une ligne de politique : **déclarer le proxy comme unique destination
autorisée** pour le processus agent. C'est le cas le plus simple, et le plus
probable en pratique.

## Ce qui reste vrai en attendant

Le harnais d'egress (Phase 0) est le garde-fou de non-régression : il
inventorie ce qui sort et **échoue** sur toute destination non justifiée. Il
détecte, il n'empêche pas.

C'est la différence entre un contrôle et une alarme — et c'est pourquoi **D9
n'est pas tenue tant que le déploiement n'est pas conteneurisé ou encadré par
un bac à sable**. À énoncer tel quel dans l'analyse de risque : le proxy
réduit la surface, il ne la ferme pas.
