# D9 — le proxy comme seul chemin réseau

> « Un contrôle contournable n'est pas un contrôle. » (plan §2, décision D9)

Le proxy (canal 1) et le hook `PreToolUse` (canal 2) protègent le chemin
NORMAL. Ni l'un ni l'autre n'empêche un processus déterminé d'ouvrir une
socket directe. La réponse définitive est un blocage au pare-feu.

## Ce que l'on observe réellement

Mesuré par `tests/datadog_probe.sh` (session synthétique, télémétrie non
désactivée, 2026-08-02) — 34 flux vers 5 destinations :

| Destination | Flux | Passe par `ANTHROPIC_BASE_URL` ? |
|---|---|---|
| `mcp-proxy.anthropic.com` | 12 | **non** — connecteurs claude.ai |
| `mcp.context7.com` | 11 | **non** — serveur MCP distant |
| `api.anthropic.com` | 5 | oui — c'est le canal 1 |
| `registry.npmjs.org` | 4 | **non** — installation de serveurs MCP |
| `api.githubcopilot.com` | 2 | **non** — serveur MCP du plugin github |

**Quatre destinations sur cinq échappent au proxy.** Aucune ne transporte la
conversation modèle, mais toutes transportent des requêtes formulées par
l'agent (donc potentiellement des identifiants internes dans une requête MCP).

### Datadog : la coupure fonctionne, le contenu reste inconnu

La Phase 0 (2026-08-01) avait mesuré ~343 Ko envoyés à
`http-intake.logs.us5.datadoghq.com`. La sonde du 2026-08-02 ne capte **aucun**
flux Datadog, alors que le harnais voyait bien 34 autres flux.

**Attention à la lecture.** Entre les deux mesures, `~/.claude/settings.json`
a reçu `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `DISABLE_TELEMETRY=1`,
`DISABLE_ERROR_REPORTING=1` et `DO_NOT_TRACK`. Claude Code injecte le bloc
`env` de ses settings dans la session : ne pas poser la variable dans
l'environnement du script ne suffit donc pas à la neutraliser. La sonde a
tourné télémétrie déjà coupée.

Ce qui est établi : **la coupure par settings fonctionne** (deux mesures
concordantes). Ce qui ne l'est pas : le contenu des payloads, jamais inspecté
faute de flux à inspecter.

Pour le mesurer, il faudrait lancer la session avec un fichier de settings
temporaire dépourvu de ces variables (`claude --settings /tmp/probe.json`), et
non en jouant sur l'environnement. Tant que ce n'est pas fait, Datadog reste
**volontairement absent** de `tests/egress/known_destinations.json` : sa
réapparition doit faire ÉCHOUER le garde-fou d'egress, pas passer inaperçue.

## Politique proposée (à valider par jo)

Le principe : autoriser en sortie ce qui est nécessaire, refuser le reste, et
n'autoriser `api.anthropic.com` **que** depuis le processus du proxy.

```bash
# Groupe dédié : seuls les processus du proxy peuvent joindre l'API modèle.
sudo groupadd -f anonproxy-net
# lancer le proxy sous ce groupe : sg anonproxy-net -c 'scripts/run-proxy.sh'

# nftables — squelette, à adapter à la distribution
sudo nft add table inet anonproxy
sudo nft add chain inet anonproxy output \
  '{ type filter hook output priority 0; policy accept; }'

# 1. api.anthropic.com : réservé au groupe du proxy
sudo nft add rule inet anonproxy output \
  ip daddr @anthropic_ips tcp dport 443 skgid != anonproxy-net drop

# 2. connecteurs et MCP distants : refusés tant qu'ils ne sont pas arbitrés
sudo nft add rule inet anonproxy output ip daddr @mcp_proxy_ips drop
```

Points d'attention :

- Les adresses d'`api.anthropic.com` changent (CDN) : résoudre régulièrement
  et alimenter un `set` nftables, ou filtrer par SNI avec un pare-feu
  applicatif. Un filtrage par IP figée se périme silencieusement.
- Le filtrage par groupe (`skgid`) suppose que le proxy tourne sous un compte
  ou un groupe dédié — ce qui rejoint la recommandation d'isoler le coffre
  (réponse §3.5 : aujourd'hui « local, même utilisateur », gap assumé).
- `mcp-proxy.anthropic.com` : à couper tant que les connecteurs claude.ai ne
  sont pas arbitrés, ou à désactiver côté paramètres de connecteurs — c'est
  plus simple et réversible qu'une règle réseau.
- Toute règle ajoutée doit être vérifiée par `tests/egress_capture.sh` : une
  politique non testée n'est pas une politique.

## Ce qui reste vrai sans pare-feu

Le harnais d'egress (Phase 0) reste le garde-fou de non-régression : il
inventorie ce qui sort et **échoue** sur toute destination non justifiée. Il
détecte, il n'empêche pas. C'est la différence entre un contrôle et une
alarme — et c'est pourquoi D9 n'est pas encore tenue.
