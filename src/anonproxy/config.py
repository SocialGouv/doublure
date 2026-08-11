"""Configuration du proxy — tout par variables d'environnement.

Le chemin de la clé maître est un SECRET : il est passé par référence aux
composants, jamais lu ni journalisé ailleurs qu'au point d'usage.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

STATE_DIR = Path(os.environ.get("ANONPROXY_STATE_DIR", Path.home() / ".local/state/anonproxy"))


@dataclass(frozen=True)
class Settings:
    #: Portée du déterminisme (réponse §3.1 : par projet par défaut).
    #: `project:<nom>` | `session:<id>` | `tenant:<nom>` | `global`
    scope_key: str
    upstream_base: str
    detect_url: str
    #: Détecteur de DONNÉES PERSONNELLES, second processus (Apache-2.0, donc
    #: hors de la frontière GPL ; `transformers >= 5`, donc hors du venv épinglé
    #: d'AnonShield). Le NER d'infrastructure n'a pas de classe `PERSON` : sans
    #: ce service, aucun nom n'est détecté, et rien ne le compte.
    #:
    #: `ANONPROXY_PII=off` le désactive EXPLICITEMENT — une décision d'opérateur,
    #: tracée au démarrage. Une panne, elle, ne décide de rien : elle se solde
    #: par un 503, comme pour l'autre détecteur.
    pii_url: str | None
    vault_path: Path
    master_key_file: Path
    listen_host: str
    listen_port: int
    #: Au-delà de cette taille, détection en mode `regex` (plan §5 : gros volumes).
    regex_threshold: int
    #: Nombre max de chaînes distinctes mémorisées par le cache de substitution.
    cache_size: int
    request_timeout: float
    #: Bundle CA pour la connexion amont (CA d'entreprise, ou mitmproxy pendant
    #: les tests de capture). None = magasin par défaut.
    ca_bundle: str | None
    #: Allowlist §6, partagée avec le service de détection.
    allowlist_file: Path
    #: Racine des politiques de confidentialité (une par portée).
    policy_dir: Path
    #: Identifiant de session : la portée la plus proche, celle qui prime.
    #: Absent = deux couches seulement (global → projet).
    session_id: str | None
    #: Chemin ABSOLU du projet, exporté par le lanceur. Il dit où se trouve le
    #: nom du dépôt — que la substitution de chemins DEVINAIT par sa position,
    #: donc laissait en clair dès que le projet n'était pas directement sous le
    #: home. Absent = repli sur ce pari de position.
    projet: str | None

    @staticmethod
    def from_env() -> "Settings":
        scope = os.environ.get("ANONPROXY_SCOPE")
        if not scope:
            scope = f"project:{Path.cwd().name}"
        return Settings(
            scope_key=scope,
            upstream_base=os.environ.get("ANONPROXY_UPSTREAM", "https://api.anthropic.com"),
            detect_url=os.environ.get("ANONPROXY_DETECT_URL", "http://127.0.0.1:9000"),
            pii_url=(None if os.environ.get("ANONPROXY_PII", "").lower() == "off"
                     else os.environ.get("ANONPROXY_PII_URL",
                                         "http://127.0.0.1:9100")),
            vault_path=Path(os.environ.get("ANONPROXY_VAULT", STATE_DIR / "vault.db")),
            master_key_file=Path(
                os.environ.get("ANONPROXY_MASTER_KEY_FILE", STATE_DIR / "anon_secret_key")
            ),
            listen_host=os.environ.get("ANONPROXY_HOST", "127.0.0.1"),
            listen_port=int(os.environ.get("ANONPROXY_PORT", "8090")),
            regex_threshold=int(os.environ.get("ANONPROXY_REGEX_THRESHOLD", "8000")),
            cache_size=int(os.environ.get("ANONPROXY_CACHE_SIZE", "20000")),
            request_timeout=float(os.environ.get("ANONPROXY_TIMEOUT", "600")),
            ca_bundle=os.environ.get("ANONPROXY_CA_BUNDLE") or None,
            allowlist_file=Path(
                os.environ.get("ANON_ALLOWLIST_FILE",
                               Path(__file__).resolve().parents[2] / "config/allowlist.txt")
            ),
            policy_dir=Path(os.environ.get("ANONPROXY_POLICY_DIR", STATE_DIR / "policy")),
            session_id=os.environ.get("ANONPROXY_SESSION") or None,
            projet=os.environ.get("ANONPROXY_PROJECT") or None,
        )


def read_master_key(path: Path) -> str:
    """Lit la clé maître. Jamais journalisée, jamais renvoyée dans une réponse."""
    try:
        key = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(
            f"clé maître illisible ({path}) — lancer d'abord "
            f"services/anonshield/wrapper/run.sh qui la génère"
        ) from exc
    if not key:
        raise RuntimeError(f"clé maître vide ({path})")
    return key
