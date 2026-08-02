"""Coffre des correspondances substitut ↔ valeur réelle (SQLite chiffré).

Le coffre vit HORS du dépôt (défaut : ``~/.local/state/anonproxy/vault.db``,
cf. réponse §3.5 : local, même utilisateur — gap assumé et documenté).

Garanties structurelles :

- **Chiffré au repos** : les valeurs réelles sont scellées en AES-256-GCM avec
  une clé dérivée de la clé maître. Le fichier seul — sauvegarde égarée,
  disque récupéré — ne révèle rien. C'est ce qui rend vraie la formule « la
  clé et la base sont les deux moitiés du secret » : tant que les valeurs
  étaient stockées en clair, la base suffisait.
- **Recherche déterministe** : le chiffrement authentifié utilise un nonce
  aléatoire, donc deux scellés d'une même valeur diffèrent. La recherche passe
  par un index HMAC, qui ne révèle rien de plus qu'une égalité.
- **Injectivité** (D6) : contrainte d'unicité SQL sur ``(scope, surrogate)``
  ET sur ``(scope, etype, index de la valeur)``. Une collision est une erreur
  d'intégrité remontée à l'appelant, jamais un écrasement silencieux.
- **Fail-closed** (D5) : coffre illisible, clé fausse, schéma en clair d'une
  version antérieure ⇒ ``VaultUnavailableError``. Aucun mode dégradé.
- Les **secrets ne sont jamais stockés** : ils ne transitent pas par ce module
  (D4) — le moteur les dérive sans persistance.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_VAULT_PATH = Path.home() / ".local" / "state" / "anonproxy" / "vault.db"

#: Version de schéma : un coffre antérieur stockait les valeurs en clair et
#: doit être refusé plutôt que lu.
SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mapping (
    scope      TEXT NOT NULL,
    etype      TEXT NOT NULL,
    key_idx    TEXT NOT NULL,   -- HMAC(scope, etype, réel) : recherche
    real_idx   TEXT NOT NULL,   -- HMAC(scope, réel)        : existence
    real_enc   BLOB NOT NULL,   -- AES-256-GCM(réel)
    surrogate  TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (scope, etype, key_idx)
);
-- injectivité : un substitut ne peut désigner deux réels dans une portée
CREATE UNIQUE INDEX IF NOT EXISTS idx_surrogate_unique ON mapping (scope, surrogate);
CREATE INDEX IF NOT EXISTS idx_scope ON mapping (scope);
CREATE INDEX IF NOT EXISTS idx_real ON mapping (scope, real_idx);
"""


class VaultUnavailableError(RuntimeError):
    """Le coffre est inaccessible ou illisible : on refuse de continuer."""


class SurrogateConflict(RuntimeError):
    """Le substitut proposé est déjà pris par une autre valeur réelle."""


class Vault:
    """Accès SQLite au coffre. Sûr vis-à-vis des threads (connexion sérialisée)."""

    def __init__(self, path: str | Path | None = None, *, master_key: str,
                 create_parents: bool = True):
        self.path = Path(path) if path is not None else DEFAULT_VAULT_PATH
        self._lock = threading.RLock()
        # Incrémenté à chaque nouvelle correspondance : permet à l'appelant de
        # savoir si sa vue est encore à jour sans relire toute la table.
        self.version = 0

        raw = master_key.encode() if isinstance(master_key, str) else master_key
        # Deux usages, deux clés dérivées : l'index ne doit rien apprendre du
        # chiffrement, et réciproquement.
        self._idx_key = hmac.new(raw, b"anonproxy/vault/index", hashlib.sha256).digest()
        self._aes = AESGCM(hmac.new(raw, b"anonproxy/vault/cipher", hashlib.sha256).digest())

        try:
            if create_parents:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            elif not self.path.parent.is_dir():
                raise FileNotFoundError(f"répertoire parent absent : {self.path.parent}")
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._reject_plaintext_schema()
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        except (OSError, sqlite3.Error) as exc:
            raise VaultUnavailableError(f"coffre indisponible ({self.path}) : {exc}") from exc
        self._restrict_permissions()

    # -- interne ------------------------------------------------------------ #

    def _reject_plaintext_schema(self) -> None:
        row = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='mapping'"
        ).fetchone()
        if row and "real_enc" not in (row[0] or ""):
            raise VaultUnavailableError(
                f"coffre {self.path} au format antérieur : les valeurs y sont en CLAIR. "
                "Il n'est pas lu. Sauvegarder puis recréer un coffre, ou migrer "
                "explicitement — les substituts déjà émis ne sont pas reproductibles "
                "sans lui."
            )

    def _restrict_permissions(self) -> None:
        """0600 : le coffre est un secret, y compris pour les autres comptes."""
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            try:
                if p.exists():
                    p.chmod(0o600)
            except OSError:
                pass  # système de fichiers sans permissions POSIX

    def _index(self, *parts: str) -> str:
        msg = "\x1f".join(parts).encode("utf-8")
        return hmac.new(self._idx_key, msg, hashlib.sha256).hexdigest()

    def _seal(self, real: str) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, real.encode("utf-8"), None)

    def _open(self, blob: bytes) -> str:
        try:
            return self._aes.decrypt(bytes(blob[:12]), bytes(blob[12:]), None).decode("utf-8")
        except (InvalidTag, ValueError) as exc:
            raise VaultUnavailableError(
                f"déchiffrement impossible ({self.path}) : clé maître incorrecte "
                "ou coffre altéré. Aucune valeur n'est devinée."
            ) from exc

    # -- lecture ------------------------------------------------------------ #

    def get_surrogate(self, scope: str, etype: str, real: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT surrogate FROM mapping WHERE scope=? AND etype=? AND key_idx=?",
                (scope, etype, self._index(scope, etype, real)),
            ).fetchone()
        return row[0] if row else None

    def get_real(self, scope: str, surrogate: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT real_enc FROM mapping WHERE scope=? AND surrogate=?", (scope, surrogate)
            ).fetchone()
        return self._open(row[0]) if row else None

    def real_exists(self, scope: str, real: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM mapping WHERE scope=? AND real_idx=? LIMIT 1",
                (scope, self._index(scope, real)),
            ).fetchone()
        return row is not None

    def view(self, scope: str, *, include_internal: bool = False) -> dict[str, str]:
        """Table substitut → réel pour la portée (sens entrant du walker).

        Les **attributs partagés** (types préfixés d'un `_` : zone DNS,
        sous-réseau, organisation, registry) en sont EXCLUS par défaut. Ce
        sont des aides à l'allocation, pas des entités restaurables : les
        exposer permettrait de résoudre partiellement un substitut inventé
        par le modèle — `canyon-02-prod.<zone connue>` deviendrait
        `canyon-02-prod.<zone réelle>`, un hôte fictif déguisé en hôte réel.
        Fail-closed (D5) : mieux vaut un substitut non résolu, visible comme
        tel, qu'une valeur plausible et fausse.
        """
        query = "SELECT surrogate, real_enc FROM mapping WHERE scope=?"
        if not include_internal:
            query += r" AND etype NOT LIKE '\_%' ESCAPE '\'"
        with self._lock:
            rows = self._conn.execute(query, (scope,)).fetchall()
        return {s: self._open(enc) for s, enc in rows}

    def count(self, scope: str) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM mapping WHERE scope=?", (scope,)
            ).fetchone()[0]

    # -- écriture ----------------------------------------------------------- #

    def bind(self, scope: str, etype: str, real: str, surrogate: str) -> str:
        """Lie ``real`` à ``surrogate``, atomiquement.

        Retourne le substitut effectivement en base (celui déjà lié si la
        valeur était connue). Lève ``SurrogateConflict`` si le substitut est
        déjà pris par un AUTRE réel — l'appelant doit alors régénérer.
        """
        with self._lock:
            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO mapping (scope, etype, key_idx, real_idx, real_enc,"
                        " surrogate) VALUES (?,?,?,?,?,?)",
                        (scope, etype, self._index(scope, etype, real),
                         self._index(scope, real), self._seal(real), surrogate),
                    )
                self.version += 1
                return surrogate
            except sqlite3.IntegrityError:
                existing = self.get_surrogate(scope, etype, real)
                if existing is not None:
                    return existing  # course : un autre thread a lié la même valeur
                raise SurrogateConflict(
                    f"substitut déjà pris dans {scope!r} : {surrogate!r}"
                ) from None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
