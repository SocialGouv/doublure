"""The local authority that lets the proxy read what it forwards.

Intercepting TLS means presenting a certificate the client accepts, which means
signing one — and a certificate authority a machine trusts is a **permanent
lever on it**: whoever holds the key can impersonate any site to any process
that trusts it. Three properties make that acceptable, and they are enforced by
`tests/test_forward_ca.py` rather than promised here.

**The key lives in the state directory, `0600`.** Not in the repository: a
repository is shared, cloned and published, and the hook denies the agent that
directory.

**It is never installed in the system trust store.** Trust travels in the
ENVIRONMENT of the launched process — `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE` — so it covers exactly the agent we launched and dies with
it. Installing it system-wide would outlive the need, cover processes nobody
meant to intercept, and be worse than the leak it prevents. There is
deliberately no method here that would do it.

**It persists across restarts.** Regenerating would invalidate the trust
already handed to a running agent; a proxy that breaks the sessions it was
meant to protect gets turned off, and then nothing is protected.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

#: L'autorité est RSA : c'est le format qu'acceptent sans discuter les magasins
#: de confiance de Node, Python, curl et Go. Les feuilles sont EC P-256, dont
#: la génération coûte une milliseconde là où RSA en coûte cent — et une
#: feuille se génère à la volée, pour chaque hôte rencontré.
_TAILLE_RSA = 2048
_VALIDITE_AUTORITE = dt.timedelta(days=365)
_VALIDITE_FEUILLE = dt.timedelta(days=30)
#: Antidatage : l'horloge d'un conteneur ou d'une VM qui reprend est
#: couramment en retard de quelques minutes, et un certificat « pas encore
#: valide » se présente comme une erreur de confiance indéchiffrable.
_ANTIDATE = dt.timedelta(minutes=5)

_NOM_AUTORITE = "doublure interception CA (local)"


def _maintenant() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


#: Paquets concaténés des distributions courantes. `capath` est le cas
#: fréquent sous Debian et Ubuntu : le magasin y est un RÉPERTOIRE de liens
#: hachés, et `cafile` n'existe pas — s'arrêter à `cafile` rend un paquet vide
#: sur la moitié des machines.
_PAQUETS_CONNUS = (
    "/etc/ssl/certs/ca-certificates.crt",   # Debian, Ubuntu, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",     # RHEL, Fedora
    "/etc/ssl/cert.pem",                    # BSD, macOS via ports
)


def _racines_du_systeme() -> bytes:
    """Les racines que la machine croit, en un seul PEM."""
    chemins = ssl.get_default_verify_paths()
    for candidat in (chemins.cafile, chemins.openssl_cafile, *_PAQUETS_CONNUS):
        if candidat and Path(candidat).is_file():
            return Path(candidat).read_bytes()
    for repertoire in (chemins.capath, chemins.openssl_capath):
        if not repertoire or not Path(repertoire).is_dir():
            continue
        # Les liens hachés pointent plusieurs fois sur le même certificat :
        # dédoublonné par CONTENU, pas par nom.
        vus, morceaux = set(), []
        for fichier in sorted(Path(repertoire).glob("*")):
            if fichier.suffix not in (".pem", ".crt", ".0"):
                continue
            try:
                contenu = fichier.read_bytes()
            except OSError:
                continue
            if b"BEGIN CERTIFICATE" in contenu and contenu not in vus:
                vus.add(contenu)
                morceaux.append(contenu)
        if morceaux:
            return b"\n".join(morceaux)
    return b""


def _san_pour(host: str) -> x509.SubjectAlternativeName:
    """Un client qui joint une ADRESSE vérifie un SAN de type IP.

    Un `DNSName` portant les mêmes chiffres ne le satisfait pas — et la
    destination d'un agent est aussi souvent une adresse qu'un nom.
    """
    try:
        return x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address(host))])
    except ValueError:
        return x509.SubjectAlternativeName([x509.DNSName(host)])


class InterceptionCA:
    """Autorité locale et fabrique de feuilles, une par hôte."""

    def __init__(self, state_dir: Path | str):
        self.state_dir = Path(state_dir)
        self.cert_path = self.state_dir / "interception-ca.crt"
        self.key_path = self.state_dir / "interception-ca.key"
        self.leaves_dir = self.state_dir / "leaves"
        self._cle = None
        self._cert = None
        self._feuilles: dict[str, tuple[bytes, bytes]] = {}
        self._contextes: dict[str, ssl.SSLContext] = {}

    # ----------------------------------------------------------------- autorité

    def ensure(self) -> None:
        """Charge l'autorité, ou la crée si elle n'existe pas encore."""
        if self._cert is not None:
            return
        if self.cert_path.exists() and self.key_path.exists():
            self._charger()
            return
        self._creer()

    def _charger(self) -> None:
        self._cle = serialization.load_pem_private_key(
            self.key_path.read_bytes(), password=None)
        self._cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        # Les droits sont remis à chaque ouverture : un `umask` permissif ou
        # une copie maladroite les aurait élargis sans que rien ne le dise.
        os.chmod(self.key_path, 0o600)

    def _creer(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        cle = rsa.generate_private_key(public_exponent=65537, key_size=_TAILLE_RSA)
        nom = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, _NOM_AUTORITE),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "doublure"),
        ])
        debut = _maintenant() - _ANTIDATE
        cert = (
            x509.CertificateBuilder()
            .subject_name(nom)
            .issuer_name(nom)
            .public_key(cle.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(debut)
            .not_valid_after(debut + _VALIDITE_AUTORITE)
            # `path_length=0` : elle ne signe que des feuilles. Une autorité qui
            # peut déléguer étend le levier au-delà de ce processus.
            .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                           critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False),
                critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                cle.public_key()), critical=False)
            .sign(cle, hashes.SHA256())
        )
        # La clé est écrite AVANT d'être remplie, avec ses droits définitifs :
        # entre un `write_bytes` et un `chmod`, elle est lisible par tous.
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(cle.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        self.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self._cle, self._cert = cle, cert

    # ------------------------------------------------------------------ feuilles

    def leaf_for(self, host: str) -> tuple[bytes, bytes]:
        """Certificat et clé pour cet hôte, en PEM. Mémorisé : une session
        touche le même hôte des dizaines de fois."""
        if (connu := self._feuilles.get(host)) is not None:
            return connu
        self.ensure()
        cle = ec.generate_private_key(ec.SECP256R1())
        debut = _maintenant() - _ANTIDATE
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self._cert.subject)
            .public_key(cle.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(debut)
            .not_valid_after(debut + _VALIDITE_FEUILLE)
            .add_extension(_san_pour(host), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            # Sans l'identifiant de l'autorité, une validation conforme au
            # profil RFC 5280 refuse la chaîne — même correctement signée.
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    self._cert.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier).value),
                critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                cle.public_key()), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=False,
                    key_agreement=True, content_commitment=False,
                    data_encipherment=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False),
                critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False)
            .sign(self._cle, hashes.SHA256())
        )
        feuille = (
            cert.public_bytes(serialization.Encoding.PEM),
            cle.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
        )
        self._feuilles[host] = feuille
        return feuille

    def bundle_path(self) -> Path:
        """Paquet de confiance à donner à l'agent : les racines du système
        PLUS la nôtre.

        Pointer `SSL_CERT_FILE` sur notre seule autorité ferait échouer TOUT
        accès TLS que le proxy ne fabrique pas — un dépôt de paquets, une API
        publique — et le symptôme serait une erreur de confiance que personne
        ne rattache au proxy. On AJOUTE, on ne remplace pas.

        Reconstruit à chaque appel : le magasin du système est mis à jour par
        l'administrateur, et un paquet figé prendrait du retard sans le dire.
        """
        self.ensure()
        racines = _racines_du_systeme()
        if not racines:
            # Livrer un paquet qui ne contient QUE notre autorité ferait
            # échouer tout accès TLS légitime de l'agent, et l'erreur ne se
            # rattacherait pas au proxy. Mieux vaut ne pas démarrer.
            raise RuntimeError(
                "magasin de certificats du système introuvable : un paquet "
                "sans ses racines casserait tout accès TLS de l'agent")
        paquet = self.state_dir / "trust-bundle.pem"
        paquet.write_bytes(racines + b"\n" + self.cert_path.read_bytes())
        return paquet

    def server_context(self, host: str) -> ssl.SSLContext:
        """Contexte TLS servant cet hôte, mémorisé.

        `load_cert_chain` n'accepte que des CHEMINS : la feuille est donc
        écrite, sous le répertoire d'état et en `0600`, jamais ailleurs. Le nom
        du fichier est un condensé — un hôte peut être un littéral IPv6, dont
        les deux-points et les crochets ne font pas un nom de fichier, et
        assainir les caractères ferait collisionner deux hôtes distincts.

        ALPN n'annonce que `http/1.1` : HTTP/2 se négocie là, et relayer un
        protocole qu'on ne sait pas relire reviendrait à ne rien lire.
        """
        if (connu := self._contextes.get(host)) is not None:
            return connu
        cert_pem, cle_pem = self.leaf_for(host)
        self.leaves_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.leaves_dir, 0o700)
        chemin = self.leaves_dir / (
            hashlib.sha256(host.encode("utf-8")).hexdigest()[:32] + ".pem")
        fd = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(cert_pem + cle_pem)
        contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        contexte.load_cert_chain(certfile=str(chemin))
        contexte.set_alpn_protocols(["http/1.1"])
        self._contextes[host] = contexte
        return contexte
