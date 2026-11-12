"""Certificates for HTTPS on the local network (plan section 38).

No public certificate authority will issue a certificate for 192.168.1.20, so
NetPulse makes its own, the way mkcert does:

- A certificate authority that exists only on this PC. Its key never leaves
  the data folder. Installing its certificate on a phone or laptop makes that
  device trust this NetPulse, and nothing else: the authority is constrained
  to private addresses and local names, so even a stolen key could not be
  used to impersonate a public website.
- A server certificate signed by it, for this PC's names and addresses. It is
  made again when they change, and every device that trusts the authority
  trusts the new one too.

Until the authority is installed on a device, its browser warns, and it is
right to: nothing has yet told it this certificate is ours. The fingerprint
on the access page is how a person checks.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_DAYS = 3650
SERVER_DAYS = 397  # the longest browsers accept from an authority a person installed
RENEW_BEFORE_DAYS = 30

# What the authority may sign for. Anything else it signs, a browser refuses.
LOCAL_SUFFIXES = ("local", "lan", "home", "home.arpa", "internal", "localdomain", "localhost", "test")
LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
))

CA_CERT, CA_KEY, SERVER_CERT, SERVER_KEY = "ca.pem", "ca-key.pem", "server.pem", "server-key.pem"


class TlsError(RuntimeError):
    """A certificate could not be made, read or used. The message is safe to show."""


@dataclass(frozen=True)
class CertificateInfo:
    subject: str
    names: tuple[str, ...]  # the DNS names and addresses it is valid for
    not_after: datetime
    fingerprint: str  # SHA-256, as AA:BB:…

    def days_left(self, now: datetime) -> int:
        return (self.not_after - now).days


def tls_folder(database: Path) -> Path:
    """Beside the database, named after it, like the captures folder: netpulse.db -> netpulse-tls."""
    return database.with_name(f"{database.stem}-tls")


def covered_by_authority(name: str, computer: str = "") -> bool:
    """Whether the local authority may sign for a name or address: exactly what its
    name constraints permit, so NetPulse never issues a certificate a browser must refuse."""
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        lowered = name.lower().rstrip(".")
        own = computer.lower()
        if lowered in LOCAL_SUFFIXES or (own and (lowered == own or lowered.endswith("." + own))):
            return True
        return lowered.endswith(tuple("." + suffix for suffix in LOCAL_SUFFIXES))
    return any(address in network for network in LOCAL_NETWORKS if address.version == network.version)


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _write_private(path: Path, key) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    path.write_bytes(pem)
    try:
        path.chmod(0o600)  # on Windows the folder's own permissions are what protect it
    except OSError:
        pass


def _name(common: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetPulse"),
        x509.NameAttribute(NameOID.COMMON_NAME, common[:64]),
    ])


def ensure_authority(folder: Path, computer: str, *, now: datetime | None = None) -> x509.Certificate:
    """This PC's certificate authority, made on first use and then kept."""
    cert_path, key_path = folder / CA_CERT, folder / CA_KEY
    if cert_path.is_file() and key_path.is_file():
        return _load_cert(cert_path)
    now = now or datetime.now(UTC)
    folder.mkdir(parents=True, exist_ok=True)
    key = _key()
    name = _name(f"NetPulse local authority ({computer})")
    constraints = x509.NameConstraints(
        permitted_subtrees=[
            *(x509.DNSName(suffix) for suffix in LOCAL_SUFFIXES),
            x509.DNSName(computer.lower()),
            *(x509.IPAddress(network) for network in LOCAL_NETWORKS),
        ],
        excluded_subtrees=None,
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False,
            decipher_only=False), critical=True)
        .add_extension(constraints, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write_private(key_path, key)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def issue_server_certificate(
    folder: Path, computer: str, names: list[str], *, now: datetime | None = None
) -> CertificateInfo:
    """A server certificate for these names and addresses, signed by the local authority.

    Names the authority may not sign for are refused: a browser would reject the
    certificate, and the page says to use a certificate of your own for them.
    """
    now = now or datetime.now(UTC)
    refused = [name for name in names if not covered_by_authority(name, computer)]
    if refused:
        raise TlsError(
            f"{refused[0]} is not a private address or a local name (one ending in .lan, .local or .home.arpa), "
            "so NetPulse's own authority cannot sign for it; use a certificate of your own for that name"
        )
    authority = ensure_authority(folder, computer, now=now)
    try:
        ca_key = serialization.load_pem_private_key((folder / CA_KEY).read_bytes(), password=None)
    except (OSError, ValueError) as exc:
        raise TlsError("the local certificate authority's key cannot be read") from exc
    alt = []
    for name in dict.fromkeys(["localhost", "127.0.0.1", computer.lower(), *names]):
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            alt.append(x509.DNSName(name.lower()))
    key = _key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(computer)).issuer_name(authority.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=SERVER_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=False, crl_sign=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False,
            decipher_only=False), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _write_private(folder / SERVER_KEY, key)
    # The server sends its certificate and then the authority's, so a device that
    # trusts the authority can check the whole chain.
    (folder / SERVER_CERT).write_bytes(
        cert.public_bytes(serialization.Encoding.PEM) + authority.public_bytes(serialization.Encoding.PEM)
    )
    return describe(folder / SERVER_CERT)


def needs_new_certificate(folder: Path, names: list[str], *, now: datetime | None = None) -> bool:
    """Whether the server certificate is missing, close to expiring, or lacks one of these names."""
    try:
        info = describe(folder / SERVER_CERT)
    except TlsError:
        return True
    now = now or datetime.now(UTC)
    wanted = {name.lower() for name in names}
    return info.days_left(now) < RENEW_BEFORE_DAYS or not wanted <= {name.lower() for name in info.names}


def _load_cert(path: Path) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise TlsError(f"{path.name} is not a readable PEM certificate") from exc


def describe(path: Path) -> CertificateInfo:
    """What a certificate file says about itself: the first certificate in it."""
    cert = _load_cert(path)
    try:
        alt = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = tuple(str(entry.value) for entry in alt)
    except x509.ExtensionNotFound:
        names = ()
    digest = cert.fingerprint(hashes.SHA256()).hex().upper()
    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        names=names,
        not_after=cert.not_valid_after_utc,
        fingerprint=":".join(digest[i : i + 2] for i in range(0, len(digest), 2)),
    )


def authority_pem(folder: Path) -> bytes:
    """The authority's certificate, to install on other devices. Public: never its key."""
    try:
        return (folder / CA_CERT).read_bytes()
    except OSError as exc:
        raise TlsError("NetPulse has not made its certificate authority yet") from exc


def check_pair(cert_path: Path, key_path: Path) -> CertificateInfo:
    """A certificate and key of the user's own: both readable, and the key is that certificate's."""
    info = describe(cert_path)
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise TlsError("the private key is not a readable PEM key without a passphrase") from exc
    public = _load_cert(cert_path).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    mine = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public != mine:
        raise TlsError("the private key does not belong to that certificate")
    return info
