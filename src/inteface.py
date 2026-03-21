import dataclasses

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from src import aliases


@dataclasses.dataclass
class IdentityKey:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey


@dataclasses.dataclass
class SignedPreKey:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey
    signature: bytes


@dataclasses.dataclass
class PublicSignedPreKey:
    public_key: X25519PublicKey
    signature: aliases.Signature


@dataclasses.dataclass
class UserPublicKeys:
    public_identity_key: Ed25519PublicKey
    public_signed_pre_key: PublicSignedPreKey


@dataclasses.dataclass(frozen=True)
class ChatParticipant:
    username: aliases.Username
    public_keys: UserPublicKeys
