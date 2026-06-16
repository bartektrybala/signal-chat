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

# Public Key Types (Signal Protocol)
# - Identity Key Pair - A long-term Curve25519 key pair, generated at registration time.
# - Signed Pre Key    - A medium-term Curve25519 key pair, generated at registration
#                       time, signed by the Identity Key, and rotated periodically.
# - One-Time Pre Keys - A queue of Curve25519 key pairs for one time use, generated at
#                       registration time, and replenished as needed.
#
# Curve25519 is used for the ECDH key agreement. Signing a Curve25519 key requires
# XEdDSA, which the standard library does not expose, so the Identity Key carries a
# separate Ed25519 signing pair. Real Signal folds both roles into one Curve25519 key.


@dataclasses.dataclass
class IdentityKey:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey
    signing_private_key: Ed25519PrivateKey
    signing_public_key: Ed25519PublicKey

    def sign(self, public_key: X25519PublicKey) -> aliases.Signature:
        return aliases.Signature(
            self.signing_private_key.sign(data=public_key.public_bytes_raw())
        )


@dataclasses.dataclass
class SignedPreKey:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey
    signature: aliases.Signature


@dataclasses.dataclass
class OneTimePreKey:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey


@dataclasses.dataclass
class PublicSignedPreKey:
    public_key: X25519PublicKey
    signature: aliases.Signature


@dataclasses.dataclass
class UserPublicKeys:
    public_identity_key: X25519PublicKey
    public_signing_key: Ed25519PublicKey
    public_signed_pre_key: PublicSignedPreKey
    public_one_time_pre_keys: list[X25519PublicKey]

    def verify(self) -> None:
        verify_signed_pre_key(
            public_signing_key=self.public_signing_key,
            public_signed_pre_key=self.public_signed_pre_key,
        )


@dataclasses.dataclass
class PreKeyBundle:
    public_identity_key: X25519PublicKey
    public_signing_key: Ed25519PublicKey
    public_signed_pre_key: PublicSignedPreKey
    public_one_time_pre_key: X25519PublicKey

    def verify(self) -> None:
        verify_signed_pre_key(
            public_signing_key=self.public_signing_key,
            public_signed_pre_key=self.public_signed_pre_key,
        )


def verify_signed_pre_key(
    public_signing_key: Ed25519PublicKey,
    public_signed_pre_key: PublicSignedPreKey,
) -> None:
    public_signing_key.verify(
        signature=public_signed_pre_key.signature,
        data=public_signed_pre_key.public_key.public_bytes_raw(),
    )


def generate_private_key() -> X25519PrivateKey:
    return X25519PrivateKey.generate()
