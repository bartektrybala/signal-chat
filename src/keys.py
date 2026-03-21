import dataclasses

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from src import aliases


@dataclasses.dataclass
class IdentityKey:
    private_key: EllipticCurvePrivateKey
    public_key: EllipticCurvePublicKey

    def sign(self, public_key: EllipticCurvePublicKey) -> bytes:
        return self.private_key.sign(
            data=public_key.public_bytes(
                encoding=Encoding.X962,
                format=PublicFormat.CompressedPoint,
            ),
            signature_algorithm=ec.ECDSA(
                algorithm=hashes.SHA256(),
                deterministic_signing=True,
            ),
        )


@dataclasses.dataclass
class SignedPreKey:
    private_key: EllipticCurvePrivateKey
    public_key: EllipticCurvePublicKey
    signature: bytes


@dataclasses.dataclass
class PublicSignedPreKey:
    public_key: EllipticCurvePublicKey
    signature: aliases.Signature


@dataclasses.dataclass
class UserPublicKeys:
    public_identity_key: EllipticCurvePublicKey
    public_signed_pre_key: PublicSignedPreKey

    def verify(self, signature: bytes, public_key: EllipticCurvePublicKey) -> None:
        self.public_identity_key.verify(
            signature=signature,
            data=public_key.public_bytes(
                encoding=Encoding.X962,
                format=PublicFormat.CompressedPoint,
            ),
            signature_algorithm=ec.ECDSA(
                algorithm=hashes.SHA256(),
                deterministic_signing=True,
            ),
        )


@dataclasses.dataclass(frozen=True)
class ChatParticipant:
    username: aliases.Username
    public_keys: UserPublicKeys


def generate_private_key() -> EllipticCurvePrivateKey:
    return ec.generate_private_key(curve=ec.SECP256R1())
