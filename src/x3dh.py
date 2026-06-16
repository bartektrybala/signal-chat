from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.keys import IdentityKey, OneTimePreKey, PreKeyBundle, SignedPreKey

ROOT_KEY_LENGTH = 32


def x3dh_initiator(
    identity_key: IdentityKey,
    ephemeral_key: X25519PrivateKey,
    recipient: PreKeyBundle,
) -> bytes:
    # master_secret = ECDH(Iinitiator, Srecipient)
    #              || ECDH(Einitiator, Irecipient)
    #              || ECDH(Einitiator, Srecipient)
    #              || ECDH(Einitiator, Orecipient)
    master_secret = (
        identity_key.private_key.exchange(recipient.public_signed_pre_key.public_key)
        + ephemeral_key.exchange(recipient.public_identity_key)
        + ephemeral_key.exchange(recipient.public_signed_pre_key.public_key)
        + ephemeral_key.exchange(recipient.public_one_time_pre_key)
    )
    return _derive_root_key(master_secret)


def x3dh_recipient(
    identity_key: IdentityKey,
    signed_pre_key: SignedPreKey,
    one_time_pre_key: OneTimePreKey,
    initiator_identity_key: X25519PublicKey,
    initiator_ephemeral_key: X25519PublicKey,
) -> bytes:
    # master_secret = ECDH(Srecipient, Iinitiator)
    #              || ECDH(Irecipient, Einitiator)
    #              || ECDH(Srecipient, Einitiator)
    #              || ECDH(Orecipient, Einitiator)
    master_secret = (
        signed_pre_key.private_key.exchange(initiator_identity_key)
        + identity_key.private_key.exchange(initiator_ephemeral_key)
        + signed_pre_key.private_key.exchange(initiator_ephemeral_key)
        + one_time_pre_key.private_key.exchange(initiator_ephemeral_key)
    )
    return _derive_root_key(master_secret)


def _derive_root_key(master_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=ROOT_KEY_LENGTH,
        salt=None,
        info=b"signal-chat/x3dh",
    ).derive(master_secret)
