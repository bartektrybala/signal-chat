import dataclasses

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7

AES_BLOCK_SIZE = 128
MESSAGE_KEY_LENGTH = 80


@dataclasses.dataclass(frozen=True)
class MessageKey:
    # Message Key - An 80-byte value: 32 bytes for an AES-256 key, 32 bytes for a
    # HMAC-SHA256 key, and 16 bytes for an IV.
    aes_key: bytes
    hmac_key: bytes
    iv: bytes

    @classmethod
    def derive(cls, seed: bytes) -> "MessageKey":
        material = HKDF(
            algorithm=hashes.SHA256(),
            length=MESSAGE_KEY_LENGTH,
            salt=None,
            info=b"signal-chat/message-key",
        ).derive(seed)
        return cls(aes_key=material[:32], hmac_key=material[32:64], iv=material[64:80])


@dataclasses.dataclass(frozen=True)
class SessionSetup:
    # Carried in the header of messages until the recipient replies: the initiator's
    # public Einitiator, Iinitiator, and the Orecipient it used.
    identity_key: X25519PublicKey
    ephemeral_key: X25519PublicKey
    one_time_pre_key: X25519PublicKey


@dataclasses.dataclass(frozen=True)
class MessageHeader:
    ratchet_public_key: X25519PublicKey
    message_number: int
    previous_chain_length: int


@dataclasses.dataclass(frozen=True)
class EncryptedMessage:
    header: MessageHeader
    ciphertext: bytes
    tag: bytes
    session_setup: SessionSetup | None = None


def encrypt(
    message_key: MessageKey, plaintext: bytes, header: MessageHeader
) -> EncryptedMessage:
    padder = PKCS7(AES_BLOCK_SIZE).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES256(message_key.aes_key), modes.CBC(message_key.iv)
    ).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return EncryptedMessage(
        header=header,
        ciphertext=ciphertext,
        tag=_tag(message_key.hmac_key, header, ciphertext),
    )


def decrypt(message_key: MessageKey, message: EncryptedMessage) -> bytes:
    _verify_tag(message_key.hmac_key, message.header, message.ciphertext, message.tag)
    decryptor = Cipher(
        algorithms.AES256(message_key.aes_key), modes.CBC(message_key.iv)
    ).decryptor()
    padded = decryptor.update(message.ciphertext) + decryptor.finalize()
    unpadder = PKCS7(AES_BLOCK_SIZE).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _tag(hmac_key: bytes, header: MessageHeader, ciphertext: bytes) -> bytes:
    authenticator = hmac.HMAC(hmac_key, hashes.SHA256())
    authenticator.update(_header_bytes(header) + ciphertext)
    return authenticator.finalize()


def _verify_tag(
    hmac_key: bytes, header: MessageHeader, ciphertext: bytes, tag: bytes
) -> None:
    authenticator = hmac.HMAC(hmac_key, hashes.SHA256())
    authenticator.update(_header_bytes(header) + ciphertext)
    authenticator.verify(tag)


def _header_bytes(header: MessageHeader) -> bytes:
    return (
        header.ratchet_public_key.public_bytes_raw()
        + header.message_number.to_bytes(4, "big")
        + header.previous_chain_length.to_bytes(4, "big")
    )
