import dataclasses

import cryptography.exceptions
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.message import (
    MESSAGE_KEY_LENGTH,
    MessageHeader,
    MessageKey,
    decrypt,
    encrypt,
)


def _header() -> MessageHeader:
    return MessageHeader(
        ratchet_public_key=X25519PrivateKey.generate().public_key(),
        message_number=0,
        previous_chain_length=0,
    )


class TestMessage:
    def test_message_key_splits_into_aes_hmac_and_iv(self) -> None:
        # given / when
        message_key = MessageKey.derive(seed=bytes(32))

        # then
        assert len(message_key.aes_key) == 32
        assert len(message_key.hmac_key) == 32
        assert len(message_key.iv) == 16
        assert (
            len(message_key.aes_key) + len(message_key.hmac_key) + len(message_key.iv)
            == MESSAGE_KEY_LENGTH
        )

    def test_encrypt_then_decrypt_round_trip(self) -> None:
        # given
        message_key = MessageKey.derive(seed=b"\x01" * 32)

        # when
        message = encrypt(message_key, b"secret message", _header())

        # then
        assert decrypt(message_key, message) == b"secret message"

    def test_tampered_ciphertext_fails_the_mac(self) -> None:
        # given
        message_key = MessageKey.derive(seed=b"\x02" * 32)
        message = encrypt(message_key, b"secret message", _header())

        # when
        flipped = message.ciphertext[:-1] + bytes([message.ciphertext[-1] ^ 0x01])
        tampered = dataclasses.replace(message, ciphertext=flipped)

        # then
        with pytest.raises(cryptography.exceptions.InvalidSignature):
            decrypt(message_key, tampered)
