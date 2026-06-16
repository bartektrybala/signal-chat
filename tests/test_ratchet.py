from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.ratchet import DoubleRatchet


class TestDoubleRatchet:
    def test_consecutive_messages_use_different_keys(self) -> None:
        # given
        root_key = bytes(32)
        signed_pre_key = X25519PrivateKey.generate()
        sender = DoubleRatchet.initiate(
            root_key=root_key, remote_signed_pre_key=signed_pre_key.public_key()
        )

        # when
        first = sender.encrypt(b"same plaintext")
        second = sender.encrypt(b"same plaintext")

        # then
        assert first.ciphertext != second.ciphertext
        assert first.header.message_number == 0
        assert second.header.message_number == 1
