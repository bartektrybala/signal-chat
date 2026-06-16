import dataclasses

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.message import (
    EncryptedMessage,
    MessageHeader,
    MessageKey,
    decrypt,
    encrypt,
)

# Session Key Types (Signal Protocol)
# - Root Key    - A 32-byte value that is used to create Chain Keys.
# - Chain Key   - A 32-byte value that is used to create Message Keys.
# - Message Key - An 80-byte value that is used to encrypt message contents.

CHAIN_KEY_LENGTH = 32
MAX_SKIP = 256

_SkippedKeys = dict[tuple[bytes, int], MessageKey]


@dataclasses.dataclass
class DoubleRatchet:
    root_key: bytes
    dh_self: X25519PrivateKey
    dh_remote: X25519PublicKey | None
    send_chain_key: bytes | None
    recv_chain_key: bytes | None
    send_number: int = 0
    recv_number: int = 0
    previous_send_number: int = 0
    skipped_keys: _SkippedKeys = dataclasses.field(default_factory=dict)

    @classmethod
    def initiate(
        cls, root_key: bytes, remote_signed_pre_key: X25519PublicKey
    ) -> "DoubleRatchet":
        dh_self = X25519PrivateKey.generate()
        root_key, send_chain_key = _advance_root(
            root_key=root_key, ephemeral_secret=dh_self.exchange(remote_signed_pre_key)
        )
        return cls(
            root_key=root_key,
            dh_self=dh_self,
            dh_remote=remote_signed_pre_key,
            send_chain_key=send_chain_key,
            recv_chain_key=None,
        )

    @classmethod
    def accept(
        cls, root_key: bytes, signed_pre_key: X25519PrivateKey
    ) -> "DoubleRatchet":
        return cls(
            root_key=root_key,
            dh_self=signed_pre_key,
            dh_remote=None,
            send_chain_key=None,
            recv_chain_key=None,
        )

    def encrypt(self, plaintext: bytes) -> EncryptedMessage:
        assert self.send_chain_key is not None
        self.send_chain_key, message_key_seed = _advance_chain(self.send_chain_key)
        header = MessageHeader(
            ratchet_public_key=self.dh_self.public_key(),
            message_number=self.send_number,
            previous_chain_length=self.previous_send_number,
        )
        self.send_number += 1
        return encrypt(MessageKey.derive(message_key_seed), plaintext, header)

    def decrypt(self, message: EncryptedMessage) -> bytes:
        header = message.header

        skipped = self.skipped_keys.pop(
            (header.ratchet_public_key.public_bytes_raw(), header.message_number), None
        )
        if skipped is not None:
            return decrypt(skipped, message)

        if self._is_new_ratchet_key(header.ratchet_public_key):
            self._skip_message_keys(header.previous_chain_length)
            self._dh_ratchet(header.ratchet_public_key)

        self._skip_message_keys(header.message_number)
        assert self.recv_chain_key is not None
        self.recv_chain_key, message_key_seed = _advance_chain(self.recv_chain_key)
        self.recv_number += 1
        return decrypt(MessageKey.derive(message_key_seed), message)

    def _is_new_ratchet_key(self, ratchet_public_key: X25519PublicKey) -> bool:
        return self.dh_remote is None or (
            ratchet_public_key.public_bytes_raw() != self.dh_remote.public_bytes_raw()
        )

    def _dh_ratchet(self, remote_ratchet_public_key: X25519PublicKey) -> None:
        self.previous_send_number = self.send_number
        self.dh_remote = remote_ratchet_public_key
        self.root_key, self.recv_chain_key = _advance_root(
            root_key=self.root_key,
            ephemeral_secret=self.dh_self.exchange(self.dh_remote),
        )
        self.recv_number = 0

        self.dh_self = X25519PrivateKey.generate()
        self.root_key, self.send_chain_key = _advance_root(
            root_key=self.root_key,
            ephemeral_secret=self.dh_self.exchange(self.dh_remote),
        )
        self.send_number = 0

    def _skip_message_keys(self, until: int) -> None:
        if self.recv_chain_key is None or self.dh_remote is None:
            return
        if until - self.recv_number > MAX_SKIP:
            raise ValueError("too many skipped messages")
        remote_key = self.dh_remote.public_bytes_raw()
        while self.recv_number < until:
            self.recv_chain_key, message_key_seed = _advance_chain(self.recv_chain_key)
            self.skipped_keys[(remote_key, self.recv_number)] = MessageKey.derive(
                message_key_seed
            )
            self.recv_number += 1


def _advance_chain(chain_key: bytes) -> tuple[bytes, bytes]:
    # Message Key = HMAC-SHA-256(Chain Key, 0x01)
    # Chain Key   = HMAC-SHA-256(Chain Key, 0x02)
    message_key_seed = _hmac(chain_key, b"\x01")
    next_chain_key = _hmac(chain_key, b"\x02")
    return next_chain_key, message_key_seed


def _advance_root(root_key: bytes, ephemeral_secret: bytes) -> tuple[bytes, bytes]:
    # ephemeral_secret = ECDH(Ephemeral_sender, Ephemeral_recipient)
    # Chain Key, Root Key = HKDF(Root Key, ephemeral_secret)
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=CHAIN_KEY_LENGTH * 2,
        salt=root_key,
        info=b"signal-chat/dh-ratchet",
    ).derive(ephemeral_secret)
    return material[:CHAIN_KEY_LENGTH], material[CHAIN_KEY_LENGTH:]


def _hmac(key: bytes, data: bytes) -> bytes:
    authenticator = hmac.HMAC(key, hashes.SHA256())
    authenticator.update(data)
    return authenticator.finalize()
