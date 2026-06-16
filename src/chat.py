import dataclasses

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from src.keys import OneTimePreKey, PreKeyBundle
from src.message import EncryptedMessage, SessionSetup
from src.ratchet import DoubleRatchet
from src.user import User
from src.x3dh import x3dh_initiator, x3dh_recipient


@dataclasses.dataclass
class ChatSession:
    ratchet: DoubleRatchet
    pending_setup: SessionSetup | None = None

    @classmethod
    def initiate(cls, user: User, recipient: PreKeyBundle) -> "ChatSession":
        recipient.verify()
        ephemeral_key = X25519PrivateKey.generate()
        root_key = x3dh_initiator(
            identity_key=user.keys.identity_key,
            ephemeral_key=ephemeral_key,
            recipient=recipient,
        )
        return cls(
            ratchet=DoubleRatchet.initiate(
                root_key=root_key,
                remote_signed_pre_key=recipient.public_signed_pre_key.public_key,
            ),
            pending_setup=SessionSetup(
                identity_key=user.keys.identity_key.public_key,
                ephemeral_key=ephemeral_key.public_key(),
                one_time_pre_key=recipient.public_one_time_pre_key,
            ),
        )

    @classmethod
    def accept(cls, user: User, message: EncryptedMessage) -> "ChatSession":
        setup = message.session_setup
        if setup is None:
            raise ValueError("first message is missing session setup information")

        root_key = x3dh_recipient(
            identity_key=user.keys.identity_key,
            signed_pre_key=user.keys.signed_pre_key,
            one_time_pre_key=_match_one_time_pre_key(user, setup.one_time_pre_key),
            initiator_identity_key=setup.identity_key,
            initiator_ephemeral_key=setup.ephemeral_key,
        )
        return cls(
            ratchet=DoubleRatchet.accept(
                root_key=root_key,
                signed_pre_key=user.keys.signed_pre_key.private_key,
            )
        )

    def encrypt(self, plaintext: str) -> EncryptedMessage:
        message = self.ratchet.encrypt(plaintext.encode())
        if self.pending_setup is not None:
            message = dataclasses.replace(message, session_setup=self.pending_setup)
            self.pending_setup = None
        return message

    def decrypt(self, message: EncryptedMessage) -> str:
        return self.ratchet.decrypt(message).decode()


def _match_one_time_pre_key(user: User, public_key: X25519PublicKey) -> OneTimePreKey:
    raw = public_key.public_bytes_raw()
    return next(
        one_time_pre_key
        for one_time_pre_key in user.keys.one_time_pre_keys
        if one_time_pre_key.public_key.public_bytes_raw() == raw
    )
