from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src import aliases
from src.keys import PreKeyBundle, PublicSignedPreKey
from src.user import create_user
from src.x3dh import ROOT_KEY_LENGTH, x3dh_initiator, x3dh_recipient


class TestX3DH:
    def test_initiator_and_recipient_derive_the_same_root_key(self) -> None:
        # given
        alice = create_user(username=aliases.Username("alice"))
        bob = create_user(username=aliases.Username("bob"))
        ephemeral_key = X25519PrivateKey.generate()
        one_time_pre_key = bob.keys.one_time_pre_keys[0]
        bundle = PreKeyBundle(
            public_identity_key=bob.keys.identity_key.public_key,
            public_signing_key=bob.keys.identity_key.signing_public_key,
            public_signed_pre_key=PublicSignedPreKey(
                public_key=bob.keys.signed_pre_key.public_key,
                signature=bob.keys.signed_pre_key.signature,
            ),
            public_one_time_pre_key=one_time_pre_key.public_key,
        )

        # when
        initiator_root_key = x3dh_initiator(
            identity_key=alice.keys.identity_key,
            ephemeral_key=ephemeral_key,
            recipient=bundle,
        )
        recipient_root_key = x3dh_recipient(
            identity_key=bob.keys.identity_key,
            signed_pre_key=bob.keys.signed_pre_key,
            one_time_pre_key=one_time_pre_key,
            initiator_identity_key=alice.keys.identity_key.public_key,
            initiator_ephemeral_key=ephemeral_key.public_key(),
        )

        # then
        assert initiator_root_key == recipient_root_key
        assert len(initiator_root_key) == ROOT_KEY_LENGTH
