import dataclasses

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from src import aliases
from src.user import PublicSignedPreKey, UserPublicKeys, create_user


class TestUserKeys:
    def test_public_part(self) -> None:
        # given
        user = create_user(username=aliases.Username("user"))

        # when
        public_keys = user.keys.public_part()

        # then
        assert public_keys == UserPublicKeys(
            public_identity_key=user.keys.identity_key.public_key,
            public_signed_pre_key=PublicSignedPreKey(
                public_key=user.keys.signed_pre_key.public_key,
                signature=aliases.Signature(user.keys.signed_pre_key.signature),
            ),
            public_one_time_pre_keys=tuple(
                one_time_key.public_key for one_time_key in user.keys.one_time_pre_keys
            ),
        )

    def test_if_public_part_doesnt_contain_any_private_keys(self) -> None:
        # given
        user = create_user(username=aliases.Username("user"))

        # when
        public_keys = user.keys.public_part()

        # then
        def _check(
            field: Ed25519PublicKey
            | PublicSignedPreKey
            | aliases.Signature
            | list[Ed25519PublicKey],
        ) -> None:
            assert user.keys.identity_key.private_key != field
            assert user.keys.identity_key.private_key.private_bytes_raw() != field

            assert user.keys.signed_pre_key.private_key != field
            assert user.keys.signed_pre_key.private_key.private_bytes_raw() != field

            assert all(
                one_time_key.private_key != field
                for one_time_key in user.keys.one_time_pre_keys
            )
            assert all(
                one_time_key.private_key.private_bytes_raw() != field
                for one_time_key in user.keys.one_time_pre_keys
            )

            if dataclasses.is_dataclass(field):
                for value in field.__dict__.values():
                    _check(value)

            if isinstance(field, list):
                for item in field:
                    _check(item)

        for field in public_keys.__dict__.values():
            _check(field)
