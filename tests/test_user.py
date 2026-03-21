from src import aliases
from src.keys import PublicSignedPreKey, UserPublicKeys
from src.user import create_user


class TestUserKeys:
    def test_public_part(self) -> None:
        # given
        user = create_user(username=aliases.Username("user"))

        # when
        public_keys = user.keys.public_keys()

        # then
        assert public_keys == UserPublicKeys(
            public_identity_key=user.keys.identity_key.public_key,
            public_signed_pre_key=PublicSignedPreKey(
                public_key=user.keys.signed_pre_key.public_key,
                signature=aliases.Signature(user.keys.signed_pre_key.signature),
            ),
        )
