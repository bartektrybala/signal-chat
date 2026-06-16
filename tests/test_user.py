from src import aliases
from src.user import ONE_TIME_PRE_KEY_COUNT, create_user


class TestUserKeys:
    def test_public_part(self) -> None:
        # given
        user = create_user(username=aliases.Username("user"))

        # when
        public_keys = user.keys.public_keys()

        # then
        identity_key = user.keys.identity_key
        assert public_keys.public_identity_key == identity_key.public_key
        assert public_keys.public_signing_key == identity_key.signing_public_key
        assert (
            public_keys.public_signed_pre_key.public_key
            == user.keys.signed_pre_key.public_key
        )
        assert len(public_keys.public_one_time_pre_keys) == ONE_TIME_PRE_KEY_COUNT

    def test_signed_pre_key_is_signed_by_identity(self) -> None:
        # given
        user = create_user(username=aliases.Username("user"))

        # when / then
        user.keys.public_keys().verify()
