import cryptography
import cryptography.exceptions
import pytest

from src import aliases
from src.keys import PreKeyBundle
from src.server import Server
from src.user import ONE_TIME_PRE_KEY_COUNT, create_user


class TestServer:
    def test_register_user_invalid_signature(self) -> None:
        # given
        server = Server()
        user = create_user(username=aliases.Username("user"))

        # when
        user.keys.signed_pre_key.signature = aliases.Signature(b"invalid_signature")

        # then
        with pytest.raises(cryptography.exceptions.InvalidSignature):
            server.register_user(
                username=user.username,
                user_public_keys=user.keys.public_keys(),
            )

    def test_register_user_valid_signature(self) -> None:
        # given
        server = Server()
        user = create_user(username=aliases.Username("user"))

        # when
        server.register_user(
            username=user.username,
            user_public_keys=user.keys.public_keys(),
        )

        # then
        assert user.username in server.users

    def test_fetch_pre_key_bundle_consumes_one_time_pre_key(self) -> None:
        # given
        server = Server()
        user = create_user(username=aliases.Username("user"))
        server.register_user(
            username=user.username,
            user_public_keys=user.keys.public_keys(),
        )

        # when
        bundle = server.fetch_pre_key_bundle(username=user.username)

        # then
        assert isinstance(bundle, PreKeyBundle)
        bundle.verify()
        assert bundle.public_one_time_pre_key is not None
        assert (
            len(server.users[user.username].public_one_time_pre_keys)
            == ONE_TIME_PRE_KEY_COUNT - 1
        )
