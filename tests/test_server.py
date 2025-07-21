import cryptography
import cryptography.exceptions
import pytest

from src import aliases
from src.server import FetchedUserKeys, Server
from src.user import create_user


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
                user_public_keys=user.keys.public_part(),
            )

    def test_register_user_valid_signature(self) -> None:
        # given
        server = Server()
        user = create_user(username=aliases.Username("user"))

        # when
        server.register_user(
            username=user.username,
            user_public_keys=user.keys.public_part(),
        )

        # then
        assert user.username in server.users

    def test_fetch_keys_for_username(self) -> None:
        # given
        server = Server()
        user = create_user(username=aliases.Username("user"))

        server.register_user(
            username=user.username,
            user_public_keys=user.keys.public_part(),
        )
        assert len(server.users[user.username].public_one_time_pre_keys) == 3

        # when
        fetched_user_keys = server.fetch_user_keys(
            username=aliases.Username("user"),
        )

        # then
        assert fetched_user_keys == FetchedUserKeys(
            username=user.username,
            public_identity_key=user.keys.identity_key.public_key,
            public_signed_pre_key=user.keys.signed_pre_key.public_key,
            public_one_time_pre_key=user.keys.one_time_pre_keys[0].public_key,
        )
        assert len(server.users[user.username].public_one_time_pre_keys) == 2
