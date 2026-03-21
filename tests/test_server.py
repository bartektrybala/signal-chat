import cryptography
import cryptography.exceptions
import pytest

from src import aliases
from src.keys import UserPublicKeys
from src.server import Server
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

    def test_fetch_user_public_keys(self) -> None:
        # given
        server = Server()
        user = create_user(username=aliases.Username("user"))

        server.register_user(
            username=user.username,
            user_public_keys=user.keys.public_keys(),
        )

        # when
        user_public_keys = server.fetch_user_public_keys(
            username=aliases.Username("user"),
        )

        # then
        assert isinstance(user_public_keys, UserPublicKeys)
        assert user_public_keys.public_identity_key == user.keys.identity_key.public_key

        signature = user_public_keys.public_signed_pre_key.signature
        public_key = user_public_keys.public_signed_pre_key.public_key
        user_public_keys.verify(signature=signature, public_key=public_key)
