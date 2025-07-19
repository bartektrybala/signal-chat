import cryptography
import cryptography.exceptions
import pytest

from src import aliases
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
                user_publik_keys=user.keys.public_part(),
            )
