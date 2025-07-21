import dataclasses

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
)

from src import aliases
from src.user import UserPublicKeys


@dataclasses.dataclass
class FetchedUserKeys:
    username: aliases.Username
    public_identity_key: X25519PublicKey
    public_signed_pre_key: X25519PublicKey
    public_one_time_pre_key: X25519PublicKey


@dataclasses.dataclass
class Server:
    users: dict[aliases.Username, UserPublicKeys] = dataclasses.field(
        default_factory=dict
    )

    def register_user(
        self, username: aliases.Username, user_public_keys: UserPublicKeys
    ) -> None:
        user_public_keys.public_identity_key.verify(
            user_public_keys.public_signed_pre_key.signature,
            user_public_keys.public_signed_pre_key.public_key.public_bytes_raw(),
        )
        self.users[username] = user_public_keys

    def fetch_user_keys(self, username: aliases.Username) -> FetchedUserKeys:
        user_keys = self.users[username]
        fetched_user_keys = FetchedUserKeys(
            username=username,
            public_identity_key=user_keys.public_identity_key,
            public_signed_pre_key=user_keys.public_signed_pre_key.public_key,
            public_one_time_pre_key=user_keys.public_one_time_pre_keys[0],
        )
        user_keys.public_one_time_pre_keys = user_keys.public_one_time_pre_keys[1:]
        return fetched_user_keys
