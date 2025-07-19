import dataclasses

from src import aliases
from src.user import UserPublicKeys


@dataclasses.dataclass
class Server:
    users: dict[aliases.Username, UserPublicKeys] = dataclasses.field(
        default_factory=dict
    )

    def register_user(
        self, username: aliases.Username, user_publik_keys: UserPublicKeys
    ) -> None:
        user_publik_keys.public_identity_key.verify(
            user_publik_keys.public_signed_pre_key.signature,
            user_publik_keys.public_signed_pre_key.public_key.public_bytes_raw(),
        )
        self.users[username] = user_publik_keys
