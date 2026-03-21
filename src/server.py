import dataclasses

from src import aliases
from src.inteface import UserPublicKeys


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

    def fetch_user_public_keys(self, username: aliases.Username) -> UserPublicKeys:
        user_pks = self.users[username]
        to_return = UserPublicKeys(
            public_identity_key=user_pks.public_identity_key,
            public_signed_pre_key=user_pks.public_signed_pre_key,
        )
        return to_return
