import dataclasses

from src import aliases
from src.keys import PreKeyBundle, UserPublicKeys


@dataclasses.dataclass
class Server:
    users: dict[aliases.Username, UserPublicKeys] = dataclasses.field(
        default_factory=dict
    )

    def register_user(
        self, username: aliases.Username, user_public_keys: UserPublicKeys
    ) -> None:
        user_public_keys.verify()
        self.users[username] = user_public_keys

    def fetch_pre_key_bundle(self, username: aliases.Username) -> PreKeyBundle:
        user_public_keys = self.users[username]
        # A One-Time Pre Key is only used once, so it is removed from server storage
        # after being requested. We assume the batch is never exhausted.
        one_time_pre_key = user_public_keys.public_one_time_pre_keys.pop(0)
        return PreKeyBundle(
            public_identity_key=user_public_keys.public_identity_key,
            public_signing_key=user_public_keys.public_signing_key,
            public_signed_pre_key=user_public_keys.public_signed_pre_key,
            public_one_time_pre_key=one_time_pre_key,
        )
