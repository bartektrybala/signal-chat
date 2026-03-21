import dataclasses

from src import aliases
from src.keys import (
    IdentityKey,
    PublicSignedPreKey,
    SignedPreKey,
    UserPublicKeys,
    generate_private_key,
)


@dataclasses.dataclass
class UserKeys:
    identity_key: IdentityKey
    signed_pre_key: SignedPreKey

    def public_keys(self) -> UserPublicKeys:
        return UserPublicKeys(
            public_identity_key=self.identity_key.public_key,
            public_signed_pre_key=PublicSignedPreKey(
                public_key=self.signed_pre_key.public_key,
                signature=aliases.Signature(self.signed_pre_key.signature),
            ),
        )


@dataclasses.dataclass
class User:
    username: aliases.Username
    keys: UserKeys


def create_user(username: aliases.Username) -> User:
    identity_private_key = generate_private_key()

    identity_key = IdentityKey(
        private_key=identity_private_key,
        public_key=identity_private_key.public_key(),
    )

    signed_pre_key_private_key = generate_private_key()
    signed_pre_key_public_key = signed_pre_key_private_key.public_key()
    signature = identity_key.sign(public_key=signed_pre_key_public_key)
    signed_pre_key = SignedPreKey(
        private_key=signed_pre_key_private_key,
        public_key=signed_pre_key_public_key,
        signature=signature,
    )

    return User(
        username=username,
        keys=UserKeys(identity_key=identity_key, signed_pre_key=signed_pre_key),
    )
