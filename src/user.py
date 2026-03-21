import dataclasses

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from src import aliases
from src.inteface import (
    IdentityKey,
    PublicSignedPreKey,
    SignedPreKey,
    UserPublicKeys,
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
    identity_private_key = Ed25519PrivateKey.generate()

    identity_key = IdentityKey(
        private_key=identity_private_key,
        public_key=identity_private_key.public_key(),
    )

    signed_pre_key_private_key = X25519PrivateKey.generate()
    signed_pre_key_public_key = signed_pre_key_private_key.public_key()
    signed_pre_key = SignedPreKey(
        private_key=signed_pre_key_private_key,
        public_key=signed_pre_key_public_key,
        signature=identity_key.private_key.sign(
            signed_pre_key_public_key.public_bytes_raw()
        ),
    )

    return User(
        username=username,
        keys=UserKeys(
            identity_key=identity_key,
            signed_pre_key=signed_pre_key,
        ),
    )
