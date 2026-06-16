import dataclasses

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src import aliases
from src.keys import (
    IdentityKey,
    OneTimePreKey,
    PublicSignedPreKey,
    SignedPreKey,
    UserPublicKeys,
    generate_private_key,
)

ONE_TIME_PRE_KEY_COUNT = 5


@dataclasses.dataclass
class UserKeys:
    identity_key: IdentityKey
    signed_pre_key: SignedPreKey
    one_time_pre_keys: list[OneTimePreKey]

    def public_keys(self) -> UserPublicKeys:
        return UserPublicKeys(
            public_identity_key=self.identity_key.public_key,
            public_signing_key=self.identity_key.signing_public_key,
            public_signed_pre_key=PublicSignedPreKey(
                public_key=self.signed_pre_key.public_key,
                signature=self.signed_pre_key.signature,
            ),
            public_one_time_pre_keys=[
                one_time_pre_key.public_key
                for one_time_pre_key in self.one_time_pre_keys
            ],
        )


@dataclasses.dataclass
class User:
    username: aliases.Username
    keys: UserKeys


def create_user(username: aliases.Username) -> User:
    identity_private_key = generate_private_key()
    signing_private_key = Ed25519PrivateKey.generate()
    identity_key = IdentityKey(
        private_key=identity_private_key,
        public_key=identity_private_key.public_key(),
        signing_private_key=signing_private_key,
        signing_public_key=signing_private_key.public_key(),
    )

    signed_pre_key_private_key = generate_private_key()
    signed_pre_key_public_key = signed_pre_key_private_key.public_key()
    signed_pre_key = SignedPreKey(
        private_key=signed_pre_key_private_key,
        public_key=signed_pre_key_public_key,
        signature=identity_key.sign(public_key=signed_pre_key_public_key),
    )

    return User(
        username=username,
        keys=UserKeys(
            identity_key=identity_key,
            signed_pre_key=signed_pre_key,
            one_time_pre_keys=[
                create_one_time_pre_key() for _ in range(ONE_TIME_PRE_KEY_COUNT)
            ],
        ),
    )


def create_one_time_pre_key() -> OneTimePreKey:
    private_key = generate_private_key()
    return OneTimePreKey(private_key=private_key, public_key=private_key.public_key())
