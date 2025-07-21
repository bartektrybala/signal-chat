import dataclasses

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from src import aliases


@dataclasses.dataclass
class ECKey:
    private_key: X25519PrivateKey
    public_key: X25519PublicKey


@dataclasses.dataclass
class SignedPreKey(ECKey):
    signature: bytes


@dataclasses.dataclass
class PublicSignedPreKey:
    public_key: X25519PublicKey
    signature: aliases.Signature


@dataclasses.dataclass
class UserPublicKeys:
    public_identity_key: X25519PublicKey
    public_signed_pre_key: PublicSignedPreKey
    public_one_time_pre_keys: tuple[X25519PublicKey, ...]


@dataclasses.dataclass
class UserKeys:
    identity_key: ECKey
    signed_pre_key: SignedPreKey
    one_time_pre_keys: tuple[ECKey, ...]

    def public_part(self) -> UserPublicKeys:
        return UserPublicKeys(
            public_identity_key=self.identity_key.public_key,
            public_signed_pre_key=PublicSignedPreKey(
                public_key=self.signed_pre_key.public_key,
                signature=aliases.Signature(self.signed_pre_key.signature),
            ),
            public_one_time_pre_keys=tuple(
                one_time_key.public_key for one_time_key in self.one_time_pre_keys
            ),
        )


@dataclasses.dataclass
class User:
    username: aliases.Username
    keys: UserKeys


def create_user(username: aliases.Username) -> User:
    identity_private_key = X25519PrivateKey.generate()

    identity_key = ECKey(
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

    one_time_pre_keys = tuple(
        ECKey(private_key=private_key, public_key=private_key.public_key())
        for private_key in (X25519PrivateKey.generate() for _ in range(3))
    )

    return User(
        username=username,
        keys=UserKeys(
            identity_key=identity_key,
            signed_pre_key=signed_pre_key,
            one_time_pre_keys=one_time_pre_keys,
        ),
    )
