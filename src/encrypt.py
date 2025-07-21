import dataclasses

from src.user import UserKeys
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
)


@dataclasses.dataclass
class Encryptor:
    user_keys: UserKeys

    def calc_initial_master_secret(
        self,
        other_public_identity_key: X25519PublicKey,
        other_public_signed_pre_key: X25519PublicKey,
        other_public_one_time_pre_key: X25519PublicKey,
    ) -> bytes:
        self.user_keys.identity_key.private_key
