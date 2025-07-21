

from src import aliases
from src.encrypt import Encryptor
from src.user import create_user


class TestEncrypt:
    def test_calc_initial_master_secret(self) -> None:
        # given
        user1 = create_user(username=aliases.Username("user1"))
        user2 = create_user(username=aliases.Username("user2"))
        
        user1_encryptor = Encryptor(user_keys=user1.keys)
        user2_encryptor = Encryptor(user_keys=user2.keys)

        # when
        user1_master_secret = user1_encryptor.calc_initial_master_secret(
            other_public_identity_key=user2.keys.identity_key.public_key,
            other_public_signed_pre_key=user2.keys.signed_pre_key.public_key,
            other_public_one_time_pre_key=user2.keys.one_time_pre_keys[0].public_key
        )
        user2_master_secret = user2_encryptor.calc_initial_master_secret(
            other_public_identity_key=user1.keys.identity_key.public_key,
            other_public_signed_pre_key=user1.keys.signed_pre_key.public_key,
            other_public_one_time_pre_key=user1.keys.one_time_pre_keys[0].public_key
        )

        # then
        assert user1_master_secret == user2_master_secret
