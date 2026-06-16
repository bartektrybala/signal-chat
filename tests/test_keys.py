from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def test_x25519_ecdh_is_symmetric() -> None:
    # given
    alice = X25519PrivateKey.generate()
    bob = X25519PrivateKey.generate()

    # when
    alice_shared = alice.exchange(bob.public_key())
    bob_shared = bob.exchange(alice.public_key())

    # then
    assert alice_shared == bob_shared


def test_ed25519_sign_and_verify() -> None:
    # given
    private_key = Ed25519PrivateKey.generate()
    data = b"signed pre key"

    # when
    signature = private_key.sign(data)

    # then
    private_key.public_key().verify(signature=signature, data=data)
