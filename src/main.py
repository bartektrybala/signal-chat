from src import aliases
from src.chat import ChatRoom
from src.keys import ChatParticipant
from src.server import Server
from src.user import create_user

if __name__ == "__main__":
    server = Server()

    alice = create_user(username=aliases.Username("alice"))
    bob = create_user(username=aliases.Username("bob"))

    server.register_user(
        username=alice.username,
        user_public_keys=alice.keys.public_keys(),
    )
    server.register_user(
        username=bob.username,
        user_public_keys=bob.keys.public_keys(),
    )

    alice_public_keys = alice.keys.public_keys()
    bob_public_keys = server.fetch_user_public_keys(username=bob.username)

    bob_public_keys.verify(
        signature=bob_public_keys.public_signed_pre_key.signature,
        public_key=bob_public_keys.public_signed_pre_key.public_key,
    )
    ChatRoom(
        initiator=ChatParticipant(
            username=alice.username,
            public_keys=alice_public_keys,
        ),
        receipient=ChatParticipant(
            username=bob.username,
            public_keys=bob_public_keys,
        ),
    )
