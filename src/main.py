from src import aliases
from src.server import Server
from src.user import create_user

if __name__ == "__main__":
    server = Server()
    alice = create_user(username=aliases.Username("alice"))

    server.register_user(
        username=alice.username,
        user_publik_keys=alice.keys.public_part(),
    )
