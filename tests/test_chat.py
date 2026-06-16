from src import aliases
from src.chat import ChatSession
from src.server import Server
from src.user import create_user


class TestChatSession:
    def test_alice_sends_a_single_message_to_bob(self) -> None:
        # given
        server = Server()
        alice = create_user(username=aliases.Username("alice"))
        bob = create_user(username=aliases.Username("bob"))
        server.register_user(
            username=bob.username, user_public_keys=bob.keys.public_keys()
        )
        alice_session = ChatSession.initiate(
            user=alice, recipient=server.fetch_pre_key_bundle(username=bob.username)
        )

        # when
        message = alice_session.encrypt("Hi Bob")
        bob_session = ChatSession.accept(user=bob, message=message)

        # then
        assert bob_session.decrypt(message) == "Hi Bob"

    def test_alice_sends_several_messages_in_a_row(self) -> None:
        # given
        server = Server()
        alice = create_user(username=aliases.Username("alice"))
        bob = create_user(username=aliases.Username("bob"))

        server.register_user(
            username=bob.username, user_public_keys=bob.keys.public_keys()
        )
        alice_session = ChatSession.initiate(
            user=alice, recipient=server.fetch_pre_key_bundle(username=bob.username)
        )

        # when
        # NOTE: alice_session.rachet.send_chain_key -> a new chain key with each message
        hi = alice_session.encrypt("Hi Bob")
        message_1 = alice_session.encrypt("How are you?")
        message_2 = alice_session.encrypt("Are you free later?")
        message_3 = alice_session.encrypt("Coffee?")

        # then
        bob_session = ChatSession.accept(user=bob, message=hi)
        assert bob_session.decrypt(hi) == "Hi Bob"
        assert bob_session.decrypt(message_1) == "How are you?"
        assert bob_session.decrypt(message_2) == "Are you free later?"
        assert bob_session.decrypt(message_3) == "Coffee?"

    def test_bob_replies_to_alice(self) -> None:
        # given
        server = Server()
        alice = create_user(username=aliases.Username("alice"))
        bob = create_user(username=aliases.Username("bob"))
        server.register_user(
            username=bob.username, user_public_keys=bob.keys.public_keys()
        )
        alice_session = ChatSession.initiate(
            user=alice, recipient=server.fetch_pre_key_bundle(username=bob.username)
        )

        # when
        message = alice_session.encrypt("Hi Bob")
        bob_session = ChatSession.accept(user=bob, message=message)
        bob_session.decrypt(message)

        # then
        reply = bob_session.encrypt("Hi Alice, I'm good!")
        assert alice_session.decrypt(reply) == "Hi Alice, I'm good!"

        # NOTE: alice_session.rachet.root_key -> a new ECDH with each message round-trip
        assert alice_session

    def test_alice_and_bob_hold_a_back_and_forth_conversation(self) -> None:
        # given
        server = Server()
        alice = create_user(username=aliases.Username("alice"))
        bob = create_user(username=aliases.Username("bob"))
        server.register_user(
            username=bob.username, user_public_keys=bob.keys.public_keys()
        )
        alice_session = ChatSession.initiate(
            user=alice, recipient=server.fetch_pre_key_bundle(username=bob.username)
        )
        first = alice_session.encrypt("Hi Bob")
        bob_session = ChatSession.accept(user=bob, message=first)

        # when / then
        assert bob_session.decrypt(first) == "Hi Bob"
        assert alice_session.decrypt(bob_session.encrypt("Hey Alice")) == "Hey Alice"
        assert (
            bob_session.decrypt(alice_session.encrypt("How are you")) == "How are you"
        )
        assert alice_session.decrypt(bob_session.encrypt("Doing well")) == "Doing well"
