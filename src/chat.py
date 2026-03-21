import dataclasses

from src.inteface import ChatParticipant


@dataclasses.dataclass(frozen=True)
class ChatRoom:
    initiator: ChatParticipant
    receipient: ChatParticipant
