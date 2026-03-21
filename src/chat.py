import dataclasses

from src.keys import ChatParticipant


@dataclasses.dataclass(frozen=True)
class ChatRoom:
    initiator: ChatParticipant
    receipient: ChatParticipant
