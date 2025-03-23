from pydantic import BaseModel
from datetime import datetime

class ConversationSchema(BaseModel):
    id: int
    user_prompt: str
    response: str
    timestamp: datetime

    class Config:
        orm_mode = True         # Enable compatibility with ORM objects (Pydantic v1)
        from_attributes = True  # Required for using .from_orm() with Pydantic v2
