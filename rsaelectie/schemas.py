from typing import List
from pydantic import BaseModel

class Data(BaseModel):
    token: str = None
    party_id: str
    election_id: str
    candidates_ids: List[str] = []
