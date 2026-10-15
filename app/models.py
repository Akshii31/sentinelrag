"""Pydantic request and response contracts for the SentinelRAG API."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    mode: Literal["llm", "offline"] = "offline"
    top_k: int = Field(default=3, ge=1, le=5)

    @field_validator("question")
    @classmethod
    def strip_question(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("question cannot be blank")
        return value


class Citation(BaseModel):
    document: str
    section: str
    chunk_id: int


class RetrievalResult(BaseModel):
    chunk_id: int
    score: float


class AskResponse(BaseModel):
    answer: str
    citations: list[Citation] = Field(default_factory=list)
    retrieval: list[RetrievalResult] = Field(default_factory=list)
    refusal: bool = False
    flagged: bool = False
    request_id: int | None = None


class HealthResponse(BaseModel):
    status: str
