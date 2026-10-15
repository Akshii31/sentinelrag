"""FastAPI entry point for SentinelRAG."""

from contextlib import asynccontextmanager
from typing import Callable
import re

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from app.config import Settings
from app.db import AuditLogError, AuditLogger
from app.llm_client import LLMServiceError, call_llm
from app.models import AskRequest, AskResponse, HealthResponse
from app.prompts import SYSTEM_PROMPT, build_user_prompt
from app.retrieval import DocumentRetriever
from app.security import (
    InMemoryRateLimiter,
    api_key_is_configured,
    check_api_key,
    check_injection,
    key_fingerprint,
)

LLMCallable = Callable[[str, str, Settings], str]
_CITATION_PATTERN = re.compile(r"\[([^\]#]+)#([^\]]+)\]")


def validate_grounded_answer(answer: str, citations: list[dict]) -> str:
    """Accept only non-empty LLM output with citations from retrieved evidence.

    This is a response-contract check, not a guarantee that an LLM faithfully
    summarized every passage. It prevents an answer with missing or fabricated
    source labels from being returned as grounded evidence.
    """
    if not isinstance(answer, str) or not answer.strip():
        raise LLMServiceError("LLM provider returned an empty answer")

    allowed = {
        (citation["document"], citation["section"])
        for citation in citations
    }
    found = {
        (match.group(1).strip(), match.group(2).strip())
        for match in _CITATION_PATTERN.finditer(answer)
    }
    if not found:
        raise LLMServiceError("LLM response lacked citations to retrieved evidence")
    if not found.issubset(allowed):
        raise LLMServiceError("LLM response contained a citation outside retrieved evidence")
    return answer.strip()


def create_app(
    settings: Settings | None = None,
    retriever: DocumentRetriever | None = None,
    llm_callable: LLMCallable | None = None,
    audit_logger: AuditLogger | None = None,
) -> FastAPI:
    config = settings or Settings.from_env()
    llm = llm_callable or call_llm
    logger = audit_logger or AuditLogger(config.db_path)
    try:
        document_retriever = retriever or DocumentRetriever(config.data_dir)
        retrieval_error = ""
    except (FileNotFoundError, ValueError) as exc:
        document_retriever = None
        retrieval_error = str(exc)

    limiter = InMemoryRateLimiter(
        max_requests=config.rate_limit_requests,
        window_seconds=config.rate_limit_window_seconds,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        logger.close()

    application = FastAPI(
        title="SentinelRAG API",
        description=(
            "A portfolio prototype for grounded cybersecurity runbook Q&A. "
            "Heuristic checks reduce some risks but do not guarantee security."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )
    application.state.settings = config
    application.state.retriever = document_retriever
    application.state.logger = logger
    application.state.rate_limiter = limiter
    application.state.llm_callable = llm
    application.state.retrieval_error = retrieval_error

    def record_event(**event: object) -> int | JSONResponse:
        """Persist an audit event or fail closed if persistent auditing is unavailable."""
        try:
            return logger.log_request(**event)  # type: ignore[arg-type]
        except AuditLogError:
            return JSONResponse(
                status_code=503,
                content={"detail": "Audit logging is unavailable; request was not completed."},
            )

    @application.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        if application.state.retriever is None:
            return HealthResponse(status="degraded: knowledge base unavailable")
        return HealthResponse(status="ok")

    @application.post("/ask", response_model=AskResponse)
    def ask(
        body: AskRequest,
        request: Request,
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ):
        identity = key_fingerprint(x_api_key)

        if not api_key_is_configured(config.api_key):
            audit_result = record_event(
                key_fingerprint=identity,
                decision="authentication_failure",
                question=body.question,
                mode=body.mode,
                status_code=503,
                reason="api_key_not_configured",
            )
            if isinstance(audit_result, JSONResponse):
                return audit_result
            return JSONResponse(
                status_code=503,
                content={"detail": "Server API key is not configured. Set a non-placeholder SENTINELRAG_API_KEY in .env."},
            )

        if not check_api_key(x_api_key, config.api_key):
            audit_result = record_event(
                key_fingerprint=identity,
                decision="authentication_failure",
                question=body.question,
                mode=body.mode,
                status_code=401,
                reason="invalid_api_key",
            )
            if isinstance(audit_result, JSONResponse):
                return audit_result
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})

        if not limiter.allow(identity):
            audit_result = record_event(
                key_fingerprint=identity,
                decision="rate_limited",
                question=body.question,
                mode=body.mode,
                status_code=429,
                reason="rate_limit_exceeded",
            )
            if isinstance(audit_result, JSONResponse):
                return audit_result
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded; try again later."},
                headers={"Retry-After": str(config.rate_limit_window_seconds)},
            )

        flagged, reason = check_injection(body.question)
        if flagged:
            request_id = record_event(
                key_fingerprint=identity,
                decision="block",
                question=body.question,
                mode=body.mode,
                status_code=403,
                flagged=True,
                reason=reason,
                answer_snippet="Request blocked before retrieval and LLM call.",
            )
            if isinstance(request_id, JSONResponse):
                return request_id
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Request blocked by the input security policy.",
                    "flagged": True,
                    "reason": reason,
                    "request_id": request_id,
                },
            )

        if len(body.question) > config.max_question_chars:
            audit_result = record_event(
                key_fingerprint=identity,
                decision="request_rejected",
                question=body.question,
                mode=body.mode,
                status_code=413,
                reason="question_too_long",
            )
            if isinstance(audit_result, JSONResponse):
                return audit_result
            return JSONResponse(status_code=413, content={"detail": "Question is too long"})

        if application.state.retriever is None:
            audit_result = record_event(
                key_fingerprint=identity,
                decision="system_error",
                question=body.question,
                mode=body.mode,
                status_code=503,
                reason="knowledge_base_unavailable",
            )
            if isinstance(audit_result, JSONResponse):
                return audit_result
            return JSONResponse(
                status_code=503,
                content={"detail": f"Knowledge base unavailable: {application.state.retrieval_error}"},
            )

        results = application.state.retriever.search(body.question, top_k=body.top_k)
        best_score = results[0]["score"] if results else 0.0
        retrieval_summary = [
            {"chunk_id": item["chunk_id"], "score": item["score"]}
            for item in results
        ]

        if not results or best_score < config.min_similarity:
            answer = "Insufficient evidence in the knowledge base to answer this question reliably."
            request_id = record_event(
                key_fingerprint=identity,
                decision="refuse",
                question=body.question,
                mode=body.mode,
                status_code=200,
                similarity=best_score,
                reason="insufficient_retrieval_evidence",
                answer_snippet=answer,
            )
            if isinstance(request_id, JSONResponse):
                return request_id
            return AskResponse(
                answer=answer,
                citations=[],
                retrieval=retrieval_summary,
                refusal=True,
                request_id=request_id,
            )

        citations = [
            {
                "document": item["document"],
                "section": item["section"],
                "chunk_id": item["chunk_id"],
            }
            for item in results
        ]

        if body.mode == "offline":
            answer_lines = ["Retrieved evidence (offline mode):"]
            for item in results:
                answer_lines.append(
                    f"\n- [{item['document']}#{item['section']}] {item['text']}"
                )
            answer = "\n".join(answer_lines)
        else:
            if not config.llm_api_key or not config.llm_model:
                audit_result = record_event(
                    key_fingerprint=identity,
                    decision="provider_error",
                    question=body.question,
                    mode=body.mode,
                    status_code=503,
                    similarity=best_score,
                    reason="llm_not_configured",
                )
                if isinstance(audit_result, JSONResponse):
                    return audit_result
                return JSONResponse(
                    status_code=503,
                    content={"detail": "LLM mode requires LLM_API_KEY and LLM_MODEL in .env."},
                )
            user_prompt = build_user_prompt(body.question, results)
            try:
                answer = validate_grounded_answer(
                    llm(SYSTEM_PROMPT, user_prompt, config),
                    citations,
                )
            except LLMServiceError as exc:
                request_id = record_event(
                    key_fingerprint=identity,
                    decision="provider_error",
                    question=body.question,
                    mode=body.mode,
                    status_code=502,
                    similarity=best_score,
                    reason="llm_upstream_error",
                    answer_snippet=str(exc),
                )
                if isinstance(request_id, JSONResponse):
                    return request_id
                return JSONResponse(
                    status_code=502,
                    content={"detail": str(exc), "request_id": request_id},
                )

        request_id = record_event(
            key_fingerprint=identity,
            decision="allow",
            question=body.question,
            mode=body.mode,
            status_code=200,
            similarity=best_score,
            answer_snippet=answer,
        )
        if isinstance(request_id, JSONResponse):
            return request_id
        return AskResponse(
            answer=answer,
            citations=citations,
            retrieval=retrieval_summary,
            refusal=False,
            request_id=request_id,
        )

    return application


app = create_app()
