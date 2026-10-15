"""Small OpenAI-compatible chat-completions adapter."""

import requests

from app.config import Settings


class LLMServiceError(RuntimeError):
    """Raised when an upstream LLM cannot provide a valid answer."""


def call_llm(system_prompt: str, user_prompt: str, settings: Settings) -> str:
    """Call a configured OpenAI-compatible endpoint without exposing secrets."""
    if not settings.llm_api_key:
        raise LLMServiceError("LLM_API_KEY is not configured")
    if not settings.llm_model:
        raise LLMServiceError("LLM_MODEL is not configured")

    url = f"{settings.llm_base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": settings.llm_model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    try:
        response = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {settings.llm_api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=settings.llm_timeout_seconds,
        )
        response.raise_for_status()
        body = response.json()
        answer = body["choices"][0]["message"]["content"]
        if not isinstance(answer, str) or not answer.strip():
            raise LLMServiceError("LLM provider returned an empty answer")
        return answer.strip()
    except LLMServiceError:
        raise
    except requests.Timeout as exc:
        raise LLMServiceError("LLM provider request timed out") from exc
    except requests.HTTPError as exc:
        # Do not include the provider response body or headers: either can contain
        # implementation details or sensitive data.
        status_code = exc.response.status_code if exc.response is not None else None
        if status_code in {401, 403}:
            message = "LLM provider authentication failed; check LLM_API_KEY"
        elif status_code == 429:
            message = "LLM provider rate limit reached; try again later"
        elif status_code is not None and status_code >= 500:
            message = "LLM provider is temporarily unavailable"
        else:
            message = "LLM provider returned an HTTP error"
        raise LLMServiceError(message) from exc
    except requests.RequestException as exc:
        raise LLMServiceError("LLM provider network request failed") from exc
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise LLMServiceError("LLM provider returned a malformed response") from exc
