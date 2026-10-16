"""Local Streamlit chat interface for the SentinelRAG FastAPI service.

Run the API and this UI as separate local processes. The browser talks only to
Streamlit; Streamlit loads the local API key and sends it to FastAPI server-side.
"""

from typing import Any

import requests
import streamlit as st

from app.config import Settings
from app.security import api_key_is_configured


API_URL = "http://127.0.0.1:8000/ask"
REQUEST_TIMEOUT_SECONDS = 20
WELCOME_MESSAGE = (
    "Ask a question about the incident-response runbooks. SentinelRAG will show "
    "retrieved evidence from the local cybersecurity knowledge base."
)
EXAMPLE_QUESTIONS = (
    "What should I do about a suspicious email attachment?",
    "What are the immediate actions for suspected ransomware?",
    "How should we respond to a critical CVE?",
)


def ask_backend(question: str, api_key: str) -> tuple[dict[str, Any] | None, str | None]:
    """Call the authenticated local API and return a validated response payload.

    The returned error messages deliberately avoid including the API key, request
    headers, or raw backend body.
    """
    try:
        response = requests.post(
            API_URL,
            json={"question": question, "mode": "offline", "top_k": 3},
            headers={"X-API-Key": api_key},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.Timeout:
        return None, "The local SentinelRAG API timed out. Check that it is running."
    except requests.RequestException:
        return None, (
            "The local SentinelRAG API is unavailable. Start it with "
            "`uvicorn app.main:app --reload` and try again."
        )

    if response.status_code != 200:
        if response.status_code == 401:
            return None, "The local API did not accept its configured API key. Check `.env` and restart both local processes."
        if response.status_code == 403:
            return None, "The request was blocked by the SentinelRAG input security policy."
        if response.status_code == 429:
            return None, "The local API rate limit was reached. Wait a moment and try again."
        if response.status_code == 503:
            return None, "The local API is unavailable or not fully configured. Check the API terminal and `.env`."
        return None, f"The local API returned an error (HTTP {response.status_code})."

    try:
        payload = response.json()
    except ValueError:
        return None, "The local API returned an invalid response. Check the API terminal."

    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("answer"), str)
        or not payload["answer"].strip()
    ):
        return None, "The local API response did not contain a usable answer."

    citations = payload.get("citations", [])
    retrieval = payload.get("retrieval", [])
    payload["citations"] = [item for item in citations if isinstance(item, dict)] if isinstance(citations, list) else []
    payload["retrieval"] = [item for item in retrieval if isinstance(item, dict)] if isinstance(retrieval, list) else []
    payload["refusal"] = bool(payload.get("refusal", False))
    return payload, None


def render_citations(citations: list[dict[str, Any]]) -> None:
    """Render citations safely even if an older API omits optional fields."""
    if not citations:
        st.caption("No citations were returned by the API.")
        return

    st.caption("Citations")
    for citation in citations:
        document = str(citation.get("document") or "Unknown document")
        section = str(citation.get("section") or "Unknown section")
        st.markdown(f"- `{document}` — {section}")


def render_assistant_message(message: dict[str, Any]) -> None:
    """Render one stored assistant message and its API diagnostics."""
    if message.get("error"):
        st.error(str(message["error"]))
        return

    answer = str(message.get("answer") or "No answer was returned by the API.")
    if message.get("refusal"):
        st.warning("Insufficient evidence: the knowledge base could not answer this reliably.")
    st.write(answer)
    render_citations(message.get("citations", []))

    diagnostics = {
        "request_id": message.get("request_id"),
        "retrieval": message.get("retrieval", []),
    }
    with st.expander("Sources and diagnostics"):
        st.json(diagnostics)


def main() -> None:
    st.set_page_config(page_title="SentinelRAG", page_icon="🛡️", layout="centered")
    st.title("SentinelRAG")
    st.caption("Local chat over a cybersecurity incident-response knowledge base.")

    if "messages" not in st.session_state:
        st.session_state.messages = []

    clear_column, _ = st.columns([1, 5])
    with clear_column:
        if st.button("Clear conversation"):
            st.session_state.messages = []
            st.rerun()

    if not st.session_state.messages:
        with st.chat_message("assistant"):
            st.write(WELCOME_MESSAGE)
            st.caption("Examples")
            for example in EXAMPLE_QUESTIONS:
                st.markdown(f"- {example}")

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            if message["role"] == "assistant":
                render_assistant_message(message)
            else:
                st.write(message["content"])

    question = st.chat_input("Ask about an incident-response runbook")
    if not question or not question.strip():
        return

    question = question.strip()
    st.session_state.messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.write(question)

    with st.chat_message("assistant"):
        try:
            settings = Settings.from_env()
        except ValueError:
            message = {
                "role": "assistant",
                "error": "Local configuration is invalid. Check the SentinelRAG `.env` file and restart the app.",
            }
        else:
            if not api_key_is_configured(settings.api_key):
                message = {
                    "role": "assistant",
                    "error": "Configure a non-placeholder `SENTINELRAG_API_KEY` in the project `.env` file, then restart the API and chat UI.",
                }
            else:
                with st.spinner("Retrieving runbook evidence…"):
                    payload, error = ask_backend(question, settings.api_key)
                message = {"role": "assistant", "error": error} if error else {"role": "assistant", **payload}

        render_assistant_message(message)
        st.session_state.messages.append(message)


if __name__ == "__main__":
    main()
