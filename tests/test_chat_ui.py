import chat_ui


def test_ask_backend_uses_offline_api_contract(monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "answer": "Retrieved evidence (offline mode): test evidence",
                "citations": [
                    {
                        "document": "phishing_triage.md",
                        "section": "Initial assessment",
                        "chunk_id": 14,
                    }
                ],
                "retrieval": [{"chunk_id": 14, "score": 0.2}],
                "refusal": False,
                "request_id": 42,
            }

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return FakeResponse()

    monkeypatch.setattr(chat_ui.requests, "post", fake_post)

    payload, error = chat_ui.ask_backend("How do I report phishing?", "test-ui-key")

    assert error is None
    assert captured["url"] == "http://127.0.0.1:8000/ask"
    assert captured["json"] == {
        "question": "How do I report phishing?",
        "mode": "offline",
        "top_k": 3,
    }
    assert captured["headers"] == {"X-API-Key": "test-ui-key"}
    assert captured["timeout"] == chat_ui.REQUEST_TIMEOUT_SECONDS
    assert payload is not None
    assert payload["answer"] == "Retrieved evidence (offline mode): test evidence"
    assert payload["citations"][0]["document"] == "phishing_triage.md"
    assert payload["retrieval"] == [{"chunk_id": 14, "score": 0.2}]
    assert payload["request_id"] == 42


def test_ask_backend_tolerates_missing_citations_and_retrieval_data(monkeypatch):
    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"answer": "Retrieved evidence", "citations": None, "retrieval": None}

    monkeypatch.setattr(chat_ui.requests, "post", lambda *args, **kwargs: FakeResponse())

    payload, error = chat_ui.ask_backend("Question", "test-ui-key")

    assert payload is not None
    assert payload["citations"] == []
    assert payload["retrieval"] == []
    assert error is None


def test_ask_backend_rejects_an_empty_answer(monkeypatch):
    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"answer": "   "}

    monkeypatch.setattr(chat_ui.requests, "post", lambda *args, **kwargs: FakeResponse())

    payload, error = chat_ui.ask_backend("Question", "test-ui-key")

    assert payload is None
    assert error == "The local API response did not contain a usable answer."
