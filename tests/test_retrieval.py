from pathlib import Path

import pytest

from app.retrieval import DocumentRetriever


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"


@pytest.fixture(scope="module")
def retriever():
    return DocumentRetriever(DATA_DIR)


@pytest.mark.parametrize(
    ("question", "document"),
    [
        ("What should I do about a suspicious email attachment?", "phishing_triage.md"),
        ("How should we investigate a suspicious login with MFA?", "suspicious_login.md"),
        ("What evidence should we retain for endpoint malware?", "malware_response.md"),
        ("How should we review suspected SQL injection?", "sql_injection.md"),
        ("What immediate actions are appropriate for ransomware?", "ransomware_response.md"),
        ("How do we respond to a DDoS affecting service availability?", "ddos_response.md"),
        ("How should we triage and patch a critical CVE?", "critical_cve.md"),
        ("An API key leaked in a public repository; what next?", "exposed_api_key.md"),
    ],
)
def test_each_runbook_has_a_threshold_qualified_golden_query(retriever, question, document):
    results = retriever.search(question, top_k=3)
    assert results
    assert results[0]["document"] == document
    assert results[0]["score"] >= 0.10


def test_suspicious_email_query_has_one_threshold_qualified_passage(retriever):
    results = retriever.search(
        "What should an employee do after receiving a suspicious email?", top_k=3
    )

    assert results[0]["document"] == "phishing_triage.md"
    assert results[0]["score"] >= 0.10
    assert all(result["score"] < 0.10 for result in results[1:])


def test_out_of_scope_query_has_no_lexical_matches(retriever):
    assert retriever.search("What is the policy for office parking spaces?") == []


def test_blank_query_rejected(retriever):
    with pytest.raises(ValueError):
        retriever.search("   ")


def test_invalid_top_k_rejected(retriever):
    with pytest.raises(ValueError):
        retriever.search("phishing", top_k=0)
