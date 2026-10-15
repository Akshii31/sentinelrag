"""TF-IDF retrieval over local Markdown/text incident-response runbooks.

This retrieval score is a lexical similarity heuristic, not a measure of factual
correctness. Thresholds should be calibrated against the included demo queries.
"""

from dataclasses import dataclass
from pathlib import Path
import re

from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass(frozen=True)
class Chunk:
    chunk_id: int
    document: str
    section: str
    text: str


# Generic words common across many runbooks should not dominate retrieval.
GENERIC_STOP_WORDS = set(ENGLISH_STOP_WORDS).union({
    "policy", "company", "office", "immediate", "initial", "action",
    "actions", "response", "procedure", "procedures", "information",
    "approved", "team", "suspected", "employee", "employees",
})


class DocumentRetriever:
    """Load local runbooks into paragraph-sized chunks and retrieve by TF-IDF."""

    def __init__(self, documents_dir: Path):
        self.documents_dir = Path(documents_dir)
        self.chunks: list[Chunk] = []
        self.vectorizer: TfidfVectorizer | None = None
        self.matrix = None
        self._load_documents()

        if not self.chunks:
            raise ValueError(f"No usable .md or .txt documents found in {self.documents_dir}")

        self.vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words=sorted(GENERIC_STOP_WORDS),
            ngram_range=(1, 2),
            sublinear_tf=True,
        )
        # A user will naturally ask with a runbook title (for example, "CVE")
        # or a section label (for example, "Containment").  Those labels are
        # useful retrieval terms even though the citation should return only
        # the original source paragraph as evidence.
        self.matrix = self.vectorizer.fit_transform(
            [self._index_text(chunk) for chunk in self.chunks]
        )

    @staticmethod
    def _index_text(chunk: Chunk) -> str:
        """Combine stable document metadata with the source paragraph for search."""
        document_title = Path(chunk.document).stem.replace("_", " ")
        return f"Document: {document_title}\nSection: {chunk.section}\n{chunk.text}"

    def _load_documents(self) -> None:
        if not self.documents_dir.is_dir():
            raise FileNotFoundError(f"Runbook folder not found: {self.documents_dir}")

        next_id = 1
        for path in sorted(list(self.documents_dir.glob("*.md")) + list(self.documents_dir.glob("*.txt"))):
            text = path.read_text(encoding="utf-8-sig").strip()
            if not text:
                continue

            current_section = path.stem.replace("_", " ").title()
            paragraphs: list[tuple[str, str]] = []
            paragraph_lines: list[str] = []

            def flush_paragraph() -> None:
                nonlocal paragraph_lines
                if paragraph_lines:
                    paragraph = " ".join(line.strip() for line in paragraph_lines).strip()
                    if paragraph:
                        paragraphs.append((current_section, paragraph))
                    paragraph_lines = []

            for line in text.splitlines():
                heading = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
                if heading:
                    flush_paragraph()
                    current_section = heading.group(1).strip()
                elif not line.strip():
                    flush_paragraph()
                else:
                    paragraph_lines.append(line)
            flush_paragraph()

            for section, paragraph in paragraphs:
                # Avoid indexing very short heading-only fragments.
                if len(paragraph.split()) < 3:
                    continue
                self.chunks.append(
                    Chunk(
                        chunk_id=next_id,
                        document=path.name,
                        section=section,
                        text=paragraph,
                    )
                )
                next_id += 1

    def search(self, query: str, top_k: int = 3) -> list[dict]:
        """Return ranked passages; zero-overlap results are omitted."""
        if not isinstance(query, str) or not query.strip():
            raise ValueError("Search query cannot be empty")
        if not 1 <= top_k <= 20:
            raise ValueError("top_k must be between 1 and 20")
        assert self.vectorizer is not None and self.matrix is not None

        # Avoid high scores caused by one generic overlap (for example, the word
        # "policy" in an unrelated question). If most meaningful query terms are
        # unknown to the index, treat it as out-of-scope rather than guessing.
        query_terms = [
            token.lower() for token in re.findall(r"[A-Za-z][A-Za-z0-9_-]*", query)
            if token.lower() not in GENERIC_STOP_WORDS
        ]
        if not query_terms:
            return []
        known_terms = sum(1 for token in query_terms if token in self.vectorizer.vocabulary_)
        if known_terms / len(query_terms) < 0.5:
            return []

        query_vector = self.vectorizer.transform([query.strip()])
        scores = cosine_similarity(query_vector, self.matrix).flatten()
        ranked = scores.argsort()[::-1]
        results: list[dict] = []

        for index in ranked:
            score = float(scores[index])
            if score <= 0:
                continue
            chunk = self.chunks[int(index)]
            results.append(
                {
                    "chunk_id": chunk.chunk_id,
                    "document": chunk.document,
                    "section": chunk.section,
                    "text": chunk.text,
                    "score": round(score, 4),
                }
            )
            if len(results) >= top_k:
                break
        return results
