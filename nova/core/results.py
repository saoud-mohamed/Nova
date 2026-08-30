
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """
    Represents one NOVA security finding.
    """

    type: str

    value: str

    url: str

    status: int | None = None

    score: float = 0.0

    confidence: str = "LOW"

    similarity: float | None = None

    reasons: list[str] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


class ResultEngine:
    """
    Stores, deduplicates and manages NOVA findings.
    """

    def __init__(self):
        self.results: list[Finding] = []

    # --------------------------------------------------
    # Internal helpers
    # --------------------------------------------------

    @staticmethod
    def _normalize(value: str | None) -> str:
        """
        Normalize a string for comparison.
        """

        if value is None:
            return ""

        return " ".join(
            value.strip().lower().split()
        )

    @classmethod
    def _fingerprint(
        cls,
        finding: Finding,
    ) -> tuple:
        """
        Generate a stable fingerprint.

        Two findings with the same:
            type
            URL
            payload/value

        are considered duplicates.
        """

        return (
            cls._normalize(finding.type),
            cls._normalize(finding.url),
            cls._normalize(finding.value),
        )

    # --------------------------------------------------
    # Add finding
    # --------------------------------------------------

    def add(
        self,
        finding: Finding,
    ) -> bool:
        """
        Add a finding if it does not already exist.

        Returns:
            True  -> added
            False -> duplicate
        """

        if finding is None:
            return False

        fingerprint = self._fingerprint(
            finding
        )

        for existing in self.results:

            if self._fingerprint(
                existing
            ) != fingerprint:
                continue

            # ------------------------------------------------
            # Same finding detected again.
            #
            # Keep the stronger result.
            # ------------------------------------------------

            if finding.score > existing.score:
                existing.score = finding.score

            if (
                self._confidence_rank(
                    finding.confidence
                )
                > self._confidence_rank(
                    existing.confidence
                )
            ):
                existing.confidence = (
                    finding.confidence
                )

            if finding.similarity is not None:
                existing.similarity = (
                    finding.similarity
                )

            # Merge reasons.
            for reason in finding.reasons:

                if reason not in existing.reasons:
                    existing.reasons.append(
                        reason
                    )

            # Merge metadata.
            existing.metadata.update(
                finding.metadata
            )

            return False

        self.results.append(
            finding
        )

        return True

    # --------------------------------------------------
    # Confidence ranking
    # --------------------------------------------------

    @staticmethod
    def _confidence_rank(
        confidence: str,
    ) -> int:
        """
        HIGH > MEDIUM > LOW
        """

        ranks = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
        }

        return ranks.get(
            confidence.upper(),
            0,
        )

    # --------------------------------------------------
    # Sort by score
    # --------------------------------------------------

    def sort(self):

        self.results.sort(
            key=lambda item: (
                item.score,
                self._confidence_rank(
                    item.confidence
                ),
            ),
            reverse=True,
        )

        return self.results

    # --------------------------------------------------
    # Count all findings
    # --------------------------------------------------

    def count(self):

        return len(
            self.results
        )

    # --------------------------------------------------
    # High confidence
    # --------------------------------------------------

    def high_confidence(self):

        return [
            item
            for item in self.results
            if item.confidence.upper()
            == "HIGH"
        ]

    # --------------------------------------------------
    # Medium confidence
    # --------------------------------------------------

    def medium_confidence(self):

        return [
            item
            for item in self.results
            if item.confidence.upper()
            == "MEDIUM"
        ]

    # --------------------------------------------------
    # Low confidence
    # --------------------------------------------------

    def low_confidence(self):

        return [
            item
            for item in self.results
            if item.confidence.upper()
            == "LOW"
        ]

    # --------------------------------------------------
    # Findings by type
    # --------------------------------------------------

    def by_type(
        self,
        finding_type: str,
    ):

        normalized = self._normalize(
            finding_type
        )

        return [
            item
            for item in self.results
            if self._normalize(
                item.type
            ) == normalized
        ]

    # --------------------------------------------------
    # Findings by URL
    # --------------------------------------------------

    def by_url(
        self,
        url: str,
    ):

        normalized = self._normalize(
            url
        )

        return [
            item
            for item in self.results
            if self._normalize(
                item.url
            ) == normalized
        ]

    # --------------------------------------------------
    # Findings above score
    # --------------------------------------------------

    def above_score(
        self,
        minimum: float,
    ):

        return [
            item
            for item in self.results
            if item.score >= minimum
        ]

    # --------------------------------------------------
    # Confirmed / high findings
    # --------------------------------------------------

    def confirmed(self):

        return [
            item
            for item in self.results
            if item.confidence.upper()
            == "HIGH"
        ]

    # --------------------------------------------------
    # Top findings
    # --------------------------------------------------

    def top(
        self,
        limit: int = 10,
    ):

        if limit <= 0:
            return []

        return self.sort()[:limit]

    # --------------------------------------------------
    # Clear results
    # --------------------------------------------------

    def clear(self):

        self.results.clear()

    # --------------------------------------------------
    # Get all results
    # --------------------------------------------------

    def all(self):

        return list(
            self.results
        )

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    def summary(self):

        return {
            "total": self.count(),
            "high": len(
                self.high_confidence()
            ),
            "medium": len(
                self.medium_confidence()
            ),
            "low": len(
                self.low_confidence()
            ),
        }

    # --------------------------------------------------
    # Type statistics
    # --------------------------------------------------

    def type_summary(self):

        summary: dict[str, int] = {}

        for finding in self.results:

            finding_type = finding.type

            summary[finding_type] = (
                summary.get(
                    finding_type,
                    0,
                )
                + 1
            )

        return summary

    # --------------------------------------------------
    # Export-friendly format
    # --------------------------------------------------

    def to_dicts(self):

        return [
            {
                "type": item.type,
                "value": item.value,
                "url": item.url,
                "status": item.status,
                "score": item.score,
                "confidence": item.confidence,
                "similarity": item.similarity,
                "reasons": list(
                    item.reasons
                ),
                "metadata": dict(
                    item.metadata
                ),
            }
            for item in self.results
        ]

