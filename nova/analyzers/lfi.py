from dataclasses import dataclass
from typing import List


@dataclass
class LFIAnalysis:
    detected: bool
    score: int
    confidence: str
    evidence: List[str]
    reasons: List[str]


class LFIAnalyzer:
    """
    Local File Inclusion response analyzer.

    This analyzer looks for response-side indicators that can
    suggest LFI. It does not attempt to retrieve sensitive files.
    """

    HIGH_CONFIDENCE_PATTERNS = {
        "root:x:": "Unix passwd-file signature",
        "[boot loader]": "Windows boot.ini signature",
        "for 16-bit app support": "Windows boot configuration signature",
    }

    MEDIUM_CONFIDENCE_PATTERNS = {
        "failed to open stream": "PHP file/stream error",
        "include(": "PHP include error",
        "require(": "PHP require error",
        "failed opening required": "PHP require/include error",
        "no such file or directory": "File-not-found indicator",
        "include_path": "PHP include_path indicator",
        "cannot open": "File open error",
        "file_get_contents(": "PHP file_get_contents indicator",
    }

    GENERIC_PATTERNS = {
        "permission denied": "Permission error",
        "is a directory": "Directory access indicator",
        "directory listing": "Directory listing indicator",
    }

    def analyze(
        self,
        response_body: str,
        payload: str,
    ) -> LFIAnalysis:

        if not response_body:
            return LFIAnalysis(
                detected=False,
                score=0,
                confidence="low",
                evidence=[],
                reasons=[],
            )

        body = response_body.lower()

        score = 0
        evidence = []
        reasons = []

        # ==================================================
        # HIGH CONFIDENCE
        # ==================================================

        for pattern, reason in self.HIGH_CONFIDENCE_PATTERNS.items():

            if pattern.lower() in body:

                score += 70

                evidence.append(pattern)
                reasons.append(reason)

        # ==================================================
        # MEDIUM CONFIDENCE
        # ==================================================

        for pattern, reason in self.MEDIUM_CONFIDENCE_PATTERNS.items():

            if pattern.lower() in body:

                score += 25

                evidence.append(pattern)
                reasons.append(reason)

        # ==================================================
        # GENERIC INDICATORS
        # ==================================================

        for pattern, reason in self.GENERIC_PATTERNS.items():

            if pattern.lower() in body:

                score += 10

                evidence.append(pattern)
                reasons.append(reason)

        # ==================================================
        # CAP SCORE
        # ==================================================

        score = min(score, 100)

        # ==================================================
        # CONFIDENCE
        # ==================================================

        if score >= 70:

            confidence = "high"

        elif score >= 40:

            confidence = "medium"

        elif score > 0:

            confidence = "low"

        else:

            confidence = "low"

        # ==================================================
        # DETECTION
        # ==================================================

        detected = score >= 40

        return LFIAnalysis(
            detected=detected,
            score=score,
            confidence=confidence,
            evidence=evidence,
            reasons=reasons,
        )