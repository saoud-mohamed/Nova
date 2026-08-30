import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class CommandAnalysis:
    detected: bool = False
    score: int = 0
    confidence: str = "low"
    evidence: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


class CommandAnalyzer:
    """
    Command Injection response analyzer.

    Detects evidence commonly associated with command execution
    in an HTTP response. It does not execute commands itself.
    """

    # --------------------------------------------------
    # Command execution error signatures
    # --------------------------------------------------

    ERROR_PATTERNS = [
        re.compile(
            r"(?:sh|bash|dash):\s*\d+:\s*.+?:\s*not found",
            re.IGNORECASE,
        ),
        re.compile(
            r"sh:\s*.+?:\s*command not found",
            re.IGNORECASE,
        ),
        re.compile(
            r"bash:\s*.+?:\s*command not found",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:cmd\.exe|cmd):.*not recognized",
            re.IGNORECASE,
        ),
        re.compile(
            r"is not recognized as an internal or external command",
            re.IGNORECASE,
        ),
        re.compile(
            r"cannot find the path specified",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?:system|exec|shell_exec|passthru)\(\).*?(?:warning|error)",
            re.IGNORECASE,
        ),
        re.compile(
            r"shell_exec\(\):.*?(?:warning|error)",
            re.IGNORECASE,
        ),
        re.compile(
            r"proc_open\(\):.*?(?:warning|error)",
            re.IGNORECASE,
        ),
        re.compile(
            r"popen\(\):.*?(?:warning|error)",
            re.IGNORECASE,
        ),
    ]

    # --------------------------------------------------
    # Windows command execution indicators
    # --------------------------------------------------

    WINDOWS_PATTERNS = [
        re.compile(
            r"Microsoft Windows \[Version",
            re.IGNORECASE,
        ),
        re.compile(
            r"Volume Serial Number is",
            re.IGNORECASE,
        ),
        re.compile(
            r"Directory of [A-Za-z]:\\",
            re.IGNORECASE,
        ),
        re.compile(
            r"Windows IP Configuration",
            re.IGNORECASE,
        ),
        re.compile(
            r"systeminfo",
            re.IGNORECASE,
        ),
    ]

    # --------------------------------------------------
    # Unix/Linux command execution indicators
    # --------------------------------------------------

    UNIX_PATTERNS = [
        re.compile(
            r"uid=\d+.*gid=\d+",
            re.IGNORECASE,
        ),
        re.compile(
            r"Linux version \d",
            re.IGNORECASE,
        ),
        re.compile(
            r"GNU/Linux",
            re.IGNORECASE,
        ),
        re.compile(
            r"root:x:\d+:\d+",
            re.IGNORECASE,
        ),
        re.compile(
            r"bin:x:\d+:\d+",
            re.IGNORECASE,
        ),
    ]

    # --------------------------------------------------
    # Generic shell error indicators
    # --------------------------------------------------

    SHELL_ERROR_PATTERNS = [
        re.compile(
            r"permission denied",
            re.IGNORECASE,
        ),
        re.compile(
            r"syntax error near unexpected token",
            re.IGNORECASE,
        ),
        re.compile(
            r"syntax error",
            re.IGNORECASE,
        ),
        re.compile(
            r"bad substitution",
            re.IGNORECASE,
        ),
        re.compile(
            r"bad command",
            re.IGNORECASE,
        ),
        re.compile(
            r"unexpected token",
            re.IGNORECASE,
        ),
    ]

    def analyze(
        self,
        response_body: str,
        payload: str = "",
    ) -> CommandAnalysis:
        """
        Analyze an HTTP response for command injection evidence.

        Parameters
        ----------
        response_body:
            HTTP response body.

        payload:
            Payload that produced the response.

        Returns
        -------
        CommandAnalysis
        """

        if not response_body:
            return CommandAnalysis()

        body = str(response_body)

        evidence = []
        reasons = []
        score = 0

        # --------------------------------------------------
        # Strong command execution errors
        # --------------------------------------------------

        for pattern in self.ERROR_PATTERNS:

            match = pattern.search(body)

            if match:

                evidence.append(
                    self._clean_evidence(
                        match.group(0)
                    )
                )

                reasons.append(
                    "Command execution error signature detected"
                )

                score += 45

        # --------------------------------------------------
        # Unix/Linux evidence
        # --------------------------------------------------

        for pattern in self.UNIX_PATTERNS:

            match = pattern.search(body)

            if match:

                evidence.append(
                    self._clean_evidence(
                        match.group(0)
                    )
                )

                reasons.append(
                    "Unix/Linux command output detected"
                )

                score += 35

        # --------------------------------------------------
        # Windows evidence
        # --------------------------------------------------

        for pattern in self.WINDOWS_PATTERNS:

            match = pattern.search(body)

            if match:

                evidence.append(
                    self._clean_evidence(
                        match.group(0)
                    )
                )

                reasons.append(
                    "Windows command output detected"
                )

                score += 35

        # --------------------------------------------------
        # Shell errors
        # --------------------------------------------------

        for pattern in self.SHELL_ERROR_PATTERNS:

            match = pattern.search(body)

            if match:

                evidence.append(
                    self._clean_evidence(
                        match.group(0)
                    )
                )

                reasons.append(
                    "Shell error signature detected"
                )

                score += 10

        # --------------------------------------------------
        # Payload reflection
        #
        # Reflection alone is NOT enough to confirm
        # command injection.
        # --------------------------------------------------

        if payload:

            try:
                reflected = payload in body
            except TypeError:
                reflected = False

            if reflected:

                reasons.append(
                    "Payload was reflected in the response"
                )

                score += 5

        # --------------------------------------------------
        # Remove duplicates
        # --------------------------------------------------

        evidence = list(
            dict.fromkeys(evidence)
        )

        reasons = list(
            dict.fromkeys(reasons)
        )

        # --------------------------------------------------
        # Cap score
        # --------------------------------------------------

        score = min(score, 100)

        # --------------------------------------------------
        # Detection decision
        #
        # Reflection alone cannot trigger detection.
        # Strong evidence >= 35.
        # --------------------------------------------------

        detected = score >= 35

        # --------------------------------------------------
        # Confidence
        # --------------------------------------------------

        if score >= 75:

            confidence = "high"

        elif score >= 50:

            confidence = "medium"

        elif score >= 35:

            confidence = "low"

        else:

            confidence = "low"

        return CommandAnalysis(
            detected=detected,
            score=score,
            confidence=confidence,
            evidence=evidence,
            reasons=reasons,
        )

    # --------------------------------------------------
    # Helpers
    # --------------------------------------------------

    @staticmethod
    def _clean_evidence(
        value: str,
        max_length: int = 160,
    ) -> str:
        """
        Normalize evidence before storing it.
        """

        value = " ".join(
            value.split()
        )

        if len(value) > max_length:

            return (
                value[:max_length - 3]
                + "..."
            )

        return value