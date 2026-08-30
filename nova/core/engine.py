
from .baseline import Baseline
from .fingerprint import Fingerprint
from .similarity import Similarity
from .results import Finding, ResultEngine


class NovaEngine:
    """
    Main NOVA response-analysis engine.

    Responsibilities:
    - Establish target baseline
    - Compare fuzzing responses against baseline
    - Calculate response differences
    - Analyze response metadata
    - Reduce obvious false positives
    - Create normalized findings

    NOTE:
    This engine performs generic response analysis.
    Specialized vulnerability detection such as SQLi
    should be implemented separately.
    """

    def __init__(
        self,
        requester,
        target,
    ):
        self.requester = requester
        self.target = target

        self.baseline = Baseline(
            requester,
            target,
        )

        self.fingerprint = Fingerprint()
        self.similarity = Similarity()
        self.results = ResultEngine()

    # =========================================================
    # BASELINE
    # =========================================================

    def calibrate(self):
        """
        Establish the target baseline response.
        """

        return self.baseline.calibrate()

    # =========================================================
    # SAFE HELPERS
    # =========================================================

    @staticmethod
    def _safe_length(response):
        if response is None:
            return 0

        return getattr(
            response,
            "content_length",
            0,
        ) or len(
            getattr(
                response,
                "body",
                "",
            ) or ""
        )

    @staticmethod
    def _safe_words(response):
        if response is None:
            return 0

        return getattr(
            response,
            "words",
            0,
        ) or 0

    @staticmethod
    def _safe_lines(response):
        if response is None:
            return 0

        return getattr(
            response,
            "lines",
            0,
        ) or 0

    @staticmethod
    def _safe_elapsed(response):
        if response is None:
            return 0.0

        return getattr(
            response,
            "elapsed_ms",
            0.0,
        ) or 0.0

    # =========================================================
    # RESPONSE METRICS
    # =========================================================

    def _response_metrics(self, response):
        """
        Extract normalized response metrics.
        """

        return {
            "length": self._safe_length(
                response
            ),

            "words": self._safe_words(
                response
            ),

            "lines": self._safe_lines(
                response
            ),

            "elapsed_ms": self._safe_elapsed(
                response
            ),
        }

    def _baseline_metrics(self):
        """
        Extract metrics from Baseline.response.

        Baseline stores the actual ResponseData object
        in self.baseline.response.
        """

        response = getattr(
            self.baseline,
            "response",
            None,
        )

        return self._response_metrics(
            response
        )

    # =========================================================
    # DIFFERENCE
    # =========================================================

    @staticmethod
    def _relative_difference(
        current,
        baseline,
    ):
        """
        Calculate relative difference safely.

        Example:

            baseline = 1000
            current = 1200

            result = 0.20
        """

        if baseline <= 0:

            if current > 0:
                return 1.0

            return 0.0

        return abs(
            current - baseline
        ) / baseline

    # =========================================================
    # STATUS
    # =========================================================

    def _status_changed(
        self,
        response,
    ):
        """
        Check whether response status differs
        from the calibrated baseline.
        """

        baseline_status = getattr(
            self.baseline,
            "status",
            None,
        )

        response_status = getattr(
            response,
            "status",
            None,
        )

        if baseline_status is None:
            return False

        return (
            response_status
            != baseline_status
        )

    # =========================================================
    # GENERIC ANALYSIS
    # =========================================================

    def analyze(
        self,
        response,
        value,
        finding_type,
    ):
        """
        Compare a response against the baseline.

        Important:
        A status change alone does NOT indicate a
        vulnerability.
        """

        if response is None:
            return None

        if getattr(
            response,
            "error",
            None,
        ):
            return None

        # -----------------------------------------------------
        # Baseline validation
        # -----------------------------------------------------

        baseline_response = getattr(
            self.baseline,
            "response",
            None,
        )

        if baseline_response is None:
            return None

        # -----------------------------------------------------
        # Bodies
        # -----------------------------------------------------

        baseline_body = (
            getattr(
                baseline_response,
                "body",
                "",
            )
            or ""
        )

        response_body = (
            getattr(
                response,
                "body",
                "",
            )
            or ""
        )

        # -----------------------------------------------------
        # Similarity
        # -----------------------------------------------------

        similarity = self.similarity.score(
            baseline_body,
            response_body,
        )

        similarity = max(
            0.0,
            min(
                1.0,
                similarity,
            ),
        )

        difference = max(
            0.0,
            min(
                1.0,
                1.0 - similarity,
            ),
        )

        # -----------------------------------------------------
        # Metrics
        # -----------------------------------------------------

        current = self._response_metrics(
            response
        )

        baseline = self._baseline_metrics()

        length_diff = (
            self._relative_difference(
                current["length"],
                baseline["length"],
            )
        )

        words_diff = (
            self._relative_difference(
                current["words"],
                baseline["words"],
            )
        )

        lines_diff = (
            self._relative_difference(
                current["lines"],
                baseline["lines"],
            )
        )

        # -----------------------------------------------------
        # Status
        # -----------------------------------------------------

        baseline_status = getattr(
            baseline_response,
            "status",
            None,
        )

        response_status = getattr(
            response,
            "status",
            None,
        )

        status_changed = (
            baseline_status is not None
            and response_status
            != baseline_status
        )

        # -----------------------------------------------------
        # Reasons
        # -----------------------------------------------------

        reasons = []

        if status_changed:
            reasons.append(
                "status_changed"
            )

        if difference >= 0.10:
            reasons.append(
                "response_changed"
            )

        if length_diff >= 0.20:
            reasons.append(
                "content_length_changed"
            )

        if words_diff >= 0.20:
            reasons.append(
                "word_count_changed"
            )

        if lines_diff >= 0.20:
            reasons.append(
                "line_count_changed"
            )

        if getattr(
            response,
            "is_redirect",
            False,
        ):
            reasons.append(
                "redirect"
            )

        # -----------------------------------------------------
        # False Positive Protection
        # -----------------------------------------------------

        # Status-only difference is weak evidence.
        only_status_change = (
            status_changed
            and difference < 0.05
            and length_diff < 0.10
            and words_diff < 0.10
            and lines_diff < 0.10
        )

        if only_status_change:
            return None

        # Ignore extremely small differences.
        tiny_difference = (
            difference < 0.05
            and length_diff < 0.10
            and words_diff < 0.10
            and lines_diff < 0.10
        )

        if tiny_difference:
            return None

        if not reasons:
            return None

        # -----------------------------------------------------
        # Score
        # -----------------------------------------------------

        score = 0.0

        # Response similarity is the strongest signal.
        score += (
            difference * 65.0
        )

        # Content length.
        score += min(
            length_diff * 15.0,
            15.0,
        )

        # Word count.
        score += min(
            words_diff * 10.0,
            10.0,
        )

        # Line count.
        score += min(
            lines_diff * 10.0,
            10.0,
        )

        # Status change provides additional context,
        # but should not dominate the score.
        if status_changed:
            score += 5.0

        score = round(
            min(
                score,
                89.0,
            ),
            2,
        )

        # -----------------------------------------------------
        # Confidence
        # -----------------------------------------------------

        if score >= 70:
            confidence = "MEDIUM"

        elif score >= 35:
            confidence = "LOW"

        else:
            confidence = "LOW"

        # Generic analysis NEVER creates HIGH.
        #
        # HIGH is reserved for explicit evidence.
        if confidence == "HIGH":
            confidence = "MEDIUM"

        # -----------------------------------------------------
        # Finding
        # -----------------------------------------------------

        finding = Finding(
            type=finding_type,
            value=value,
            url=getattr(
                response,
                "url",
                self.target,
            ),
            status=response_status,
            score=score,
            confidence=confidence,
            similarity=round(
                similarity,
                4,
            ),
            reasons=reasons,
            metadata={
                "length": current[
                    "length"
                ],

                "words": current[
                    "words"
                ],

                "lines": current[
                    "lines"
                ],

                "elapsed_ms": current[
                    "elapsed_ms"
                ],

                "baseline_status":
                    baseline_status,

                "baseline_length":
                    baseline[
                        "length"
                    ],

                "baseline_words":
                    baseline[
                        "words"
                    ],

                "baseline_lines":
                    baseline[
                        "lines"
                    ],

                "length_difference":
                    round(
                        length_diff,
                        4,
                    ),

                "word_difference":
                    round(
                        words_diff,
                        4,
                    ),

                "line_difference":
                    round(
                        lines_diff,
                        4,
                    ),
            },
        )

        self.results.add(
            finding
        )

        return finding

    # =========================================================
    # EXPLICIT EVIDENCE
    # =========================================================

    def analyze_evidence(
        self,
        response,
        value,
        finding_type,
        evidence,
    ):
        """
        Create HIGH confidence finding only when
        explicit evidence is present in the response.

        This is intentionally separate from generic
        response-difference analysis.
        """

        if response is None:
            return None

        if getattr(
            response,
            "error",
            None,
        ):
            return None

        if not evidence:
            return None

        body = (
            getattr(
                response,
                "body",
                "",
            )
            or ""
        )

        if (
            evidence.lower()
            not in body.lower()
        ):
            return None

        metrics = self._response_metrics(
            response
        )

        finding = Finding(
            type=finding_type,
            value=value,
            url=getattr(
                response,
                "url",
                self.target,
            ),
            status=getattr(
                response,
                "status",
                None,
            ),
            score=90.0,
            confidence="HIGH",
            similarity=None,
            reasons=[
                "explicit_evidence",
            ],
            metadata={
                "evidence": evidence,

                "length": metrics[
                    "length"
                ],

                "words": metrics[
                    "words"
                ],

                "lines": metrics[
                    "lines"
                ],

                "elapsed_ms": metrics[
                    "elapsed_ms"
                ],
            },
        )

        self.results.add(
            finding
        )

        return finding

    # =========================================================
    # RESULTS
    # =========================================================

    def findings(self):
        """
        Return all findings sorted by score.
        """

        return self.results.sort()

    def summary(self):
        """
        Return result summary.
        """

        return self.results.summary()

    def clear(self):
        """
        Clear all findings.
        """

        self.results.clear()

