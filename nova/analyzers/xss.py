from dataclasses import dataclass


@dataclass
class XSSAnalysis:
    detected: bool
    score: float
    confidence: str
    reasons: list[str]
    evidence: list[str]
    context: str


class XSSAnalyzer:

    def analyze(
        self,
        response_body: str,
        payload: str,
    ) -> XSSAnalysis:

        body = response_body or ""
        payload = payload or ""

        if not body or not payload:
            return XSSAnalysis(
                detected=False,
                score=0.0,
                confidence="LOW",
                reasons=[],
                evidence=[],
                context="none",
            )

        reasons = []
        evidence = []

        # ---------------------------------------------
        # Exact reflection
        # ---------------------------------------------

        if payload in body:

            evidence.append(payload)
            reasons.append("payload_reflected")

            score = 50.0

        else:

            return XSSAnalysis(
                detected=False,
                score=0.0,
                confidence="LOW",
                reasons=["payload_not_reflected"],
                evidence=[],
                context="none",
            )

        # ---------------------------------------------
        # Detect reflection context
        # ---------------------------------------------

        context = self.detect_context(
            body,
            payload,
        )

        if context != "unknown":

            reasons.append(
                f"reflection_context:{context}"
            )

            score += 20.0

        # ---------------------------------------------
        # Executable HTML indicators
        # ---------------------------------------------

        lower_payload = payload.lower()

        executable_patterns = (
            "<script",
            "<svg",
            "<img",
            "<iframe",
            "<object",
            "<embed",
            "onerror=",
            "onload=",
            "onclick=",
            "javascript:",
        )

        if any(
            pattern in lower_payload
            for pattern in executable_patterns
        ):

            reasons.append(
                "executable_xss_payload_reflected"
            )

            score += 25.0

        # ---------------------------------------------
        # Cap score
        # ---------------------------------------------

        score = min(
            score,
            100.0,
        )

        # ---------------------------------------------
        # Confidence
        # ---------------------------------------------

        if score >= 90:

            confidence = "HIGH"
            detected = True

        elif score >= 70:

            confidence = "MEDIUM"
            detected = True

        elif score >= 50:

            confidence = "LOW"
            detected = False

        else:

            confidence = "LOW"
            detected = False

        return XSSAnalysis(
            detected=detected,
            score=score,
            confidence=confidence,
            reasons=reasons,
            evidence=evidence,
            context=context,
        )

    # ---------------------------------------------
    # Context detection
    # ---------------------------------------------

    def detect_context(
        self,
        body: str,
        payload: str,
    ) -> str:

        index = body.find(payload)

        if index == -1:
            return "none"

        before = body[:index]
        after = body[index + len(payload):]

        # Inside <script>
        script_open = before.lower().rfind(
            "<script"
        )

        script_close = before.lower().rfind(
            "</script>"
        )

        if script_open > script_close:

            return "javascript"

        # Inside HTML attribute
        last_open = before.rfind("<")
        last_close = before.rfind(">")

        if last_open > last_close:

            return "html_attribute"

        # Inside HTML element text
        return "html"