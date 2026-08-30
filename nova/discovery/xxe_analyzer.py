from dataclasses import dataclass


@dataclass
class XXEAnalysis:

    detected: bool

    score: float

    confidence: str

    reasons: list[str]

    evidence: list[str]


class XXEAnalyzer:

    MARKER = "NOVA_XXE_7F31A"

    XML_ERROR_MARKERS = (
        "doctype",
        "entity",
        "dtd",
        "xml parser",
        "xmlparse",
        "saxparse",
        "expat",
        "xerces",
        "libxml",
        "xml syntax",
        "malformed xml",
    )

    def analyze(
        self,
        response_body: str,
        response_status: int | None = None,
        content_type: str = "",
    ):

        body = response_body or ""

        body_lower = body.lower()

        reasons = []

        evidence = []

        score = 0.0

        # -----------------------------------------
        # Strong evidence
        # -----------------------------------------

        if self.MARKER in body:

            score = 100.0

            reasons.append(
                "internal_entity_expansion"
            )

            evidence.append(
                self.MARKER
            )

        # -----------------------------------------
        # XML parser indicators
        # -----------------------------------------

        parser_errors = [
            marker
            for marker in self.XML_ERROR_MARKERS
            if marker in body_lower
        ]

        if parser_errors:

            reasons.append(
                "xml_parser_indicator"
            )

            evidence.extend(
                parser_errors[:5]
            )

            if score < 100:

                score = max(
                    score,
                    10.0
                )

        # -----------------------------------------
        # XML Content-Type
        # -----------------------------------------

        if content_type:

            if "xml" in content_type.lower():

                reasons.append(
                    "xml_content_type"
                )

        # -----------------------------------------
        # Confidence
        # -----------------------------------------

        if score >= 90:

            confidence = "HIGH"

            detected = True

        elif score >= 50:

            confidence = "MEDIUM"

            detected = True

        elif score > 0:

            confidence = "LOW"

            detected = False

        else:

            confidence = "LOW"

            detected = False

        return XXEAnalysis(
            detected=detected,
            score=score,
            confidence=confidence,
            reasons=reasons,
            evidence=evidence,
        )