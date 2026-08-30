class SSTIAnalysis:
    def __init__(
        self,
        detected=False,
        confidence="LOW",
        score=0.0,
        evidence="",
        reasons=None,
        engine="unknown",
    ):
        self.detected = detected
        self.confidence = confidence
        self.score = score
        self.evidence = evidence
        self.reasons = reasons or []
        self.engine = engine


class SSTIAnalyzer:

    ENGINE_MARKERS = {
        "jinja2": (
            "jinja2",
            "jinja",
        ),
        "twig": (
            "twig",
        ),
        "freemarker": (
            "freemarker",
        ),
        "velocity": (
            "velocity",
        ),
        "mako": (
            "mako",
        ),
        "handlebars": (
            "handlebars",
        ),
    }

    ERROR_MARKERS = (
        "template syntax error",
        "template error",
        "jinja2.exceptions",
        "jinja2 template",
        "twig error",
        "twig\\error",
        "freemarker.core",
        "velocityexception",
        "mako.exceptions",
        "templateexception",
    )

    def analyze(
        self,
        response_body: str,
        payload: str = "",
    ):
        body = response_body or ""
        body_lower = body.lower()

        reasons = []

        # Template engine errors
        for marker in self.ERROR_MARKERS:

            if marker.lower() in body_lower:

                engine = self._detect_engine(
                    body_lower,
                    marker,
                )

                reasons.append(
                    "Template engine error signature detected"
                )

                reasons.append(
                    f"Matched marker: {marker}"
                )

                return SSTIAnalysis(
                    detected=True,
                    confidence="HIGH",
                    score=90.0,
                    evidence=marker,
                    reasons=reasons,
                    engine=engine,
                )

        # Possible evaluated expression
        evaluation_markers = (
            "49",
            "42",
            "1337",
            "123456789",
        )

        if payload:

            for marker in evaluation_markers:

                if (
                    marker in body
                    and marker not in payload
                ):

                    reasons.append(
                        "Possible server-side template evaluation"
                    )

                    return SSTIAnalysis(
                        detected=True,
                        confidence="MEDIUM",
                        score=70.0,
                        evidence=marker,
                        reasons=reasons,
                        engine="unknown",
                    )

        return SSTIAnalysis(
            detected=False,
            confidence="LOW",
            score=0.0,
            evidence="",
            reasons=[
                "No SSTI evidence detected",
            ],
            engine="unknown",
        )

    def _detect_engine(
        self,
        body,
        marker,
    ):

        marker_lower = marker.lower()

        for engine, markers in self.ENGINE_MARKERS.items():

            if any(
                item.lower() in marker_lower
                or item.lower() in body
                for item in markers
            ):
                return engine

        return "unknown"