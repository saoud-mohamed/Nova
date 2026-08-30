from dataclasses import dataclass


@dataclass
class PayloadResult:

    payload: str
    detected: bool
    score: float
    confidence: str
    reasons: list[str]


class PayloadEngine:

    def __init__(self, analyzer=None):

        self.analyzer = analyzer

    def analyze(
        self,
        response,
        payload: str,
    ):

        if response is None:
            return None

        if response.error:
            return None

        if self.analyzer is None:
            return None

        return self.analyzer.analyze(
            response.body,
            response.status,
            response.headers.get(
                "Content-Type",
                "",
            ),
        )

    def run(
        self,
        requester,
        target,
        payloads,
        method="GET",
    ):

        results = []

        for payload in payloads:

            if method.upper() == "POST":

                response = requester.post(
                    target,
                    data=payload,
                )

            else:

                response = requester.get(
                    target,
                )

            analysis = self.analyze(
                response,
                payload,
            )

            if analysis is None:
                continue

            if analysis.detected:

                results.append(
                    PayloadResult(
                        payload=payload,
                        detected=True,
                        score=analysis.score,
                        confidence=analysis.confidence,
                        reasons=analysis.reasons,
                    )
                )

        return results