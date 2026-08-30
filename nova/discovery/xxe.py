from dataclasses import dataclass

from nova.discovery.xxe_analyzer import XXEAnalyzer


@dataclass
class XXEProbeResult:

    probe: str
    detected: bool
    confidence: str
    score: float
    reason: str

class XXEDiscovery:

    TEST_MARKER = XXEAnalyzer.MARKER

    def __init__(
        self,
        requester,
        engine,
    ):
        self.requester = requester
        self.engine = engine
        self.analyzer = XXEAnalyzer()

    def build_internal_entity_payload(self):

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
    <!ENTITY nova "{self.TEST_MARKER}">
]>
<root>&nova;</root>
"""

    def build_payload(self):
        return self.build_internal_entity_payload()

    # -------------------------------------------------
    # XML headers
    # -------------------------------------------------

    def headers(self):

        return {
            "Content-Type": "application/xml",
            "Accept": (
                "application/xml, "
                "text/xml, "
                "*/*"
            ),
        }

    # -------------------------------------------------
    # Send XML
    # -------------------------------------------------

    def send_xml(
        self,
        target,
        payload,
    ):

        return self.requester.post(
            target,
            data=payload,
            headers=self.headers(),
        )

    # -------------------------------------------------
    # Convert analyzer result to Nova Finding
    # -------------------------------------------------

    def make_finding(
        self,
        response,
        analysis,
    ):

        if not analysis.detected:
            return None

        evidence = (
            analysis.evidence[0]
            if analysis.evidence
            else self.TEST_MARKER
        )

        finding = self.engine.analyze_evidence(
            response=response,
            value=self.TEST_MARKER,
            finding_type="xxe",
            evidence=evidence,
        )

        if finding is None:
            return None

        finding.reasons.extend(
            reason
            for reason in analysis.reasons
            if reason not in finding.reasons
        )

        finding.metadata.update({
            "probe": "internal_entity",
            "probe_score": analysis.score,
            "probe_confidence": analysis.confidence,
            "probe_evidence": analysis.evidence,
            "probe_reasons": analysis.reasons,
            "response_status": response.status,
            "response_length": response.content_length,
            "response_words": response.words,
            "response_lines": response.lines,
        })

        return finding

    # -------------------------------------------------
    # Main scan
    # -------------------------------------------------

    def scan(
        self,
        target,
    ):

        findings = []

        payload = (
            self.build_internal_entity_payload()
        )

        response = self.send_xml(
            target,
            payload,
        )

        if response is None:
            return findings

        if response.error:
            return findings

        analysis = self.analyzer.analyze(
            response_body=response.body,
            response_status=response.status,
            content_type=response.headers.get(
                "Content-Type",
                "",
            ),
        )

        if not analysis.detected:
            return findings

        finding = self.make_finding(
            response,
            analysis,
        )

        if finding is not None:
            findings.append(finding)

        return findings