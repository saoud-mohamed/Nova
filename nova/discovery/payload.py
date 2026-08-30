from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from nova.analyzers.xss import XSSAnalyzer
from nova.analyzers.ssti import SSTIAnalyzer
from nova.analyzers.lfi import LFIAnalyzer
from nova.analyzers.sqli import SQLiAnalyzer
from nova.analyzers.command import CommandAnalyzer


class PayloadDiscovery:
    """
    Payload-based vulnerability discovery.

    Nova v6 flow:

        Target URL
              |
              v
        Replace parameter
              |
              v
          Requester
              |
              v
      Specialized Analyzer
              |
              v
          NovaEngine
              |
              v
           Finding

    Example:

        Target:
            http://127.0.0.1:8000/user?id=1

        Parameter:
            id

        Payload:
            TEST

        Generated request:
            http://127.0.0.1:8000/user?id=TEST

    The original parameter is replaced instead of creating:

        ?id=1&id=TEST
    """

    SUPPORTED_TYPES = {
        "xss",
        "sqli",
        "ssti",
        "lfi",
        "ssrf",
        "xxe",
        "command",
        "generic",
    }

    def __init__(
        self,
        requester,
        engine,
        wordlist,
    ):
        self.requester = requester
        self.engine = engine

        self.wordlist = [
            word.strip()
            for word in wordlist
            if word
            and word.strip()
            and not word.strip().startswith("#")
        ]

        self.xss_analyzer = XSSAnalyzer()
        self.sqli_analyzer = SQLiAnalyzer()
        self.ssti_analyzer = SSTIAnalyzer()
        self.lfi_analyzer = LFIAnalyzer()
        self.command_analyzer = CommandAnalyzer()

    # ======================================================
    # BUILD PAYLOAD URL
    # ======================================================

    @staticmethod
    def _build_payload_url(
        target: str,
        parameter: str,
        payload: str,
    ) -> str:
        """
        Replace the selected query parameter value.

        Example:

            target:
                http://127.0.0.1:8000/user?id=1&foo=bar

            parameter:
                id

            payload:
                TEST

            result:
                http://127.0.0.1:8000/user?id=TEST&foo=bar

        Only the selected parameter is modified.
        """

        if not target:
            return target

        if not parameter:
            return target

        parts = urlsplit(target)

        query_pairs = parse_qsl(
            parts.query,
            keep_blank_values=True,
        )

        replaced = False

        new_query = []

        for key, value in query_pairs:

            if key == parameter and not replaced:
                new_query.append(
                    (
                        key,
                        str(payload),
                    )
                )

                replaced = True

            else:
                new_query.append(
                    (
                        key,
                        value,
                    )
                )

        # --------------------------------------------------
        # Parameter was not present in the URL
        # --------------------------------------------------

        if not replaced:
            new_query.append(
                (
                    parameter,
                    str(payload),
                )
            )

        encoded_query = urlencode(
            new_query,
            doseq=True,
        )

        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                encoded_query,
                parts.fragment,
            )
        )

    # ======================================================
    # TEST PAYLOAD
    # ======================================================

    def test_payload(
        self,
        target: str,
        payload: str,
        parameter: str,
        payload_type: str = "generic",
    ):
        payload_type = str(
            payload_type
        ).strip().lower()

        if payload_type not in self.SUPPORTED_TYPES:
            raise ValueError(
                f"Unsupported payload type: {payload_type}"
            )

        # --------------------------------------------------
        # BUILD REQUEST URL
        # --------------------------------------------------

        payload_url = self._build_payload_url(
            target=target,
            parameter=parameter,
            payload=payload,
        )

        # --------------------------------------------------
        # REQUEST
        # --------------------------------------------------

        response = self.requester.get(
            payload_url,
        )

        if response is None:
            return None

        if getattr(
            response,
            "error",
            False,
        ):
            return None

        finding_type = (
            f"payload:{payload_type}"
        )

        # ==================================================
        # GENERIC
        # ==================================================

        if payload_type == "generic":

            return self.engine.analyze(
                response=response,
                value=payload,
                finding_type=finding_type,
            )

        # ==================================================
        # XSS
        # ==================================================

        if payload_type == "xss":

            analysis = self.xss_analyzer.analyze(
                response_body=getattr(
                    response,
                    "body",
                    "",
                ),
                payload=payload,
            )

            finding = self.engine.analyze(
                response=response,
                value=payload,
                finding_type=finding_type,
            )

            if (
                finding is None
                and analysis.detected
            ):
                finding = self._build_evidence_finding(
                    response=response,
                    payload=payload,
                    payload_type="xss",
                    analysis=analysis,
                )

            if finding is None:
                return None

            if analysis.detected:

                self._apply_analysis(
                    finding,
                    analysis,
                    prefix="xss",
                )

            return finding

        # ==================================================
        # SQL INJECTION
        # ==================================================

        if payload_type == "sqli":

            analysis = self.sqli_analyzer.analyze(
                response_body=getattr(
                    response,
                    "body",
                    "",
                ),
                payload=payload,
            )

            finding = self.engine.analyze(
                response=response,
                value=payload,
                finding_type=finding_type,
            )

            if (
                finding is None
                and analysis.detected
            ):
                finding = self._build_evidence_finding(
                    response=response,
                    payload=payload,
                    payload_type="sqli",
                    analysis=analysis,
                )

            if finding is None:
                return None

            if analysis.detected:

                self._apply_analysis(
                    finding,
                    analysis,
                    prefix="sqli",
                )

            return finding

        # ==================================================
        # SSTI
        # ==================================================

        if payload_type == "ssti":

            analysis = self.ssti_analyzer.analyze(
                response_body=getattr(
                    response,
                    "body",
                    "",
                ),
                payload=payload,
            )

            finding = self.engine.analyze(
                response=response,
                value=payload,
                finding_type=finding_type,
            )

            if (
                finding is None
                and analysis.detected
            ):
                finding = self._build_evidence_finding(
                    response=response,
                    payload=payload,
                    payload_type="ssti",
                    analysis=analysis,
                )

            if finding is None:
                return None

            if analysis.detected:

                metadata = {
                    "ssti_engine": getattr(
                        analysis,
                        "engine",
                        None,
                    ),
                    "ssti_score": getattr(
                        analysis,
                        "score",
                        0.0,
                    ),
                    "ssti_confidence": getattr(
                        analysis,
                        "confidence",
                        "LOW",
                    ),
                    "ssti_evidence": getattr(
                        analysis,
                        "evidence",
                        "",
                    ),
                    "ssti_reasons": getattr(
                        analysis,
                        "reasons",
                        [],
                    ),
                }

                self._attach_metadata(
                    finding,
                    metadata,
                )

                self._set_finding_field(
                    finding,
                    "score",
                    self._safe_float(
                        getattr(
                            analysis,
                            "score",
                            0.0,
                        )
                    ),
                )

                self._set_finding_field(
                    finding,
                    "confidence",
                    self._normalize_confidence(
                        getattr(
                            analysis,
                            "confidence",
                            "LOW",
                        )
                    ),
                )

            return finding

        # ==================================================
        # LFI
        # ==================================================

        if payload_type == "lfi":

            analysis = self.lfi_analyzer.analyze(
                response_body=getattr(
                    response,
                    "body",
                    "",
                ),
                payload=payload,
            )

            finding = self.engine.analyze(
                response=response,
                value=payload,
                finding_type=finding_type,
            )

            if (
                finding is None
                and analysis.detected
            ):
                finding = self._build_evidence_finding(
                    response=response,
                    payload=payload,
                    payload_type="lfi",
                    analysis=analysis,
                )

            if finding is None:
                return None

            if analysis.detected:

                self._apply_analysis(
                    finding,
                    analysis,
                    prefix="lfi",
                )

            return finding

        # ==================================================
        # COMMAND INJECTION
        # ==================================================

        if payload_type == "command":

            analysis = self.command_analyzer.analyze(
                response_body=getattr(
                    response,
                    "body",
                    "",
                ),
                payload=payload,
            )

            finding = self.engine.analyze(
                response=response,
                value=payload,
                finding_type=finding_type,
            )

            if (
                finding is None
                and analysis.detected
            ):

                evidence = self._first_evidence(
                    getattr(
                        analysis,
                        "evidence",
                        None,
                    )
                )

                if evidence:

                    finding = self._build_evidence_finding(
                        response=response,
                        payload=payload,
                        payload_type="command",
                        analysis=analysis,
                        evidence=evidence,
                    )

            if finding is None:
                return None

            if analysis.detected:

                self._attach_metadata(
                    finding,
                    {
                        "command_score": getattr(
                            analysis,
                            "score",
                            0.0,
                        ),
                        "command_confidence": getattr(
                            analysis,
                            "confidence",
                            "LOW",
                        ),
                        "command_evidence": getattr(
                            analysis,
                            "evidence",
                            None,
                        ),
                        "command_reasons": getattr(
                            analysis,
                            "reasons",
                            [],
                        ),
                    },
                )

                self._set_finding_field(
                    finding,
                    "score",
                    self._safe_float(
                        getattr(
                            analysis,
                            "score",
                            0.0,
                        )
                    ),
                )

                self._set_finding_field(
                    finding,
                    "confidence",
                    self._normalize_confidence(
                        getattr(
                            analysis,
                            "confidence",
                            "LOW",
                        )
                    ),
                )

            return finding

        # ==================================================
        # SSRF / XXE
        # ==================================================

        if payload_type in {
            "ssrf",
            "xxe",
        }:

            return self.engine.analyze(
                response=response,
                value=payload,
                finding_type=finding_type,
            )

        # ==================================================
        # FALLBACK
        # ==================================================

        return self.engine.analyze(
            response=response,
            value=payload,
            finding_type=finding_type,
        )

    # ======================================================
    # SCAN
    # ======================================================

    def scan(
        self,
        target: str,
        parameter: str,
        payload_type: str = "generic",
    ):
        payload_type = str(
            payload_type
        ).strip().lower()

        if payload_type not in self.SUPPORTED_TYPES:
            raise ValueError(
                f"Unsupported payload type: {payload_type}"
            )

        findings = []

        for payload in self.wordlist:

            result = self.test_payload(
                target=target,
                payload=payload,
                parameter=parameter,
                payload_type=payload_type,
            )

            if result is not None:
                findings.append(result)

        return findings

    # ======================================================
    # BUILD EVIDENCE FINDING
    # ======================================================

    def _build_evidence_finding(
        self,
        response,
        payload,
        payload_type,
        analysis,
        evidence=None,
    ):
        if evidence is None:

            evidence = self._first_evidence(
                getattr(
                    analysis,
                    "evidence",
                    None,
                )
            )

        # --------------------------------------------------
        # ENGINE EVIDENCE API
        # --------------------------------------------------

        analyze_evidence = getattr(
            self.engine,
            "analyze_evidence",
            None,
        )

        if (
            callable(analyze_evidence)
            and evidence
        ):

            finding = analyze_evidence(
                response=response,
                value=payload,
                finding_type=(
                    f"payload:{payload_type}"
                ),
                evidence=evidence,
            )

            if finding is not None:
                return finding

        # --------------------------------------------------
        # NORMAL ENGINE
        # --------------------------------------------------

        finding = self.engine.analyze(
            response=response,
            value=payload,
            finding_type=(
                f"payload:{payload_type}"
            ),
        )

        if finding is not None:
            return finding

        # --------------------------------------------------
        # LIGHTWEIGHT FALLBACK
        # --------------------------------------------------

        try:

            from nova.core.results import Finding

        except ImportError:

            return None

        score = self._safe_float(
            getattr(
                analysis,
                "score",
                0.0,
            )
        )

        confidence = (
            self._normalize_confidence(
                getattr(
                    analysis,
                    "confidence",
                    "LOW",
                )
            )
        )

        reasons = list(
            getattr(
                analysis,
                "reasons",
                [],
            )
            or []
        )

        if evidence:

            reasons.append(
                f"evidence:{evidence}"
            )

        try:

            return Finding(
                type=f"payload:{payload_type}",
                value=payload,
                url=getattr(
                    response,
                    "url",
                    "",
                ),
                status=getattr(
                    response,
                    "status",
                    0,
                ),
                score=score,
                confidence=confidence,
                similarity=None,
                reasons=reasons,
                metadata={
                    "evidence": evidence,
                    "length": getattr(
                        response,
                        "content_length",
                        0,
                    ),
                    "words": getattr(
                        response,
                        "words",
                        0,
                    ),
                    "lines": getattr(
                        response,
                        "lines",
                        0,
                    ),
                    "elapsed_ms": getattr(
                        response,
                        "elapsed_ms",
                        0,
                    ),
                },
            )

        except (
            TypeError,
            AttributeError,
        ):

            return None

    # ======================================================
    # APPLY ANALYSIS
    # ======================================================

    def _apply_analysis(
        self,
        finding,
        analysis,
        prefix,
    ):
        metadata = {
            f"{prefix}_score": getattr(
                analysis,
                "score",
                0.0,
            ),
            f"{prefix}_confidence": getattr(
                analysis,
                "confidence",
                "LOW",
            ),
            f"{prefix}_evidence": getattr(
                analysis,
                "evidence",
                "",
            ),
            f"{prefix}_reasons": getattr(
                analysis,
                "reasons",
                [],
            ),
        }

        if prefix == "xss":

            metadata[
                "xss_context"
            ] = getattr(
                analysis,
                "context",
                None,
            )

        self._attach_metadata(
            finding,
            metadata,
        )

        self._set_finding_field(
            finding,
            "score",
            self._safe_float(
                getattr(
                    analysis,
                    "score",
                    0.0,
                )
            ),
        )

        self._set_finding_field(
            finding,
            "confidence",
            self._normalize_confidence(
                getattr(
                    analysis,
                    "confidence",
                    "LOW",
                )
            ),
        )

    # ======================================================
    # FIRST EVIDENCE
    # ======================================================

    @staticmethod
    def _first_evidence(
        evidence,
    ):
        if not evidence:
            return None

        if isinstance(
            evidence,
            (list, tuple),
        ):

            return (
                evidence[0]
                if evidence
                else None
            )

        return evidence

    # ======================================================
    # SAFE FLOAT
    # ======================================================

    @staticmethod
    def _safe_float(
        value,
    ):
        try:
            return float(value)
        except (
            TypeError,
            ValueError,
        ):
            return 0.0

    # ======================================================
    # NORMALIZE CONFIDENCE
    # ======================================================

    @staticmethod
    def _normalize_confidence(
        confidence,
    ):
        if confidence is None:
            return "LOW"

        value = str(
            confidence
        ).strip().upper()

        if value == "HIGH":
            return "HIGH"

        if value == "MEDIUM":
            return "MEDIUM"

        return "LOW"

    # ======================================================
    # SET FINDING FIELD
    # ======================================================

    @staticmethod
    def _set_finding_field(
        finding,
        field,
        value,
    ):
        if finding is None:
            return

        if isinstance(
            finding,
            dict,
        ):

            finding[field] = value
            return

        try:

            setattr(
                finding,
                field,
                value,
            )

        except (
            AttributeError,
            TypeError,
        ):

            pass

    # ======================================================
    # ATTACH METADATA
    # ======================================================

    @staticmethod
    def _attach_metadata(
        finding,
        metadata,
    ):
        if finding is None:
            return

        if isinstance(
            finding,
            dict,
        ):

            current = finding.get(
                "metadata",
                {},
            )

            if not isinstance(
                current,
                dict,
            ):
                current = {}

            current.update(
                metadata
            )

            finding["metadata"] = current
            return

        try:

            current = getattr(
                finding,
                "metadata",
                None,
            )

            if not isinstance(
                current,
                dict,
            ):
                current = {}

            current.update(
                metadata
            )

            setattr(
                finding,
                "metadata",
                current,
            )

        except (
            AttributeError,
            TypeError,
        ):

            pass