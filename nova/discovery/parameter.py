
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)


class ParameterDiscovery:
    """
    NOVA GET Parameter Discovery.

    Workflow:

        Target
          |
          v
        Baseline
          |
          v
        Add candidate parameter
          |
          v
        Request
          |
          v
        Compare with baseline
          |
          v
        Finding

    Example:

        Target:
            https://example.com/search

        Candidate:
            q

        Generated request:
            https://example.com/search?q=nova

    Existing query parameters are preserved.
    """

    DEFAULT_VALUE = "nova"

    def __init__(
        self,
        requester,
        engine,
        wordlist,
    ):
        self.requester = requester
        self.engine = engine

        self.wordlist = self._clean_wordlist(
            wordlist
        )

    # =========================================================
    # WORDLIST
    # =========================================================

    @staticmethod
    def _clean_wordlist(wordlist):
        """
        Clean parameter candidates.

        Removes:
        - empty lines
        - comments
        - duplicate parameters
        """

        cleaned = []
        seen = set()

        for word in wordlist or []:

            parameter = str(word).strip()

            if not parameter:
                continue

            if parameter.startswith("#"):
                continue

            parameter = parameter.strip()

            key = parameter.lower()

            if key in seen:
                continue

            seen.add(key)
            cleaned.append(parameter)

        return cleaned

    # =========================================================
    # URL BUILDER
    # =========================================================

    @staticmethod
    def _build_url(
        target: str,
        parameter: str,
        value: str,
    ) -> str:
        """
        Add a candidate parameter to the URL.

        Existing parameters remain untouched.

        Example:

            /search?lang=en

        becomes:

            /search?lang=en&q=nova
        """

        if not target:
            return target

        if not parameter:
            return target

        parsed = urlsplit(target)

        params = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        # Do not duplicate an already existing parameter.
        parameter_exists = any(
            key == parameter
            for key, _ in params
        )

        if not parameter_exists:

            params.append(
                (
                    parameter,
                    str(value),
                )
            )

        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode(
                    params,
                    doseq=True,
                ),
                "",
            )
        )

    # =========================================================
    # PARAMETER ALREADY PRESENT
    # =========================================================

    @staticmethod
    def _parameter_exists(
        target: str,
        parameter: str,
    ) -> bool:

        parsed = urlsplit(target)

        params = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        return any(
            key == parameter
            for key, _ in params
        )

    # =========================================================
    # TEST PARAMETER
    # =========================================================

    def test_parameter(
        self,
        target: str,
        parameter: str,
        value: str = DEFAULT_VALUE,
    ):
        """
        Test one GET parameter.

        Returns:
            Finding | None
        """

        if not target:
            return None

        if not parameter:
            return None

        # Existing parameters should not be tested here.
        # They belong to a separate mutation/fuzzing flow.
        if self._parameter_exists(
            target,
            parameter,
        ):
            return None

        url = self._build_url(
            target=target,
            parameter=parameter,
            value=value,
        )

        response = self.requester.get(
            url
        )

        if response is None:
            return None

        if getattr(
            response,
            "error",
            None,
        ):
            return None

        return self.engine.analyze(
            response=response,
            value=parameter,
            finding_type="parameter",
        )

    # =========================================================
    # SCAN
    # =========================================================

    def scan(
        self,
        target: str,
        value: str = DEFAULT_VALUE,
    ):
        """
        Discover interesting GET parameters.

        The engine handles:
        - response similarity
        - content length difference
        - word difference
        - line difference
        - status changes
        - confidence
        """

        findings = []

        if not target:
            return findings

        tested = set()

        for parameter in self.wordlist:

            normalized = parameter.lower()

            if normalized in tested:
                continue

            tested.add(normalized)

            result = self.test_parameter(
                target=target,
                parameter=parameter,
                value=value,
            )

            if result is not None:
                findings.append(
                    result
                )

        return findings
