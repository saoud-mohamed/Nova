import re


class SQLiAnalysis:
    def __init__(
        self,
        detected=False,
        confidence="LOW",
        score=0.0,
        evidence="",
        reasons=None,
    ):
        self.detected = detected
        self.confidence = confidence
        self.score = score
        self.evidence = evidence
        self.reasons = reasons or []


class SQLiAnalyzer:
    """
    SQL Injection response analyzer.

    Important:
    - HTTP 500 alone is NOT considered SQLi.
    - A real SQL/database error signature is required
      for high-confidence error-based detection.
    """

    ERROR_PATTERNS = (
        # MySQL / MariaDB
        r"you have an error in your sql syntax",
        r"mysql.*syntax",
        r"mysqli.*error",
        r"mariadb.*error",
        r"mysql server version",

        # PostgreSQL
        r"postgresql.*error",
        r"postgres.*error",
        r"psycopg\d?.*error",
        r"pg::[a-z_]+",

        # SQLite
        r"sqlite3\.operationalerror",
        r"sqlite.*error",
        r"sqlite.*syntax error",
        r"unrecognized token",
        r"unterminated string",
        r"incomplete input",
        r"near [\"'].*[\"']:\s*syntax error",

        # Oracle
        r"ora-\d{4,5}",
        r"oracle.*error",

        # SQL Server
        r"microsoft sql server",
        r"sql server.*error",
        r"odbc sql server driver",
        r"unclosed quotation mark after the character string",

        # Generic database signatures
        r"sqlstate\[[0-9a-z]+\]",
        r"database error",
        r"db error",
        r"syntax error.*sql",
        r"sql syntax error",
        r"quoted string not properly terminated",
    )

    COMPILED_PATTERNS = tuple(
        re.compile(
            pattern,
            re.IGNORECASE,
        )
        for pattern in ERROR_PATTERNS
    )

    def analyze(
        self,
        response_body: str,
        payload: str = "",
    ):
        body = response_body or ""

        if not body:
            return SQLiAnalysis(
                detected=False,
                confidence="LOW",
                score=0.0,
                evidence="",
                reasons=[
                    "Empty response body",
                ],
            )

        matches = []

        for pattern in self.COMPILED_PATTERNS:
            match = pattern.search(body)

            if match:
                matches.append(
                    match.group(0)
                )

        # Real database error detected
        if matches:
            evidence = matches[0]

            return SQLiAnalysis(
                detected=True,
                confidence="HIGH",
                score=90.0,
                evidence=evidence,
                reasons=[
                    "SQL database error signature detected",
                    f"Matched: {evidence}",
                    "HTTP status alone was not used as SQLi evidence",
                ],
            )

        # No SQL error
        return SQLiAnalysis(
            detected=False,
            confidence="LOW",
            score=0.0,
            evidence="",
            reasons=[
                "No SQL database error signature detected",
            ],
        )