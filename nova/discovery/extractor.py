import re

from urllib.parse import (
    parse_qsl,
    urlsplit,
)


class ParameterExtractor:

    INPUT_RE = re.compile(
        r"""<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["']""",
        re.IGNORECASE,
    )

    DATA_PARAM_RE = re.compile(
        r"""data-(?:param|parameter)\s*=\s*["']([^"']+)["']""",
        re.IGNORECASE,
    )

    @classmethod
    def from_url(cls, url: str) -> list[str]:

        parsed = urlsplit(url)

        return list(
            dict.fromkeys(
                key
                for key, _ in parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                )
                if key
            )
        )

    @classmethod
    def from_html(cls, html: str) -> list[str]:

        if not html:
            return []

        results = []

        results.extend(
            cls.INPUT_RE.findall(html)
        )

        results.extend(
            cls.DATA_PARAM_RE.findall(html)
        )

        return list(
            dict.fromkeys(
                item.strip()
                for item in results
                if item.strip()
            )
        )

    @classmethod
    def extract(
        cls,
        url: str,
        html: str = "",
    ) -> list[str]:

        results = []

        results.extend(
            cls.from_url(url)
        )

        results.extend(
            cls.from_html(html)
        )

        return list(
            dict.fromkeys(results)
        )