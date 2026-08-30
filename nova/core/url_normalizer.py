from urllib.parse import (
    urlsplit,
    urlunsplit,
    parse_qsl,
    urlencode
)


class URLNormalizer:

    @staticmethod
    def normalize(url: str) -> str:

        parsed = urlsplit(url)

        query = urlencode(
            sorted(
                parse_qsl(
                    parsed.query,
                    keep_blank_values=True
                )
            )
        )

        return urlunsplit((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            query,
            ""
        ))