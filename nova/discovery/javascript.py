import re
from urllib.parse import urljoin


class JavaScriptExtractor:

    SCRIPT_RE = re.compile(
        r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""",
        re.IGNORECASE,
    )

    def extract(
        self,
        base_url,
        html,
    ):
        results = []

        for src in self.SCRIPT_RE.findall(
            html or ""
        ):

            url = urljoin(
                base_url,
                src,
            )

            if url not in results:
                results.append(url)

        return results