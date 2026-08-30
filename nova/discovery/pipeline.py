from collections import deque
from urllib.parse import urljoin, urlsplit

from nova.core.url_normalizer import URLNormalizer


class DiscoveryPipeline:

    def __init__(
        self,
        requester,
        max_pages=50,
    ):
        self.requester = requester
        self.max_pages = max_pages

    @staticmethod
    def _same_host(
        base_url,
        target_url,
    ):
        base = urlsplit(base_url)
        target = urlsplit(target_url)

        return (
            base.scheme == target.scheme
            and base.netloc == target.netloc
        )

    @staticmethod
    def _extract_links(
        base_url,
        html,
    ):
        import re

        pattern = re.compile(
            r"""href\s*=\s*["']([^"']+)["']""",
            re.IGNORECASE,
        )

        links = []

        for href in pattern.findall(
            html or ""
        ):

            if href.startswith(
                (
                    "#",
                    "javascript:",
                    "mailto:",
                    "tel:",
                )
            ):
                continue

            absolute = urljoin(
                base_url,
                href,
            )

            links.append(
                URLNormalizer.normalize(
                    absolute
                )
            )

        return links

    def crawl(
        self,
        target,
    ):
        queue = deque([target])

        visited = set()

        pages = []

        while queue and len(
            visited
        ) < self.max_pages:

            current = queue.popleft()

            current = URLNormalizer.normalize(
                current
            )

            if current in visited:
                continue

            if not self._same_host(
                target,
                current,
            ):
                continue

            visited.add(current)

            response = self.requester.get(
                current
            )

            if response.error:
                continue

            pages.append({
                "url": current,
                "status": response.status,
                "length": response.content_length,
                "words": response.words,
            })

            if "text/html" not in (
                response.headers.get(
                    "Content-Type",
                    ""
                ).lower()
            ):
                continue

            for link in self._extract_links(
                current,
                response.body,
            ):

                if link not in visited:
                    queue.append(link)

        return pages