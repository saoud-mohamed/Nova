from .pipeline import DiscoveryPipeline
from .path import PathDiscovery


class RecursiveDiscovery:

    def __init__(
        self,
        requester,
        engine,
        wordlist,
        max_pages=50,
    ):
        self.pipeline = DiscoveryPipeline(
            requester=requester,
            max_pages=max_pages,
        )

        self.path_scanner = PathDiscovery(
            requester=requester,
            engine=engine,
            wordlist=wordlist,
        )

    def scan(
        self,
        target,
    ):
        pages = self.pipeline.crawl(
            target
        )

        findings = []

        seen_paths = set()

        for page in pages:

            url = page["url"]

            if url in seen_paths:
                continue

            seen_paths.add(url)

            results = self.path_scanner.scan(
                url
            )

            findings.extend(results)

        return {
            "pages": pages,
            "findings": findings,
        }