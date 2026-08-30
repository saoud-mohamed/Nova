from urllib.parse import urljoin

from nova.core.url_normalizer import URLNormalizer


class PathDiscovery:

    def __init__(
        self,
        requester,
        engine,
        wordlist,
    ):
        self.requester = requester
        self.engine = engine

        self.wordlist = self._prepare_wordlist(
            wordlist
        )

    @staticmethod
    def _prepare_wordlist(wordlist):

        return [
            word.strip()
            for word in wordlist
            if word
            and word.strip()
            and not word.lstrip().startswith("#")
        ]

    @staticmethod
    def _build_url(
        target,
        word,
    ):
        return urljoin(
            target.rstrip("/") + "/",
            word.lstrip("/"),
        )

    def scan(self, target):

        findings = []
        seen = set()

        for word in self.wordlist:

            url = self._build_url(
                target,
                word,
            )

            url = URLNormalizer.normalize(
                url
            )

            if url in seen:
                continue

            seen.add(url)

            response = self.requester.get(
                url
            )

            if response is None:
                continue

            if response.error:
                continue

            # A normal 404 should not be reported.
            if response.status == 404:
                continue

            result = self.engine.analyze(
                response=response,
                value=word,
                finding_type="path",
            )

            if result is not None:
                findings.append(result)

        return findings