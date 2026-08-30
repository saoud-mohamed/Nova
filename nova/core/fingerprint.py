import hashlib

from .dynamic import DynamicContent


class Fingerprint:

    def __init__(self):

        self.normalizer = (
            DynamicContent()
        )

    def create(self, body: str) -> str:

        normalized = (
            self.normalizer.normalize(
                body
            )
        )

        return hashlib.sha256(
            normalized.encode(
                "utf-8",
                errors="ignore"
            )
        ).hexdigest()

    def metadata(self, response):

        return {
            "status": response.status,
            "length": response.content_length,
            "words": response.words,
            "lines": response.lines,
            "fingerprint": self.create(
                response.body
            )
        }