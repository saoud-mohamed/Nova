from difflib import SequenceMatcher

from .dynamic import DynamicContent


class Similarity:

    def __init__(self):
        self.normalizer = DynamicContent()

    def normalize(self, text: str | None) -> str:
        if text is None:
            return ""

        return self.normalizer.normalize(text)

    def score(
        self,
        first: str | None,
        second: str | None,
    ) -> float:

        first = self.normalize(first)
        second = self.normalize(second)

        if first == second:
            return 1.0

        if not first and not second:
            return 1.0

        return SequenceMatcher(
            None,
            first,
            second,
        ).ratio()

    def difference(
        self,
        first: str | None,
        second: str | None,
    ) -> float:

        return 1.0 - self.score(
            first,
            second,
        )