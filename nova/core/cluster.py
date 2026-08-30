from .similarity import Similarity


class ResponseCluster:

    def __init__(
        self,
        threshold: float = 0.95
    ):

        self.threshold = threshold

        self.similarity = (
            Similarity()
        )

        self.responses = []

    def add(self, response):

        for existing in self.responses:

            score = self.similarity.score(
                existing.body,
                response.body
            )

            if score >= self.threshold:

                return False

        self.responses.append(
            response
        )

        return True

    def __len__(self):

        return len(
            self.responses
        )