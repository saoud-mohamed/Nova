from urllib.parse import urljoin

from .forms import FormExtractor


class FormScanner:

    def __init__(
        self,
        requester,
    ):
        self.requester = requester
        self.extractor = FormExtractor()

    def scan(self, target: str):

        response = self.requester.get(
            target
        )

        if response.error:
            return []

        forms = self.extractor.extract(
            response.body
        )

        results = []

        for form in forms:

            action = form["action"]

            action_url = urljoin(
                target,
                action
            )

            results.append({
                "url": action_url,
                "method": form["method"],
                "parameters": form[
                    "parameters"
                ],
            })

        return results