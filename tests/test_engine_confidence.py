import unittest

from nova.core.engine import NovaEngine


class FakeResponse:

    def __init__(
        self,
        body,
        status=200,
        url="http://test.local",
    ):
        self.body = body
        self.status = status
        self.url = url

        self.error = False
        self.is_redirect = False

        self.content_length = len(body)
        self.words = len(body.split())
        self.lines = len(body.splitlines())
        self.elapsed_ms = 10


class FakeRequester:

    def __init__(self):
        self.calls = []

    def get(
        self,
        target,
        params=None,
    ):
        self.calls.append(
            {
                "target": target,
                "params": params,
            }
        )

        return FakeResponse(
            body="normal response",
            status=200,
            url=target,
        )


class TestEngineConfidence(unittest.TestCase):

    def setUp(self):

        self.requester = FakeRequester()

        self.engine = NovaEngine(
            requester=self.requester,
            target="http://test.local",
        )

        # Establish baseline using the real Baseline API.
        self.engine.calibrate()

    # ==================================================
    # NORMAL RESPONSE
    # ==================================================

    def test_normal_response_creates_no_finding(self):

        response = FakeResponse(
            body="normal response",
            status=200,
        )

        result = self.engine.analyze(
            response=response,
            value="test",
            finding_type="payload:command",
        )

        self.assertIsNone(result)

    # ==================================================
    # RESPONSE CHANGE
    # ==================================================

    def test_response_change_creates_finding(self):

        response = FakeResponse(
            body=(
                "completely different response "
                * 20
            ),
            status=200,
        )

        result = self.engine.analyze(
            response=response,
            value="demo",
            finding_type="payload:command",
        )

        self.assertIsNotNone(result)

    # ==================================================
    # FINDING TYPE
    # ==================================================

    def test_finding_type_is_preserved(self):

        response = FakeResponse(
            body=(
                "completely different response "
                * 20
            ),
            status=200,
        )

        result = self.engine.analyze(
            response=response,
            value="demo-command",
            finding_type="payload:command",
        )

        self.assertIsNotNone(result)

        self.assertEqual(
            result.type,
            "payload:command",
        )

    # ==================================================
    # DIFFERENCE ALONE
    # ==================================================

    def test_engine_does_not_claim_command_injection_from_difference_alone(self):

        response = FakeResponse(
            body=(
                "random completely different content "
                * 20
            ),
            status=200,
        )

        result = self.engine.analyze(
            response=response,
            value="normal-input",
            finding_type="payload:command",
        )

        if result is not None:

            self.assertNotEqual(
                result.metadata.get(
                    "confirmed_vulnerability",
                    False,
                ),
                True,
            )


if __name__ == "__main__":
    unittest.main()