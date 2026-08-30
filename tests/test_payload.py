import unittest

from nova.discovery.payload import PayloadDiscovery


class MockResponse:
    def __init__(
        self,
        body="normal response",
        error=None,
        status=200,
    ):
        self.body = body
        self.error = error
        self.status = status
        self.url = "http://example.test/"
        self.content_length = len(body)
        self.words = len(body.split())
        self.lines = len(body.splitlines())
        self.elapsed_ms = 1.0

    @property
    def is_redirect(self):
        return self.status in {
            301,
            302,
            303,
            307,
            308,
        }


class MockRequester:

    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(
            {
                "url": url,
                "kwargs": kwargs,
            }
        )

        return MockResponse()


class MockEngine:

    def __init__(self):
        self.calls = []

    def analyze(
        self,
        response,
        value,
        finding_type,
    ):
        self.calls.append(
            {
                "response": response,
                "value": value,
                "finding_type": finding_type,
            }
        )

        return {
            "value": value,
            "type": finding_type,
        }


class ErrorRequester:

    def get(self, url, **kwargs):
        return MockResponse(
            error="request failed"
        )


class TestPayloadDiscovery(unittest.TestCase):

    def setUp(self):
        self.requester = MockRequester()
        self.engine = MockEngine()

        self.discovery = PayloadDiscovery(
            requester=self.requester,
            engine=self.engine,
            wordlist=[
                "test1",
                "test2",
                "# comment",
                "",
                "test1",
            ],
        )

    def test_wordlist_cleanup(self):
        self.assertEqual(
            self.discovery.wordlist,
            [
                "test1",
                "test2",
                "test1",
            ],
        )

    def test_valid_payload_type(self):
        result = self.discovery.test_payload(
            target="http://example.test/",
            payload="test",
            parameter="q",
            payload_type="xss",
        )

        self.assertIsNotNone(result)

        self.assertEqual(
            result["type"],
            "payload:xss",
        )

    def test_invalid_payload_type(self):
        with self.assertRaises(ValueError):
            self.discovery.test_payload(
                target="http://example.test/",
                payload="test",
                parameter="q",
                payload_type="invalid",
            )

    def test_parameter_is_sent(self):
        self.discovery.test_payload(
            target="http://example.test/",
            payload="TEST_PAYLOAD",
            parameter="q",
            payload_type="generic",
        )

        self.assertEqual(
            len(self.requester.calls),
            1,
        )

        call = self.requester.calls[0]

        self.assertEqual(
            call["kwargs"]["params"],
            {
                "q": "TEST_PAYLOAD",
            },
        )

    def test_request_error(self):
        discovery = PayloadDiscovery(
            requester=ErrorRequester(),
            engine=self.engine,
            wordlist=["test"],
        )

        result = discovery.test_payload(
            target="http://example.test/",
            payload="test",
            parameter="q",
        )

        self.assertIsNone(result)

    def test_scan_all_payloads(self):
        findings = self.discovery.scan(
            target="http://example.test/",
            parameter="q",
            payload_type="ssti",
        )

        self.assertEqual(
            len(findings),
            3,
        )

        self.assertEqual(
            len(self.requester.calls),
            3,
        )

        self.assertTrue(
            all(
                item["type"] == "payload:ssti"
                for item in findings
            )
        )


if __name__ == "__main__":
    unittest.main()