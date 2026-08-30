import unittest

from nova.discovery.payload import PayloadDiscovery


# ==========================================================
# MOCK RESPONSE
# ==========================================================

class MockResponse:

    def __init__(
        self,
        body="",
        error=False,
    ):
        self.body = body
        self.error = error


# ==========================================================
# MOCK REQUESTER
# ==========================================================

class MockRequester:

    def __init__(
        self,
        response_body,
    ):
        self.response_body = response_body
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

        return MockResponse(
            body=self.response_body,
            error=False,
        )


# ==========================================================
# ERROR REQUESTER
# ==========================================================

class ErrorRequester:

    def get(
        self,
        target,
        params=None,
    ):
        return MockResponse(
            body="",
            error=True,
        )


# ==========================================================
# MOCK ENGINE
# ==========================================================

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
            "type": finding_type,
            "value": value,
            "score": 0,
            "confidence": "low",
            "metadata": {},
        }


# ==========================================================
# TESTS
# ==========================================================

class TestCommandPayloadIntegration(
    unittest.TestCase
):

    def setUp(self):

        self.target = (
            "http://127.0.0.1:8000/search"
        )

        self.parameter = "name"

    # ======================================================
    # COMMAND PAYLOAD DETECTION
    # ======================================================

    def test_command_payload_detection(self):

        response_body = """
Search result

uid=1000(user)
gid=1000(user)
groups=1000(user)

command output detected
"""

        requester = MockRequester(
            response_body=response_body
        )

        engine = MockEngine()

        discovery = PayloadDiscovery(
            requester=requester,
            engine=engine,
            wordlist=[
                "normal",
                "command-test",
            ],
        )

        findings = discovery.scan(
            target=self.target,
            parameter=self.parameter,
            payload_type="command",
        )

        # Pipeline completed
        self.assertIsNotNone(
            findings
        )

        # Two payloads = two requests
        self.assertEqual(
            len(requester.calls),
            2,
        )

        # Engine should also receive both
        self.assertEqual(
            len(engine.calls),
            2,
        )

    # ======================================================
    # PARAMETER IS SENT
    # ======================================================

    def test_command_parameter_is_sent(self):

        requester = MockRequester(
            response_body="normal response"
        )

        engine = MockEngine()

        discovery = PayloadDiscovery(
            requester=requester,
            engine=engine,
            wordlist=[
                "test-command",
            ],
        )

        discovery.scan(
            target=self.target,
            parameter=self.parameter,
            payload_type="command",
        )

        self.assertEqual(
            len(requester.calls),
            1,
        )

        request = requester.calls[0]

        self.assertEqual(
            request["target"],
            self.target,
        )

        self.assertEqual(
            request["params"]["name"],
            "test-command",
        )

    # ======================================================
    # FINDING TYPE
    # ======================================================

    def test_command_finding_type(self):

        response_body = """
uid=1000(user)
gid=1000(user)
groups=1000(user)
"""

        requester = MockRequester(
            response_body=response_body
        )

        engine = MockEngine()

        discovery = PayloadDiscovery(
            requester=requester,
            engine=engine,
            wordlist=[
                "command-test",
            ],
        )

        findings = discovery.scan(
            target=self.target,
            parameter=self.parameter,
            payload_type="command",
        )

        # Engine must be called
        self.assertEqual(
            len(engine.calls),
            1,
        )

        # Correct finding type
        self.assertEqual(
            engine.calls[0]["finding_type"],
            "payload:command",
        )

        # Correct payload
        self.assertEqual(
            engine.calls[0]["value"],
            "command-test",
        )

        # Finding returned
        self.assertEqual(
            len(findings),
            1,
        )

        self.assertEqual(
            findings[0]["type"],
            "payload:command",
        )

    # ======================================================
    # MULTIPLE PAYLOADS
    # ======================================================

    def test_multiple_command_payloads(self):

        payloads = [
            "payload-one",
            "payload-two",
            "payload-three",
        ]

        requester = MockRequester(
            response_body="normal response"
        )

        engine = MockEngine()

        discovery = PayloadDiscovery(
            requester=requester,
            engine=engine,
            wordlist=payloads,
        )

        discovery.scan(
            target=self.target,
            parameter=self.parameter,
            payload_type="command",
        )

        # Requests
        self.assertEqual(
            len(requester.calls),
            len(payloads),
        )

        # Engine calls
        self.assertEqual(
            len(engine.calls),
            len(payloads),
        )

        sent_payloads = [
            call["params"]["name"]
            for call in requester.calls
        ]

        self.assertEqual(
            sent_payloads,
            payloads,
        )

        engine_payloads = [
            call["value"]
            for call in engine.calls
        ]

        self.assertEqual(
            engine_payloads,
            payloads,
        )

    # ======================================================
    # REQUEST ERROR
    # ======================================================

    def test_request_error_does_not_create_finding(self):

        requester = ErrorRequester()

        engine = MockEngine()

        discovery = PayloadDiscovery(
            requester=requester,
            engine=engine,
            wordlist=[
                "command-test",
            ],
        )

        findings = discovery.scan(
            target=self.target,
            parameter=self.parameter,
            payload_type="command",
        )

        self.assertEqual(
            findings,
            [],
        )

        self.assertEqual(
            len(engine.calls),
            0,
        )

    # ======================================================
    # INVALID TYPE
    # ======================================================

    def test_invalid_payload_type(self):

        requester = MockRequester(
            response_body="normal"
        )

        engine = MockEngine()

        discovery = PayloadDiscovery(
            requester=requester,
            engine=engine,
            wordlist=[
                "test",
            ],
        )

        with self.assertRaises(
            ValueError
        ):

            discovery.scan(
                target=self.target,
                parameter=self.parameter,
                payload_type="invalid",
            )


# ==========================================================
# MAIN
# ==========================================================

if __name__ == "__main__":
    unittest.main()