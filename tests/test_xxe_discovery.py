import unittest

from unittest.mock import Mock

from nova.discovery.xxe import XXEDiscovery


class TestXXEDiscovery(unittest.TestCase):

    def setUp(self):

        self.requester = Mock()

        self.engine = Mock()

        self.discovery = XXEDiscovery(
            self.requester,
            self.engine,
        )

    def test_build_payload_contains_marker(self):

        payload = (
            self.discovery.build_payload()
        )

        self.assertIn(
            "NOVA_XXE_7F31A",
            payload,
        )

        self.assertIn(
            "<!DOCTYPE",
            payload,
        )

        self.assertIn(
            "<!ENTITY",
            payload,
        )

    def test_scan_detects_evidence(self):

        response = Mock()

        response.error = None

        response.body = (
            "<root>"
            "NOVA_XXE_7F31A"
            "</root>"
        )

        response.status = 200

        response.url = (
            "http://example.test/xml"
        )

        response.headers = {
            "Content-Type":
                "application/xml"
        }

        response.content_length = 30

        response.words = 2

        response.lines = 1

        response.elapsed_ms = 10.0

        self.requester.post.return_value = (
            response
        )

        finding = Mock()

        self.engine.analyze_evidence.return_value = (
            finding
        )

        results = self.discovery.scan(
            "http://example.test/xml"
        )

        self.requester.post.assert_called_once()

        self.engine.analyze_evidence.assert_called_once()

        self.assertEqual(
            len(results),
            1,
        )

        self.assertIs(
            results[0],
            finding,
        )

    def test_scan_without_evidence(self):

        response = Mock()

        response.error = None

        response.body = (
            "<root>Hello</root>"
        )

        response.status = 200

        response.url = (
            "http://example.test/xml"
        )

        response.headers = {
            "Content-Type":
                "application/xml"
        }

        self.requester.post.return_value = (
            response
        )

        results = self.discovery.scan(
            "http://example.test/xml"
        )

        self.assertEqual(
            results,
            [],
        )

    def test_request_error(self):

        response = Mock()

        response.error = (
            "connection failed"
        )

        self.requester.post.return_value = (
            response
        )

        results = self.discovery.scan(
            "http://example.test/xml"
        )

        self.assertEqual(
            results,
            [],
        )


if __name__ == "__main__":

    unittest.main()