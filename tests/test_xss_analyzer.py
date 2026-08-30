import unittest

from nova.analyzers.xss import XSSAnalyzer


class TestXSSAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = XSSAnalyzer()

    def test_reflected_xss(self):

        payload = "<script>alert(1)</script>"

        body = (
            "<html>"
            "<body>"
            f"{payload}"
            "</body>"
            "</html>"
        )

        result = self.analyzer.analyze(
            response_body=body,
            payload=payload,
        )

        self.assertTrue(
            result.detected
        )

        self.assertEqual(
            result.context,
            "html",
        )

        self.assertGreaterEqual(
            result.score,
            90,
        )

    def test_not_reflected(self):

        result = self.analyzer.analyze(
            response_body="<html>Hello</html>",
            payload="<script>alert(1)</script>",
        )

        self.assertFalse(
            result.detected
        )

        self.assertEqual(
            result.score,
            0.0,
        )

    def test_javascript_context(self):

        payload = "NOVA_XSS"

        body = (
            "<script>"
            f"var x = '{payload}';"
            "</script>"
        )

        result = self.analyzer.analyze(
            response_body=body,
            payload=payload,
        )

        self.assertEqual(
            result.context,
            "javascript",
        )

        self.assertTrue(
            result.detected
        )


if __name__ == "__main__":
    unittest.main()