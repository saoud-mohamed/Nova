import unittest

from nova.analyzers.lfi import LFIAnalyzer


class TestLFIAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = LFIAnalyzer()

    def test_empty_response(self):

        result = self.analyzer.analyze(
            response_body="",
            payload="test",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.score, 0)

    def test_normal_response(self):

        result = self.analyzer.analyze(
            response_body="""
                <html>
                    <body>
                        Welcome to the website.
                    </body>
                </html>
            """,
            payload="index",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.score, 0)

    def test_unix_file_signature(self):

        result = self.analyzer.analyze(
            response_body="""
                root:x:0:0:root:/root:/bin/bash
                user:x:1000:1000:user:/home/user:/bin/bash
            """,
            payload="test",
        )

        self.assertTrue(result.detected)
        self.assertGreaterEqual(result.score, 70)
        self.assertEqual(result.confidence, "high")

    def test_php_include_error(self):

        result = self.analyzer.analyze(
            response_body="""
                Warning: include(test.php):
                failed to open stream:
                No such file or directory
            """,
            payload="test",
        )

        self.assertTrue(result.detected)
        self.assertGreaterEqual(result.score, 40)

    def test_permission_error_is_low(self):

        result = self.analyzer.analyze(
            response_body="Permission denied",
            payload="test",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.confidence, "low")


if __name__ == "__main__":
    unittest.main()