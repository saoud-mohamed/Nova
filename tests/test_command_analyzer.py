import unittest

from nova.analyzers.command import CommandAnalyzer


class TestCommandAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = CommandAnalyzer()

    # ==================================================
    # EMPTY RESPONSE
    # ==================================================

    def test_empty_response(self):
        result = self.analyzer.analyze(
            response_body="",
            payload="test",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.evidence, [])

    # ==================================================
    # UNIX COMMAND ERROR
    # ==================================================

    def test_unix_command_not_found(self):
        result = self.analyzer.analyze(
            response_body="bash: id: command not found",
            payload="id",
        )

        self.assertTrue(result.detected)
        self.assertGreaterEqual(result.score, 35)
        self.assertTrue(result.evidence)

    # ==================================================
    # WINDOWS COMMAND ERROR
    # ==================================================

    def test_windows_command_error(self):
        result = self.analyzer.analyze(
            response_body=(
                "'id' is not recognized as an internal "
                "or external command"
            ),
            payload="id",
        )

        self.assertTrue(result.detected)
        self.assertGreaterEqual(result.score, 35)
        self.assertTrue(result.evidence)

    # ==================================================
    # UNIX OUTPUT
    # ==================================================

    def test_unix_command_output(self):
        result = self.analyzer.analyze(
            response_body="uid=1000(user) gid=1000(user) groups=1000(user)",
            payload="id",
        )

        self.assertTrue(result.detected)
        self.assertGreaterEqual(result.score, 35)
        self.assertTrue(result.evidence)

    # ==================================================
    # WINDOWS OUTPUT
    # ==================================================

    def test_windows_command_output(self):
        result = self.analyzer.analyze(
            response_body=(
                "Microsoft Windows [Version 10.0.19045]"
            ),
            payload="ver",
        )

        self.assertTrue(result.detected)
        self.assertGreaterEqual(result.score, 35)
        self.assertTrue(result.evidence)

    # ==================================================
    # SHELL ERROR
    # ==================================================

    def test_shell_error(self):
        result = self.analyzer.analyze(
            response_body="syntax error near unexpected token",
            payload="test",
        )

        self.assertFalse(result.detected)
        self.assertGreater(result.score, 0)
        self.assertTrue(result.evidence)

    # ==================================================
    # REFLECTION ALONE
    # ==================================================

    def test_reflection_alone_is_not_command_injection(self):
        result = self.analyzer.analyze(
            response_body="hello test hello",
            payload="test",
        )

        self.assertFalse(result.detected)
        self.assertLess(result.score, 35)

    # ==================================================
    # NORMAL RESPONSE
    # ==================================================

    def test_normal_response(self):
        result = self.analyzer.analyze(
            response_body=(
                "<html><body>"
                "Welcome to the search page"
                "</body></html>"
            ),
            payload="hello",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.evidence, [])

    # ==================================================
    # CASE INSENSITIVE
    # ==================================================

    def test_case_insensitive_detection(self):
        result = self.analyzer.analyze(
            response_body="BASH: ID: COMMAND NOT FOUND",
            payload="id",
        )

        self.assertTrue(result.detected)

    # ==================================================
    # RESULT STRUCTURE
    # ==================================================

    def test_result_structure(self):
        result = self.analyzer.analyze(
            response_body="bash: id: command not found",
            payload="id",
        )

        self.assertTrue(hasattr(result, "detected"))
        self.assertTrue(hasattr(result, "score"))
        self.assertTrue(hasattr(result, "confidence"))
        self.assertTrue(hasattr(result, "evidence"))
        self.assertTrue(hasattr(result, "reasons"))

        self.assertIsInstance(
            result.detected,
            bool,
        )

        self.assertIsInstance(
            result.score,
            int,
        )

        self.assertIsInstance(
            result.confidence,
            str,
        )

        self.assertIsInstance(
            result.evidence,
            list,
        )

        self.assertIsInstance(
            result.reasons,
            list,
        )


if __name__ == "__main__":
    unittest.main()