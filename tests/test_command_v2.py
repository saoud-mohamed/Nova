import unittest

from nova.analyzers.command import CommandAnalyzer


class TestCommandAnalyzerV2(unittest.TestCase):

    def setUp(self):
        self.analyzer = CommandAnalyzer()

    # ==================================================
    # BASIC DETECTION
    # ==================================================

    def test_command_detection_is_case_insensitive(self):
        response = """
        BASH: TEST: COMMAND NOT FOUND
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="test",
        )

        self.assertTrue(result.detected)
        self.assertGreaterEqual(result.score, 35)

    def test_command_not_found_is_detected(self):
        response = """
        bash: testcommand: command not found
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="testcommand",
        )

        self.assertTrue(result.detected)
        self.assertGreaterEqual(result.score, 35)

    def test_detected_command_injection_contains_evidence(self):
        response = """
        sh: testcommand: command not found
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="testcommand",
        )

        self.assertTrue(result.detected)

        self.assertGreater(
            len(result.evidence),
            0,
        )

    # ==================================================
    # EMPTY / NORMAL RESPONSES
    # ==================================================

    def test_empty_response_is_safe(self):
        result = self.analyzer.analyze(
            response_body="",
            payload="test",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.evidence, [])
        self.assertEqual(result.reasons, [])

    def test_normal_application_response_is_not_detected(self):
        response = """
        <html>
            <h1>Search Results</h1>
            <p>No results found.</p>
        </html>
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="test",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.score, 0)

    def test_normal_json_response_is_not_detected(self):
        response = """
        {
            "status": "success",
            "message": "Search completed",
            "results": []
        }
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="test",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.score, 0)

    # ==================================================
    # FALSE POSITIVE PROTECTION
    # ==================================================

    def test_reflection_alone_is_not_command_injection(self):
        payload = "hello"

        response = f"""
        <html>
            <p>Input: {payload}</p>
        </html>
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload=payload,
        )

        self.assertFalse(result.detected)
        self.assertLess(result.score, 35)

    def test_reflection_plus_generic_text_is_not_enough(self):
        payload = "test"

        response = f"""
        Search result for {payload}
        Error while processing request.
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload=payload,
        )

        self.assertFalse(result.detected)
        self.assertLess(result.score, 35)

    def test_random_command_word_is_not_evidence(self):
        response = """
        This page contains the word command.
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="command",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.score, 5)

    def test_generic_error_is_not_command_injection(self):
        response = """
        Internal Server Error
        Something went wrong.
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="test",
        )

        self.assertFalse(result.detected)

    # ==================================================
    # WEAK SIGNALS
    # ==================================================

    def test_permission_denied_is_weak_evidence(self):
        response = """
        permission denied
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="test",
        )

        self.assertFalse(result.detected)
        self.assertLess(result.score, 35)

        self.assertTrue(
            len(result.evidence) > 0
        )

        self.assertTrue(
            any(
                "Shell error signature detected" in reason
                for reason in result.reasons
            )
        )

    def test_shell_syntax_error_is_detected_as_weak_signal(self):
        response = """
        sh: syntax error near unexpected token
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="test",
        )

        # Syntax errors are weak evidence only.
        # They must not confirm command injection alone.
        self.assertFalse(
            result.detected
        )

        self.assertLess(
            result.score,
            35,
        )

        self.assertTrue(
            len(result.evidence) > 0
        )

        self.assertTrue(
            any(
                "Shell error signature detected" in reason
                for reason in result.reasons
            )
        )

    # ==================================================
    # UNIX / LINUX
    # ==================================================

    def test_unix_identity_output_is_high_signal(self):
        response = """
        uid=1000(nova) gid=1000(nova) groups=1000(nova)
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="test",
        )

        self.assertTrue(
            result.detected
        )

        self.assertGreaterEqual(
            result.score,
            35,
        )

        self.assertGreater(
            len(result.evidence),
            0,
        )

    def test_unix_passwd_signature_is_detected(self):
        response = """
        root:x:0:0:root:/root:/bin/bash
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="test",
        )

        self.assertTrue(
            result.detected
        )

        self.assertGreaterEqual(
            result.score,
            35,
        )

    # ==================================================
    # WINDOWS
    # ==================================================

    def test_windows_command_output_is_detected(self):
        response = """
        Microsoft Windows [Version 10.0.19045]
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="test",
        )

        self.assertTrue(
            result.detected
        )

        self.assertGreaterEqual(
            result.score,
            35,
        )

    def test_windows_directory_output_is_detected(self):
        response = r"""
        Directory of C:\Users\nova
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="test",
        )

        self.assertTrue(
            result.detected
        )

        self.assertGreaterEqual(
            result.score,
            35,
        )

    # ==================================================
    # MULTIPLE SIGNALS
    # ==================================================

    def test_multiple_command_signals_increase_score(self):
        response = """
        uid=1000(nova) gid=1000(nova)
        bash: testcommand: command not found
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="testcommand",
        )

        self.assertTrue(
            result.detected
        )

        self.assertGreaterEqual(
            result.score,
            70,
        )

    # ==================================================
    # DUPLICATE EVIDENCE
    # ==================================================

    def test_duplicate_evidence_is_removed(self):
        response = """
        bash: testcommand: command not found
        bash: testcommand: command not found
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="testcommand",
        )

        self.assertTrue(
            result.detected
        )

        self.assertEqual(
            len(result.evidence),
            len(set(result.evidence)),
        )

    # ==================================================
    # SCORE LIMIT
    # ==================================================

    def test_score_never_exceeds_100(self):
        response = r"""
        bash: testcommand: command not found

        sh: anothercommand: command not found

        uid=1000(nova) gid=1000(nova)

        root:x:0:0:root:/root:/bin/bash

        Microsoft Windows [Version 10.0.19045]

        Directory of C:\Users\nova

        permission denied

        syntax error

        unexpected token
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="testcommand",
        )

        self.assertLessEqual(
            result.score,
            100,
        )

    # ==================================================
    # RESULT STRUCTURE
    # ==================================================

    def test_result_structure(self):
        response = """
        uid=1000(nova) gid=1000(nova)
        """

        result = self.analyzer.analyze(
            response_body=response,
            payload="test",
        )

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