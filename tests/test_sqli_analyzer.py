import unittest

from nova.analyzers.sqli import SQLiAnalyzer


class TestSQLiAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = SQLiAnalyzer()

    def test_mysql_error(self):

        result = self.analyzer.analyze(
            response_body=(
                "You have an error in your SQL syntax; "
                "check the manual for the right syntax"
            ),
            payload="'",
        )

        self.assertTrue(result.detected)
        self.assertEqual(
            result.confidence,
            "HIGH",
        )
        self.assertGreater(
            result.score,
            0,
        )

    def test_postgresql_error(self):

        result = self.analyzer.analyze(
            response_body=(
                "PostgreSQL ERROR: "
                "syntax error at or near"
            ),
            payload="'",
        )

        self.assertTrue(result.detected)

    def test_oracle_error(self):

        result = self.analyzer.analyze(
            response_body=(
                "ORA-00933: SQL command not "
                "properly ended"
            ),
            payload="'",
        )

        self.assertTrue(result.detected)

    def test_normal_response(self):

        result = self.analyzer.analyze(
            response_body=(
                "Search results for hello"
            ),
            payload="hello",
        )

        self.assertFalse(result.detected)
        self.assertEqual(
            result.score,
            0.0,
        )

    def test_empty_response(self):

        result = self.analyzer.analyze(
            response_body="",
            payload="'",
        )

        self.assertFalse(result.detected)


if __name__ == "__main__":
    unittest.main()