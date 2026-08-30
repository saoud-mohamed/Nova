import unittest

from nova.analyzers.ssti import SSTIAnalyzer


class TestSSTIAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = SSTIAnalyzer()

    def test_jinja_error(self):

        result = self.analyzer.analyze(
            response_body=(
                "jinja2.exceptions.TemplateSyntaxError: "
                "unexpected end of template"
            ),
            payload="{{7*7}}",
        )

        self.assertTrue(result.detected)
        self.assertEqual(
            result.confidence,
            "HIGH",
        )
        self.assertEqual(
            result.engine,
            "jinja2",
        )
        self.assertGreater(
            result.score,
            0,
        )

    def test_twig_error(self):

        result = self.analyzer.analyze(
            response_body=(
                "Twig Error: "
                "Unable to parse template"
            ),
            payload="{{7*7}}",
        )

        self.assertTrue(result.detected)
        self.assertEqual(
            result.engine,
            "twig",
        )

    def test_freemarker_error(self):

        result = self.analyzer.analyze(
            response_body=(
                "freemarker.core.ParseException: "
                "Syntax error"
            ),
            payload="${7*7}",
        )

        self.assertTrue(result.detected)
        self.assertEqual(
            result.engine,
            "freemarker",
        )

    def test_normal_response(self):

        result = self.analyzer.analyze(
            response_body=(
                "Hello nova"
            ),
            payload="{{7*7}}",
        )

        self.assertFalse(
            result.detected
        )
        self.assertEqual(
            result.score,
            0.0,
        )

    def test_empty_response(self):

        result = self.analyzer.analyze(
            response_body="",
            payload="{{7*7}}",
        )

        self.assertFalse(
            result.detected
        )

    def test_template_error_case_insensitive(self):

        result = self.analyzer.analyze(
            response_body=(
                "JINJA2.EXCEPTIONS."
                "TEMPLATESYNTAXERROR"
            ),
            payload="{{7*7}}",
        )

        self.assertTrue(
            result.detected
        )


if __name__ == "__main__":
    unittest.main()