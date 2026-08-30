import unittest

from nova.discovery.xxe_analyzer import XXEAnalyzer


class TestXXEAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = XXEAnalyzer()

    def test_no_xxe(self):

        result = self.analyzer.analyze(
            response_body="<root>Hello</root>",
            response_status=200,
            content_type="application/xml",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.score, 0.0)

    def test_entity_evidence(self):

        result = self.analyzer.analyze(
            response_body=(
                "<root>"
                "NOVA_XXE_7F31A"
                "</root>"
            ),
            response_status=200,
            content_type="application/xml",
        )

        self.assertTrue(result.detected)
        self.assertEqual(result.score, 100.0)
        self.assertEqual(
            result.confidence,
            "HIGH",
        )

        self.assertIn(
            "internal_entity_expansion",
            result.reasons,
        )

    def test_parser_error_is_not_confirmed_xxe(self):

        result = self.analyzer.analyze(
            response_body=(
                "XML parser error: "
                "DOCTYPE is not allowed"
            ),
            response_status=400,
            content_type="text/plain",
        )

        self.assertFalse(result.detected)
        self.assertEqual(
            result.confidence,
            "LOW",
        )

    def test_xml_content_type_alone(self):

        result = self.analyzer.analyze(
            response_body="<root>Hello</root>",
            response_status=200,
            content_type="application/xml",
        )

        self.assertFalse(result.detected)

        self.assertIn(
            "xml_content_type",
            result.reasons,
        )

    def test_empty_response(self):

        result = self.analyzer.analyze(
            response_body="",
        )

        self.assertFalse(result.detected)
        self.assertEqual(result.score, 0.0)


if __name__ == "__main__":
    unittest.main()