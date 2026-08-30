import unittest

from nova.discovery.xxe_analyzer import (
    XXEAnalyzer,
)


class TestXXEAnalyzer(
    unittest.TestCase
):

    def setUp(self):

        self.analyzer = XXEAnalyzer()

    # -------------------------------------------------
    # Marker expansion
    # -------------------------------------------------

    def test_internal_entity_expansion(self):

        body = (
            "<root>"
            "NOVA_XXE_7F31A"
            "</root>"
        )

        result = self.analyzer.analyze(
            response_body=body,
            response_status=200,
            content_type="application/xml",
        )

        self.assertTrue(
            result.detected
        )

        self.assertEqual(
            result.confidence,
            "HIGH",
        )

        self.assertEqual(
            result.score,
            100.0,
        )

        self.assertIn(
            "internal_entity_expansion",
            result.reasons,
        )

    # -------------------------------------------------
    # Normal XML
    # -------------------------------------------------

    def test_normal_xml_is_not_xxe(self):

        body = """
        <?xml version="1.0"?>
        <root>
            <nova>hello</nova>
        </root>
        """

        result = self.analyzer.analyze(
            response_body=body,
            response_status=200,
            content_type="application/xml",
        )

        self.assertFalse(
            result.detected
        )

        self.assertEqual(
            result.score,
            0.0,
        )

    # -------------------------------------------------
    # Parser error
    # -------------------------------------------------

    def test_parser_error_is_not_confirmed_xxe(self):

        body = (
            "XML parser error: "
            "DOCTYPE is not allowed"
        )

        result = self.analyzer.analyze(
            response_body=body,
            response_status=400,
            content_type="text/plain",
        )

        self.assertFalse(
            result.detected
        )

        self.assertEqual(
            result.confidence,
            "LOW",
        )

        self.assertIn(
            "xml_parser_indicator",
            result.reasons,
        )

    # -------------------------------------------------
    # Empty response
    # -------------------------------------------------

    def test_empty_response(self):

        result = self.analyzer.analyze(
            response_body="",
        )

        self.assertFalse(
            result.detected
        )

        self.assertEqual(
            result.score,
            0.0,
        )

    # -------------------------------------------------
    # XML content type alone
    # -------------------------------------------------

    def test_xml_content_type_is_not_xxe(self):

        body = (
            "<root>hello</root>"
        )

        result = self.analyzer.analyze(
            response_body=body,
            response_status=200,
            content_type="application/xml",
        )

        self.assertFalse(
            result.detected
        )

        self.assertIn(
            "xml_content_type",
            result.reasons,
        )

    # -------------------------------------------------
    # Case insensitive parser errors
    # -------------------------------------------------

    def test_parser_detection_is_case_insensitive(self):

        body = (
            "XML PARSER ERROR: "
            "DOCTYPE rejected"
        )

        result = self.analyzer.analyze(
            response_body=body,
            response_status=400,
        )

        self.assertFalse(
            result.detected
        )

        self.assertIn(
            "xml_parser_indicator",
            result.reasons,
        )


if __name__ == "__main__":

    unittest.main()