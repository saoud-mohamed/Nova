import unittest

from nova.core.results import (
    Finding,
    ResultEngine,
)


class TestResultEngine(unittest.TestCase):

    def setUp(self):

        self.engine = ResultEngine()

    def make_finding(
        self,
        finding_type,
        score,
        confidence,
    ):

        return Finding(
            type=finding_type,
            value="test",
            url="http://example.test",
            score=score,
            confidence=confidence,
        )

    def test_add(self):

        finding = self.make_finding(
            "xxe",
            100.0,
            "HIGH",
        )

        self.engine.add(finding)

        self.assertEqual(
            self.engine.count(),
            1,
        )

    def test_sort(self):

        low = self.make_finding(
            "xxe",
            20.0,
            "LOW",
        )

        high = self.make_finding(
            "xxe",
            100.0,
            "HIGH",
        )

        self.engine.add(low)
        self.engine.add(high)

        results = self.engine.sort()

        self.assertEqual(
            results[0].score,
            100.0,
        )

    def test_high_confidence(self):

        high = self.make_finding(
            "xxe",
            100.0,
            "HIGH",
        )

        low = self.make_finding(
            "path",
            20.0,
            "LOW",
        )

        self.engine.add(high)
        self.engine.add(low)

        results = (
            self.engine.high_confidence()
        )

        self.assertEqual(
            len(results),
            1,
        )

        self.assertEqual(
            results[0].type,
            "xxe",
        )

    def test_by_type(self):

        xxe = self.make_finding(
            "xxe",
            100.0,
            "HIGH",
        )

        path = self.make_finding(
            "path",
            50.0,
            "MEDIUM",
        )

        self.engine.add(xxe)
        self.engine.add(path)

        results = self.engine.by_type(
            "xxe"
        )

        self.assertEqual(
            len(results),
            1,
        )

        self.assertEqual(
            results[0].type,
            "xxe",
        )


if __name__ == "__main__":
    unittest.main()