"""Scoring contract checks; no model service or source-analysis dependencies."""
import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
from metrics import evaluate
from response_parser import parse_answer


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rows = [dict(cve=cve, repository="owner/repo", version=version,
                          ground_truth=truth, prediction=prediction)
                     for cve, version, truth, prediction in [
                         ("CVE-A", "1", "YES", "YES"),
                         ("CVE-B", "1", "YES", "NO"),
                         ("CVE-B", "2", "NO", "NO"),
                         ("CVE-B", "3", "NO", "NO")]]
        self.write("labels.csv", self.rows)

    def write(self, name, rows):
        with (self.root / name).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(self.rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    def score(self, rows):
        self.write("predictions.csv", rows)
        return evaluate(self.root / "labels.csv", self.root / "predictions.csv", "repository")

    def test_macro_is_not_pooled(self):
        result = self.score(self.rows)
        self.assertEqual(result["pair"]["accuracy"], 0.75)
        self.assertAlmostEqual(result["cve_macro"]["accuracy"], 5 / 6)
        self.assertEqual(result["pair"]["fn"], 1)
        self.assertEqual(result["cve_macro"]["precision_negative"], 1 / 3)

    def test_incomplete_duplicate_extra_and_invalid_predictions_fail(self):
        variants = [self.rows[:-1], self.rows + [self.rows[0]],
                    self.rows + [dict(self.rows[0], version="extra")],
                    [dict(self.rows[0], prediction="")] + self.rows[1:],
                    [dict(self.rows[0], ground_truth="NO")] + self.rows[1:]]
        for rows in variants:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.score(rows)

    def test_parser_does_not_treat_prose_or_confidence_as_verdict(self):
        self.assertIsNone(parse_answer("The answer may be YES.\nCONFIDENCE: 0.99"))
        self.assertEqual(parse_answer("<think>YES</think>\nNO\nCONFIDENCE: 0.1"), "NO")
        self.assertEqual(parse_answer("YES\nNO\nCONFIDENCE: 0.9"), "NO")
        self.assertIsNone(parse_answer("```\nYES\n```"))


if __name__ == "__main__":
    unittest.main()
