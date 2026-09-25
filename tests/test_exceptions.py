import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from dep_evidence.errors import InputError
from dep_evidence.exceptions import (
    ExceptionPolicy,
    ExceptionRule,
    annotate_finding,
    evaluate_exceptions,
    load_exception_policy,
)


class ExceptionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.rule = ExceptionRule(
            ecosystem="Maven",
            package="org.example:library",
            advisory_id="GHSA-test-test-test",
            reason="Risk accepted by the project owner",
            expires_on=date(2026, 9, 30),
        )
        self.policy = ExceptionPolicy(schema_version=1, rules=(self.rule,))

    def test_loads_versioned_json_policy(self):
        document = {
            "schema_version": 1,
            "exceptions": [
                {
                    "ecosystem": "Maven",
                    "package": "org.example:library",
                    "advisory_id": "GHSA-test-test-test",
                    "reason": "Risk accepted by the project owner",
                    "expires_on": "2026-09-30",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exceptions.json"
            path.write_text(json.dumps(document), encoding="utf-8")

            policy = load_exception_policy(path)

        self.assertEqual(1, policy.schema_version)
        self.assertEqual(self.rule, policy.rules[0])

    def test_rejects_boolean_schema_version(self):
        document = {"schema_version": True, "exceptions": []}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exceptions.json"
            path.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaises(InputError):
                load_exception_policy(path)

    def test_rejects_malformed_policy_documents(self):
        documents = (
            "{",
            "[]",
            json.dumps({"exceptions": []}),
            json.dumps({"schema_version": 2, "exceptions": []}),
            json.dumps({"schema_version": "1", "exceptions": []}),
            json.dumps({"schema_version": 1, "exceptions": {}}),
            json.dumps({"schema_version": 1, "exceptions": [None]}),
        )

        for document in documents:
            with self.subTest(document=document):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "exceptions.json"
                    path.write_text(document, encoding="utf-8")

                    with self.assertRaises(InputError):
                        load_exception_policy(path)

    def test_rejects_non_calendar_or_non_iso_expiry_dates(self):
        for expires_on in (
            "2026-02-30",
            "20260930",
            "2026-W40-4",
            "2026-9-30",
            "not-a-date",
            20260930,
        ):
            with self.subTest(expires_on=expires_on):
                document = {
                    "schema_version": 1,
                    "exceptions": [
                        {
                            "ecosystem": "Maven",
                            "package": "org.example:library",
                            "advisory_id": "GHSA-test-test-test",
                            "reason": "Risk accepted by the project owner",
                            "expires_on": expires_on,
                        }
                    ],
                }
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "exceptions.json"
                    path.write_text(json.dumps(document), encoding="utf-8")

                    with self.assertRaises(InputError):
                        load_exception_policy(path)

    def test_rejects_exception_policy_without_reason(self):
        document = {
            "schema_version": 1,
            "exceptions": [
                {
                    "ecosystem": "Maven",
                    "package": "org.example:library",
                    "advisory_id": "GHSA-test-test-test",
                    "expires_on": "2026-09-30",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exceptions.json"
            path.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaises(InputError):
                load_exception_policy(path)

    def test_active_exception_annotates_without_erasing_finding(self):
        finding = {
            "status": "affected",
            "advisory_id": "GHSA-test-test-test",
            "evidence": {"versions": ["1.0.0"]},
        }

        decisions = evaluate_exceptions(
            self.policy,
            ecosystem="Maven",
            package="org.example:library",
            advisory_id="GHSA-test-test-test",
            as_of=date(2026, 9, 30),
        )
        annotated = annotate_finding(finding, decisions)

        self.assertEqual(["active"], [item.state for item in decisions])
        self.assertEqual("affected", annotated["status"])
        self.assertEqual("affected", finding["status"])
        self.assertEqual("active", annotated["exceptions"][0]["state"])
        annotated["evidence"]["versions"].append("2.0.0")
        self.assertEqual(["1.0.0"], finding["evidence"]["versions"])

    def test_normalizes_outer_whitespace_in_exception_identity(self):
        decisions = evaluate_exceptions(
            self.policy,
            ecosystem=" Maven ",
            package=" org.example:library ",
            advisory_id=" GHSA-test-test-test ",
            as_of=date(2026, 9, 30),
        )

        self.assertEqual(["active"], [item.state for item in decisions])

    def test_preserves_case_sensitive_maven_package_identity(self):
        decisions = evaluate_exceptions(
            self.policy,
            ecosystem="Maven",
            package="ORG.Example:library",
            advisory_id="GHSA-test-test-test",
            as_of=date(2026, 9, 30),
        )

        self.assertEqual(["inapplicable"], [item.state for item in decisions])

    def test_preserves_malformed_preexisting_exceptions_instead_of_discarding(self):
        for preexisting in ("string", {"state": "active"}, 17, None):
            with self.subTest(preexisting=preexisting):
                finding = {
                    "status": "affected",
                    "advisory_id": "GHSA-test-test-test",
                    "exceptions": preexisting,
                }

                decisions = evaluate_exceptions(
                    self.policy,
                    ecosystem="Maven",
                    package="org.example:library",
                    advisory_id="GHSA-test-test-test",
                    as_of=date(2026, 9, 30),
                )
                annotated = annotate_finding(finding, decisions)

                self.assertEqual("affected", annotated["status"])
                self.assertEqual(
                    preexisting,
                    annotated["exceptions"][0],
                    "prior exception data must stay visible",
                )
                self.assertEqual(
                    "active", annotated["exceptions"][1]["state"]
                )

    def test_expired_exception_remains_visible(self):
        decisions = evaluate_exceptions(
            self.policy,
            ecosystem="Maven",
            package="org.example:library",
            advisory_id="GHSA-test-test-test",
            as_of=date(2026, 10, 1),
        )

        self.assertEqual(["expired"], [item.state for item in decisions])

    def test_inapplicable_exception_remains_visible(self):
        decisions = evaluate_exceptions(
            self.policy,
            ecosystem="Maven",
            package="org.example:other",
            advisory_id="GHSA-other-other-other",
            as_of=date(2026, 9, 30),
        )

        self.assertEqual(["inapplicable"], [item.state for item in decisions])


if __name__ == "__main__":
    unittest.main()
