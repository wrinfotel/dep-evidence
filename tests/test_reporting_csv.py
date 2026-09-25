"""RED slice for the deterministic components.csv inventory writer.

Note: the design defines components.csv as the *component inventory*, not a
findings table. Findings live in evidence.json and report.html.
"""

import csv
import io
import unittest


class RenderComponentsCsvTests(unittest.TestCase):
    def setUp(self):
        from dep_evidence.model import Component

        self.components = [
            Component(
                ecosystem="maven",
                namespace="org.springframework",
                name="spring-core",
                version="6.1.0",
                purl="pkg:maven/org.springframework/spring-core@6.1.0",
                bom_ref="pkg:maven/org.springframework/spring-core@6.1.0",
                relationship="direct",
                licenses=({"name": "Apache-2.0", "source": "sbom"},),
            ),
            Component(
                ecosystem="maven",
                namespace="com.acme",
                name="internal-lib",
                version="1.0.0",
                relationship="transitive",
            ),
        ]

    def render(self, components=None):
        from dep_evidence.reporting import render_components_csv

        return render_components_csv(
            self.components if components is None else components
        )

    def test_header_is_stable(self):
        header = self.render().decode("utf-8").splitlines()[0]
        self.assertEqual(
            "ecosystem,namespace,name,version,coordinate,purl,bom_ref,"
            "relationship,licenses,license_state",
            header,
        )

    def test_rows_round_trip(self):
        parsed = list(csv.DictReader(io.StringIO(self.render().decode("utf-8"))))
        self.assertEqual(2, len(parsed))
        self.assertEqual("org.springframework", parsed[0]["namespace"])
        self.assertEqual("maven:org.springframework:spring-core@6.1.0", parsed[0]["coordinate"])
        self.assertEqual("direct", parsed[0]["relationship"])
        self.assertEqual("pkg:maven/org.springframework/spring-core@6.1.0", parsed[0]["purl"])

    def test_missing_license_is_explicitly_unknown(self):
        # Design: missing or conflicting license data is `unknown`, never a
        # silently empty cell.
        parsed = list(csv.DictReader(io.StringIO(self.render().decode("utf-8"))))
        self.assertEqual("unknown", parsed[1]["license_state"])
        # The design requires preserving the license source, so the cell
        # carries both the name and where it came from.
        self.assertEqual("Apache-2.0 (sbom)", parsed[0]["licenses"])
        self.assertEqual("known", parsed[0]["license_state"])

    def test_license_source_is_preserved(self):
        parsed = list(csv.DictReader(io.StringIO(self.render().decode("utf-8"))))
        self.assertIn("sbom", parsed[0]["licenses"])

    def test_output_is_deterministic(self):
        self.assertEqual(self.render(), self.render())

    def test_formula_injection_is_neutralized(self):
        from dep_evidence.model import Component

        payload = [
            Component(
                ecosystem="maven",
                namespace="=cmd|'/c calc'!A1",
                name="+1",
                version="@SUM(A1)",
            )
        ]
        parsed = list(csv.DictReader(io.StringIO(self.render(payload).decode("utf-8"))))
        for column in ("namespace", "name", "version"):
            self.assertTrue(
                parsed[0][column].startswith("'"),
                f"{column} not neutralized: {parsed[0][column]!r}",
            )

    def test_empty_inventory_still_renders_a_header(self):
        text = self.render([]).decode("utf-8")
        self.assertEqual(1, len(text.strip().splitlines()))


if __name__ == "__main__":
    unittest.main()
