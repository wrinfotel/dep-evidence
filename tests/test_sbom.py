import json
import tempfile
import unittest
from pathlib import Path

from dep_evidence.errors import InputError
from dep_evidence.sbom import parse_sbom


class SbomParserTests(unittest.TestCase):
    def make_sbom(self, *, spec_version="1.6", component_count=2):
        components = []
        for index in range(component_count):
            ref = f"pkg:maven/org.example/component-{index}@1.0.0?type=jar"
            components.append(
                {
                    "type": "library",
                    "bom-ref": ref,
                    "group": "org.example",
                    "name": f"component-{index}",
                    "version": "1.0.0",
                    "purl": ref,
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                }
            )
        return {
            "bomFormat": "CycloneDX",
            "specVersion": spec_version,
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "bom-ref": "root",
                    "name": "demo",
                    "version": "1.0.0",
                }
            },
            "components": components,
            "dependencies": [
                {"ref": "root", "dependsOn": [components[0]["bom-ref"]]},
            ],
        }

    def write_sbom(self, document):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "bom.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_parses_maven_components_and_dependency_relationships(self):
        path = self.write_sbom(self.make_sbom())

        result = parse_sbom(path)

        self.assertEqual(2, len(result.components))
        self.assertEqual("Maven", result.components[0].ecosystem)
        self.assertEqual("org.example", result.components[0].namespace)
        self.assertEqual("component-0", result.components[0].name)
        self.assertEqual("1.0.0", result.components[0].version)
        self.assertEqual("direct", result.components[0].relationship)
        self.assertEqual("transitive", result.components[1].relationship)
        self.assertEqual("Apache-2.0", result.components[0].licenses[0]["id"])

    def test_decodes_purl_coordinates_and_preserves_metadata(self):
        document = self.make_sbom(component_count=1)
        document["components"][0]["purl"] = (
            "pkg:maven/org.example.deep/A%20Demo%20Artifact@1.0.0?type=jar"
        )
        path = self.write_sbom(document)

        result = parse_sbom(path)

        component = result.components[0]
        self.assertEqual("org.example.deep", component.namespace)
        self.assertEqual("A Demo Artifact", component.name)
        self.assertEqual("1.0.0", component.version)
        self.assertEqual("jar", component.purl_qualifiers["type"])
        self.assertEqual(
            "pkg:maven/org.example/component-0@1.0.0?type=jar",
            component.bom_ref,
        )

    def test_marks_relationship_unknown_without_root_graph(self):
        document = self.make_sbom(component_count=1)
        document["metadata"]["component"].pop("bom-ref")
        document["dependencies"] = []
        path = self.write_sbom(document)

        result = parse_sbom(path)

        self.assertEqual("unknown", result.components[0].relationship)

    def test_rejects_unsupported_schema_version(self):
        path = self.write_sbom(self.make_sbom(spec_version="2.0"))

        with self.assertRaises(InputError) as context:
            parse_sbom(path)
        self.assertRegex(str(context.exception), "specVersion")

    def test_rejects_more_than_two_thousand_components(self):
        path = self.write_sbom(self.make_sbom(component_count=2001))

        with self.assertRaises(InputError) as context:
            parse_sbom(path)
        self.assertRegex(str(context.exception), "2000")

    def test_rejects_malformed_json(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "bad.json"
        path.write_text("{bad", encoding="utf-8")

        with self.assertRaises(InputError) as context:
            parse_sbom(path)
        self.assertRegex(str(context.exception), "valid JSON")


if __name__ == "__main__":
    unittest.main()
