from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from archiveweaver.catalog import Catalog
from archiveweaver.catalog_source import catalog as source_catalog
from archiveweaver.json_utils import load_json_document
from archiveweaver.schema import validate_catalog


class CatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = Catalog()

    def test_requested_solution_count_and_names(self) -> None:
        self.assertEqual(len(self.catalog.solutions), 30)
        for solution_id in (
            "invenio-rdm", "dspace", "archivematica", "dataverse", "islandora", "mayan-edms",
            "fedora-repository", "samvera-hyrax", "roda-community", "maarch-rm", "asalae",
            "resourcespace", "maarch-courrier", "docspell", "nextcloud-server", "archivesspace",
            "atom", "alfresco-community", "eprints", "kitodo-production", "goobi-workflow",
            "collectiveaccess", "seeddms", "paperless-ngx", "omeka-s", "papermerge",
            "openkm-community", "teedy", "logicaldoc-community", "seafile-community",
        ):
            self.assertIn(solution_id, self.catalog.solutions)

    def test_catalog_schema(self) -> None:
        self.assertEqual(validate_catalog(self.catalog), [])

    def test_generated_catalog_exactly_matches_its_python_source(self) -> None:
        self.assertEqual(source_catalog(), self.catalog.data)

    def test_every_solution_declares_every_mode(self) -> None:
        for solution in self.catalog.solutions.values():
            self.assertEqual(set(solution["mode_support"]), set(self.catalog.runtimes))

    def test_catalog_rejects_malformed_solution_collections(self) -> None:
        self.catalog.solutions["paperless-ngx"]["dependencies"] = "PostgreSQL"
        errors = validate_catalog(self.catalog)
        self.assertIn("solution 'paperless-ngx' field 'dependencies' must be a list of non-empty strings", errors)

    def test_json_loader_rejects_duplicate_object_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            load_json_document('{"runtime": "raw", "runtime": "docker"}')

    def test_catalog_loader_rejects_ambiguous_or_malformed_indexes(self) -> None:
        with patch("archiveweaver.catalog._read", return_value=[]):
            with self.assertRaisesRegex(ValueError, "root must be an object"):
                Catalog()

        duplicate = copy.deepcopy(self.catalog.data)
        duplicate["solutions"].append(copy.deepcopy(duplicate["solutions"][0]))
        with patch("archiveweaver.catalog._read", return_value=duplicate):
            with self.assertRaisesRegex(ValueError, "duplicate id"):
                Catalog()

        malformed = copy.deepcopy(self.catalog.data)
        malformed["runtimes"] = ["not-an-object"]
        with patch("archiveweaver.catalog._read", return_value=malformed):
            with self.assertRaisesRegex(ValueError, "entry 0 must be an object"):
                Catalog()

        missing_id = copy.deepcopy(self.catalog.data)
        missing_id["operating_systems"][0]["id"] = ""
        with patch("archiveweaver.catalog._read", return_value=missing_id):
            with self.assertRaisesRegex(ValueError, "non-empty string id"):
                Catalog()

        malformed_formats = copy.deepcopy(self.catalog.data)
        malformed_formats["formats"] = []
        with patch("archiveweaver.catalog._read", return_value=malformed_formats):
            with self.assertRaisesRegex(ValueError, "formats must be an object"):
                Catalog()

    def test_schema_reports_malformed_solution_contracts_without_crashing(self) -> None:
        solution = self.catalog.solutions["paperless-ngx"]
        del solution["name"]
        solution["id"] = "different-id"
        solution["category"] = ""
        solution["license"] = 7
        solution["upstream_repo"] = 7
        solution["architecture_components"] = [""]
        solution["format_profiles"] = ["unknown-profile"]
        solution["mode_support"] = {"raw": "invalid", "unknown": "native"}
        solution["health"] = {
            "service_aliases": "service",
            "http_paths": ["health"],
            "checks": [7],
            "default_port": 70000,
        }
        errors = validate_catalog(self.catalog)
        combined = "\n".join(errors)
        self.assertIn("missing field 'name'", combined)
        self.assertIn("does not match catalog key", combined)
        self.assertIn("must be an http(s) URL", combined)
        self.assertIn("unknown format profile", combined)
        self.assertIn("invalid support level", combined)
        self.assertIn("missing mode support", combined)
        self.assertIn("unknown mode support", combined)
        self.assertIn("health.service_aliases", combined)
        self.assertIn("HTTP path must start", combined)
        self.assertIn("health.default_port", combined)

    def test_schema_reports_runtime_os_and_format_contract_violations(self) -> None:
        runtime = self.catalog.runtimes["raw"]
        runtime["id"] = "different-runtime"
        runtime["name"] = ""
        runtime["notes"] = 7
        runtime["prerequisites"] = "systemd"
        runtime["topology"] = {"1": "invalid", "unexpected": "supported"}
        runtime["kind"] = "unknown"

        operating_system = self.catalog.operating_systems["ubuntu-24.04"]
        operating_system["id"] = "different-os"
        operating_system["name"] = ""
        operating_system["family"] = 7
        operating_system["tier"] = "unknown"

        format_profile = self.catalog.formats["documents"]
        format_profile["label"] = ""
        format_profile["extensions"] = []
        format_profile["mime_examples"] = None

        errors = "\n".join(validate_catalog(self.catalog))
        self.assertIn("runtime 'different-runtime' id does not match", errors)
        self.assertIn("invalid topology level", errors)
        self.assertIn("missing topology bucket", errors)
        self.assertIn("unknown topology bucket", errors)
        self.assertIn("unknown kind", errors)
        self.assertIn("operating system 'different-os' id does not match", errors)
        self.assertIn("unknown support tier", errors)
        self.assertIn("format profile 'documents' field 'label'", errors)

    def test_schema_rejects_non_object_nested_contracts(self) -> None:
        solution = self.catalog.solutions["paperless-ngx"]
        solution["mode_support"] = []
        solution["health"] = []
        self.catalog.runtimes["raw"]["topology"] = []

        errors = "\n".join(validate_catalog(self.catalog))
        self.assertIn("field 'mode_support' must be an object", errors)
        self.assertIn("field 'health' must be an object", errors)
        self.assertIn("field 'topology' must be an object", errors)
        self.assertIn("missing mode support for 'raw'", errors)
        self.assertIn("missing topology bucket '1'", errors)

