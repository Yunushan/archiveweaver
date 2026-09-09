from __future__ import annotations

import unittest

from archiveweaver.catalog import Catalog
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

