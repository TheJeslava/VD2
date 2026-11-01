from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
sys.path.insert(0, str(PROJECT))

from sunset.awvs import _map_type, parse_report
from sunset.baofeng import BAOFENG_CATEGORIES, BY_SAMPLE, build_manifest
from sunset.awvs_local import scan_target


class TestBaofengVer5(unittest.TestCase):
    def test_manifest_has_all_gold_categories_and_samples(self):
        manifest = build_manifest()
        self.assertEqual(manifest["category_count"], 20)
        self.assertEqual(manifest["count"], 58)
        self.assertEqual(set(BY_SAMPLE), {f"{n:03d}" for n in range(1, 59)})
        self.assertEqual({item["dataset_category"] for item in manifest["targets"]}, {item.key for item in BAOFENG_CATEGORIES})
        self.assertTrue(all(item.get("metadata_only") is True for item in manifest["targets"]))
        self.assertTrue(all("static_evidence" not in item for item in manifest["targets"]))

    def test_awvs_mapping_covers_ver5_categories(self):
        self.assertEqual(_map_type("Blind SQL Injection", "CWE-89"), "blind_sql_injection")
        self.assertEqual(_map_type("Second-order SQL Injection", "CWE-89"), "second_order_injection")
        self.assertEqual(_map_type("API Information Disclosure", "CWE-200"), "api_info_disclosure")
        self.assertEqual(_map_type("Content Security Policy Misconfiguration", "CWE-693"), "csp")
        self.assertEqual(_map_type("Brute Force Protection Missing", "307"), "brute_force")

    def test_parse_report_preserves_awvs_insertion_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps({"vulnerabilities": [{
                "name": "Blind SQL Injection", "url": "http://TARGET/058.php",
                "cwe": "CWE-89", "channel": "cookie", "parameter": "id",
                "payload": "1' AND '1'='2", "method": "GET", "evidence": "length differential",
            }]}), encoding="utf-8")
            item = parse_report(path)[0]
            self.assertEqual(item.channel, "cookie")
            self.assertEqual(item.parameter, "id")
            self.assertEqual(item.payload, "1' AND '1'='2")
            self.assertEqual(item.method, "GET")

    def test_local_probe_does_not_fabricate_from_manifest_metadata(self):
        target = build_manifest("http://127.0.0.1:1")["targets"][0]
        target["url"] = "http://127.0.0.1:1/does-not-exist.php"
        target["static_evidence"] = "legacy manifest text must not become a finding"
        self.assertEqual(scan_target(target, timeout=0.2), [])

    def test_brute_force_probe_rejects_missing_route(self):
        target = next(item for item in build_manifest("http://127.0.0.1:1")["targets"]
                      if item["dataset_category"] == "brute")
        target["url"] = "http://127.0.0.1:1/does-not-exist.php"
        self.assertEqual(scan_target(target, timeout=0.2), [])


if __name__ == "__main__":
    unittest.main()
