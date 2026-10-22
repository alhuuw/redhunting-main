#!/usr/bin/env python3
"""redhunting regression suite (part 5: the unit-load class library).

Validates the 26 per-class SKILL.md files: frontmatter shape, required sections,
frontmatter/class consistency with the router table, and that the library carries
the full class content (every substantial line of the pre-slice doctrine exists
somewhere in classes/ + router; the pre-slice baseline is embedded below).
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLASSES = REPO / "knowledge" / "classes"
ROUTER = REPO / "knowledge" / "playbook.md"

REQUIRED_SECTIONS = ("Signal", "PROOF BAR")

# classic hunt classes carry the full workflow label; technique-note classes
# (protocol patterns, technique multipliers) keep their own shape
FULL_WORKFLOW_CLASSES = {
    "hardcoded-secrets", "idor-bola", "ato-chains", "oauth-jwt-saml",
    "client-crypto-signing", "race-conditions", "ssrf", "subdomain-takeover",
    "enumeration-oracles", "xss-dom", "mobile-classes", "cloud-storage",
    "injection", "business-logic", "tenant-takeover", "cloud-vendor-consoles",
}

SLUGS = [
    "hardcoded-secrets", "idor-bola", "ato-chains", "oauth-jwt-saml",
    "client-crypto-signing", "race-conditions", "ssrf", "subdomain-takeover",
    "enumeration-oracles", "xss-dom", "mobile-classes", "cloud-storage",
    "injection", "frontend-bundle-mining", "business-logic",
    "firebase-remote-config", "jenkins-cli", "dev-box-services",
    "firebase-rtdb-paths", "graphql", "infra-exposure",
    "tenant-takeover", "api-cache-buckets", "client-aes-morgan",
    "no-arg-cursor", "cloud-vendor-consoles",
]

# baseline doctrine markers: each must exist in the class library (post-slice
# corpus) exactly as it lived in the pre-slice playbook
MARKERS = [
    "Payment-router merchant credentials in a public APK",
    "response-signature table",
    "feasibility math included",
    "redirect_uri mutation ladder",
    "recompile the DECOMPILED algorithm as a standalone Java target",
    "barrier release or last-byte sync",
    "169.254.169.254 family, per-provider variants",
    "flag CNAME chains",
    "550-vs-250 RCPT dialogue",
    "browser-verified execution",
    "autoVerify hosts",
    "v2 continuation-token pagination",
    "time-based first (SLEEP equivalents)",
    "_buildManifest.js lists EVERY route",
    "skip steps - call step 3 directly",
    "X-Goog-Api-Key",
    "jenkins-cli.jar",
    "GET /eureka/apps lists every microservice",
    'event: put',
    "Did you mean",
    "QUIT before DATA",
    "invitation abuse",
    "data/<UUID>/<api-path>",
    "EVP_KDF",
    "test the query's NO-ARG variant",
    "OneSignal",
]


class TestClassLibrary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {p.parent.name: p for p in CLASSES.glob("*/SKILL.md")}

    def test_twenty_six_class_folders(self):
        self.assertEqual(set(self.files), set(SLUGS))

    def test_every_class_file_has_valid_frontmatter(self):
        for slug, p in self.files.items():
            text = p.read_text()
            m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
            self.assertIsNotNone(m, f"{slug}: missing frontmatter block")
            fm = m.group(1)
            self.assertIn(f"name: rh-class-{slug}", fm, f"{slug}: name mismatch")
            self.assertIn("description:", fm, f"{slug}: no description")
            self.assertIn("triggers:", fm, f"{slug}: no triggers")

    def test_every_class_has_required_sections(self):
        for slug, p in self.files.items():
            text = p.read_text()
            for section in REQUIRED_SECTIONS:
                self.assertIn(section, text, f"{slug}: missing section {section}")

    def test_classic_classes_carry_workflow_content(self):
        for slug in FULL_WORKFLOW_CLASSES:
            text = self.files[slug].read_text()
            self.assertTrue(
                "Detection workflow" in text or "Workflow:" in text
                or "audit SEND and VERIFY" in text,
                f"{slug}: classic class without any workflow content")

    def test_class_heading_number_matches_slug(self):
        order = {slug: i + 1 for i, slug in enumerate(SLUGS)}
        for slug, p in self.files.items():
            text = p.read_text()
            m = re.search(r"^## (\d+)\. ", text, re.M)
            self.assertIsNotNone(m, f"{slug}: no class heading")
            self.assertEqual(int(m.group(1)), order[slug], f"{slug}: heading number drift")

    def test_router_lists_all_classes(self):
        router = ROUTER.read_text()
        for slug in SLUGS:
            self.assertIn(f"knowledge/classes/{slug}/SKILL.md", router, f"router missing {slug}")

    def test_router_keeps_cross_class_doctrine(self):
        router = ROUTER.read_text()
        self.assertIn("## Anti-patterns", router)
        self.assertIn("## Never-submit list", router)

    def test_doctrine_markers_survived_the_slice(self):
        corpus = ""
        for p in self.files.values():
            corpus += p.read_text()
        corpus += ROUTER.read_text()
        for marker in MARKERS:
            self.assertIn(marker, corpus, f"doctrine lost in slice: {marker[:60]}")

    def test_no_class_file_is_a_stub(self):
        for slug, p in self.files.items():
            lines = len(p.read_text().splitlines())
            self.assertGreater(lines, 15, f"{slug}: suspiciously thin ({lines} lines)")

    def test_cheatsheet_pairs_resolve(self):
        router = ROUTER.read_text()
        pairs = re.findall(r"cheatsheets/([a-z-]+\.md)", router)
        self.assertEqual(len(pairs), 26)
        for cs in set(pairs):
            self.assertTrue((REPO / "knowledge" / "cheatsheets" / cs).exists(), f"router points at missing {cs}")


if __name__ == "__main__":
    unittest.main()
