"""Guard the no-build frontend's principal routes and DOM contracts."""
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "microplastic-monitor"


class IdCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.assets = []
        self.views = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if tag == "link" and attributes.get("rel") == "stylesheet":
            self.assets.append(attributes.get("href", ""))
        if tag == "script" and attributes.get("src") in {"app.js", "styles.css"}:
            self.assets.append(attributes["src"])
        if "data-view" in attributes:
            self.views.append(attributes["data-view"])


class FrontendStructureTests(unittest.TestCase):
    def test_exact_three_local_source_files_and_existing_views(self):
        self.assertEqual({p.name for p in FRONTEND.iterdir() if p.is_file()}, {"index.html", "styles.css", "app.js"})
        parser = IdCollector()
        parser.feed((FRONTEND / "index.html").read_text(encoding="utf-8"))
        self.assertEqual(len(parser.ids), len(set(parser.ids)), "HTML element IDs must be unique")
        for view in ("overview", "image-analysis", "live-analysis", "map", "analytics", "reports", "tests", "profile", "settings", "admin-command", "admin-customers", "admin-tests", "admin-regions", "admin-analytics", "admin-reports", "admin-profile", "admin-settings"):
            self.assertIn(view, parser.views)
        self.assertIn("styles.css", parser.assets)
        self.assertIn("app.js", parser.assets)

    def test_javascript_dom_references_resolve(self):
        parser = IdCollector(); parser.feed((FRONTEND / "index.html").read_text(encoding="utf-8"))
        script = (FRONTEND / "app.js").read_text(encoding="utf-8")
        referenced = set(re.findall(r'document\.getElementById\(["\']([^"\']+)["\']\)', script))
        missing = referenced - set(parser.ids)
        self.assertFalse(missing, f"JavaScript references missing HTML IDs: {sorted(missing)}")


if __name__ == "__main__":
    unittest.main()
