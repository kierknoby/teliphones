"""Check internal Markdown links in the repository and in the Module Admin package.

External URLs are not fetched. Every relative link, image, reference definition,
HTML href/src and Mermaid click target must resolve to an existing file, and any
fragment pointing at a Markdown file must match a heading anchor. Packaged module
documentation must also resolve entirely inside the extracted package.
"""

from pathlib import Path, PurePosixPath
import os
import re
import tarfile
import tempfile
import unittest
import unicodedata
from urllib.parse import unquote
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "teliphones"
VERSION = ET.parse(MODULE / "module.xml").findtext("version")
PACKAGE = ROOT / ("TELIPHONES-%s.tgz" % VERSION)
SKIP_DIRS = {".git", "node_modules", "build", "out", "__pycache__"}

FENCE = re.compile(r"^\s*(`{3,}|~{3,})\s*([\w-]*)")
INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*(<[^>]*>|[^\s)]+)(?:\s+[\"'(][^)]*)?\)")
REFERENCE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]*>|\S+)")
HTML = re.compile(r"""\b(?:href|src)\s*=\s*["']([^"']+)["']""", re.I)
MERMAID_CLICK = re.compile(r"""^\s*click\s+\S+\s+(?:href\s+)?["']([^"']+)["']""")
HTML_ANCHOR = re.compile(r"""<a\s+[^>]*(?:id|name)\s*=\s*["']([^"']+)["']""", re.I)
CODE_SPAN = re.compile(r"(`+)(?:(?!\1).)+\1")
EXTERNAL = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)


def slug(heading):
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading.strip()).replace("`", "").lower()
    text = "".join(c for c in text if c in " -_" or unicodedata.category(c)[0] in "LN")
    return text.replace(" ", "-")


def scan(path):
    """Return (links, anchors) for a Markdown file; links are (line, target)."""
    links, anchors, seen = [], set(), {}
    fence, lang = None, ""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        opened = FENCE.match(line)
        if fence:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence) and not opened.group(2):
                fence = None
            elif lang == "mermaid":
                links += [(number, m.group(1)) for m in MERMAID_CLICK.finditer(line)]
            continue
        if opened:
            fence, lang = opened.group(1), opened.group(2).lower()
            continue
        anchors.update(m.group(1) for m in HTML_ANCHOR.finditer(line))
        heading = re.match(r"^\s{0,3}(#{1,6})\s+(.*?)(?:\s+#+)?\s*$", line)
        if heading:
            base = slug(heading.group(2))
            count = seen.get(base, 0)
            seen[base] = count + 1
            anchors.add(base if count == 0 else "%s-%d" % (base, count))
        text = CODE_SPAN.sub("", line)
        for pattern in (INLINE, REFERENCE, HTML):
            links += [(number, m.group(1).strip("<>")) for m in pattern.finditer(text)]
    if fence:
        raise AssertionError("%s: unterminated code fence" % path)
    return links, anchors


def markdown_files(base):
    for directory, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name.lower().endswith(".md"):
                yield Path(directory) / name


def check_tree(base, files, boundary=None):
    """Return (checked, problems) for internal links in files under base."""
    cache, checked, problems = {}, 0, []

    def anchors_of(path):
        if path not in cache:
            cache[path] = scan(path)[1]
        return cache[path]

    for source in files:
        links, own = scan(source)
        cache[source] = own
        for line, target in links:
            if EXTERNAL.match(target) or target.startswith("//"):
                continue
            checked += 1
            where = "%s:%d -> %s" % (source.relative_to(base).as_posix(), line, target)
            file_part, _, fragment = target.partition("#")
            if file_part.startswith("/"):
                problems.append(where + " (absolute paths do not resolve on GitHub or in the package)")
                continue
            resolved = Path(os.path.normpath(source.parent / unquote(file_part))) if file_part else source
            limit = boundary or base
            if resolved != limit and limit not in resolved.parents:
                problems.append(where + " (outside %s)" % limit.relative_to(base).as_posix())
            elif not resolved.exists():
                problems.append(where + " (missing)")
            elif fragment and resolved.suffix.lower() == ".md" and unquote(fragment) not in anchors_of(resolved):
                problems.append(where + " (no such anchor)")
    return checked, problems


def packaged(path):
    parts = path.relative_to(MODULE).parts
    return not any(part.startswith(".") or part in ("tests", "__pycache__") for part in parts)


class DocumentationLinkTests(unittest.TestCase):
    maxDiff = None

    def test_slugs_follow_github_rules(self):
        self.assertEqual(slug("0.2.1, firewall enforcement and lifecycle security"), "021-firewall-enforcement-and-lifecycle-security")
        self.assertEqual(slug("Install from an `unpacked` module directory"), "install-from-an-unpacked-module-directory")
        self.assertEqual(slug("AI-Assisted Contributions and Disclosure"), "ai-assisted-contributions-and-disclosure")

    def test_checker_detects_broken_links(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "pkg").mkdir()
            (base / "pkg/a.md").write_text(
                "# Title\n[ok](#title) [bad](#nope) [gone](b.md) [out](../c.md)\n| [cell](a.md#title) |\n"
                "`[code](x.md)`\n```mermaid\nflowchart LR\n  click A \"d.md\"\n```\n```bash\n[x](y.md)\n```\n",
                encoding="utf-8")
            (base / "c.md").write_text("# C\n", encoding="utf-8")
            checked, problems = check_tree(base, [base / "pkg/a.md"], boundary=base / "pkg")
            self.assertEqual(checked, 6)
            self.assertEqual([p.split(" -> ")[1] for p in problems], ["#nope (no such anchor)", "b.md (missing)", "../c.md (outside pkg)", "d.md (missing)"])

    def test_repository_links_resolve(self):
        checked, problems = check_tree(ROOT, list(markdown_files(ROOT)))
        self.assertGreater(checked, 100)
        self.assertEqual(problems, [], "Broken repository documentation links:\n" + "\n".join(problems))

    def test_packaged_source_links_stay_inside_module(self):
        files = [path for path in markdown_files(MODULE) if packaged(path)]
        self.assertIn(MODULE / "README.md", files)
        checked, problems = check_tree(ROOT, files, boundary=MODULE)
        self.assertGreater(checked, 20)
        self.assertEqual(problems, [], "Packaged documentation links leaving the module:\n" + "\n".join(problems))
        for path in files:
            self.assertTrue(packaged(path))

    @unittest.skipUnless(PACKAGE.exists(), "%s has not been built" % PACKAGE.name)
    def test_extracted_package_links_resolve(self):
        with tempfile.TemporaryDirectory() as directory, tarfile.open(PACKAGE, "r:gz") as archive:
            archive.extractall(directory, filter="data")
            base = Path(directory).resolve()
            module = base / "teliphones"
            files = list(markdown_files(module))
            self.assertIn(module / "README.md", files)
            checked, problems = check_tree(base, files, boundary=module)
            self.assertGreater(checked, 20)
            self.assertEqual(problems, [], "Broken links in %s:\n%s" % (PACKAGE.name, "\n".join(problems)))


if __name__ == "__main__":
    unittest.main()
