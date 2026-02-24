"""Comprehensive PyYAML security tests for the Na0S project.

Tests 7+ security theories about yaml.safe_load() usage in:
  - scripts/safe_yaml.py          (safe_load_yaml helper -- the hardened wrapper)
  - scripts/taxonomy/_base.py     (calls safe_load_yaml with path-containment
                                    and schema validation)
  - scripts/sync_datasets.py      (calls safe_load_yaml at line 158)

NOTE: The production code has already migrated from raw yaml.safe_load() to
safe_load_yaml() (scripts/safe_yaml.py), which adds:
  - File-size limit (10 MB by default) -- blocks billion-laughs bombs on disk
  - Path-existence check
  - Explicit UTF-8-SIG encoding (BOM-safe)
  - Clean error wrapping

The taxonomy loader (_base.py) additionally enforces:
  - Path-containment: TAXONOMY_YAML_PATH must resolve within data/
  - Schema validation: each category must be a dict with a 'name' key

These tests verify both the raw yaml.safe_load() guarantees AND the additional
controls layered on by safe_load_yaml() and _load_taxonomy().

Run with:
    python3 -m unittest tests.test_safe_yaml -v
"""

import os
import sys
import io
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path

# ── Project path bootstrap ──────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import yaml


# ===========================================================================
# Theory 1 — yaml.safe_load blocks malicious YAML tags
# ===========================================================================

class TestSafeLoadBlocksMaliciousTags(unittest.TestCase):
    """safe_load() must raise ConstructorError for all !!python/* tags.

    This verifies the primary security guarantee of PyYAML's safe loader.
    Any regression here means arbitrary code execution on the server.
    """

    def _assert_constructor_error(self, payload, description):
        with self.assertRaises(yaml.constructor.ConstructorError,
                               msg=f"Expected ConstructorError for: {description}"):
            yaml.safe_load(payload)

    def test_python_object_apply_os_system(self):
        """!!python/object/apply:os.system must be rejected."""
        self._assert_constructor_error(
            "!!python/object/apply:os.system ['echo pwned']",
            "!!python/object/apply:os.system"
        )

    def test_python_object_os_system(self):
        """!!python/object:os.system must be rejected."""
        self._assert_constructor_error(
            "!!python/object:os.system\nargs: ['echo pwned']",
            "!!python/object:os.system"
        )

    def test_python_object_new_subprocess(self):
        """!!python/object/new:subprocess.check_output must be rejected."""
        self._assert_constructor_error(
            "!!python/object/new:subprocess.check_output\nargs: [['id']]",
            "!!python/object/new:subprocess.check_output"
        )

    def test_python_object_new_eval(self):
        """!!python/object/new:builtins.eval must be rejected."""
        self._assert_constructor_error(
            "!!python/object/new:builtins.eval\nargs: ['__import__(\"os\").getcwd()']",
            "!!python/object/new:builtins.eval"
        )

    def test_python_name_os_system(self):
        """!!python/name:os.system must be rejected (resolves to function reference)."""
        self._assert_constructor_error(
            "!!python/name:os.system",
            "!!python/name:os.system"
        )

    def test_python_module_os(self):
        """!!python/module:os must be rejected."""
        self._assert_constructor_error(
            "!!python/module:os",
            "!!python/module:os"
        )

    def test_python_object_apply_subprocess_popen(self):
        """!!python/object/apply:subprocess.Popen must be rejected."""
        self._assert_constructor_error(
            "!!python/object/apply:subprocess.Popen\nargs: [['cat', '/etc/passwd']]",
            "!!python/object/apply:subprocess.Popen"
        )

    def test_python_object_apply_eval(self):
        """!!python/object/apply:builtins.eval must be rejected."""
        self._assert_constructor_error(
            "!!python/object/apply:builtins.eval ['__import__(\"os\").getcwd()']",
            "!!python/object/apply:builtins.eval"
        )

    def test_safe_scalar_types_still_load(self):
        """Regression: normal YAML types must still parse after tag tests."""
        data = yaml.safe_load("key: value\nlist: [1, 2, 3]\nbool: true")
        self.assertEqual(data["key"], "value")
        self.assertEqual(data["list"], [1, 2, 3])
        self.assertTrue(data["bool"])

    def test_safe_load_nested_tags(self):
        """Nested malicious tags must also be rejected."""
        payload = (
            "outer:\n"
            "  inner: !!python/object/apply:os.getcwd []\n"
        )
        self._assert_constructor_error(payload, "nested !!python/object/apply")

    def test_yaml_tag_in_value_string_is_safe(self):
        """A !!python tag embedded as a quoted string value must be safe."""
        data = yaml.safe_load('key: "!!python/object/apply:os.system"')
        self.assertEqual(data["key"], "!!python/object/apply:os.system")

    def test_safe_load_yaml_wrapper_also_blocks_tags(self):
        """safe_load_yaml() from scripts/safe_yaml.py also rejects !!python/* tags."""
        from scripts.safe_yaml import safe_load_yaml

        payload = "!!python/object/apply:os.system ['echo pwned']"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False) as f:
            f.write(payload)
            tmp = f.name
        try:
            with self.assertRaises(ValueError,
                                   msg="safe_load_yaml must raise ValueError for !!python tags"):
                safe_load_yaml(tmp)
        finally:
            os.unlink(tmp)


# ===========================================================================
# Theory 2 — Billion Laughs (YAML bomb) resistance
# ===========================================================================

class TestBillionLaughsResistance(unittest.TestCase):
    """PyYAML safe_load() with anchor/alias expansion (YAML bomb).

    yaml.safe_load() does NOT protect against alias expansion by default.
    However, safe_load_yaml() adds a FILE SIZE LIMIT (10 MB) which catches
    disk-based YAML bombs. In-memory bombs (generated strings) are not
    covered.
    """

    MEMORY_THRESHOLD_MB = 200

    def _build_yaml_bomb(self, depth=4, width=5):
        """Build a YAML bomb of given depth and width.

        depth=4, width=5 -> 5^4 = 625 items.
        depth=7, width=5 -> 5^7 = 78,125 items.
        """
        lol_items = ", ".join(["lol"] * width)
        lines = ["a: &a [{}]".format(lol_items)]
        prev = "a"
        for level in "bcdefghi"[:depth - 1]:
            refs = ", ".join(["*{}".format(prev)] * width)
            lines.append("{}: &{} [{}]".format(level, level, refs))
            prev = level
        return "\n".join(lines)

    def test_shallow_bomb_loads_cleanly(self):
        """A 4-level bomb (625 items) loads without crashing."""
        bomb = self._build_yaml_bomb(depth=4, width=5)
        data = yaml.safe_load(bomb)
        self.assertIsInstance(data, dict)

    def test_moderate_bomb_memory_impact(self):
        """A 6-level bomb (15,625 items) — measure memory use."""
        bomb = self._build_yaml_bomb(depth=6, width=5)

        tracemalloc.start()
        snap_before = tracemalloc.take_snapshot()
        data = yaml.safe_load(bomb)
        snap_after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snap_after.compare_to(snap_before, 'lineno')
        total_mb = sum(s.size_diff for s in stats) / (1024 * 1024)

        if total_mb > self.MEMORY_THRESHOLD_MB:
            self.fail(
                f"YAML bomb memory use {total_mb:.1f} MB exceeds threshold "
                f"{self.MEMORY_THRESHOLD_MB} MB. "
                "yaml.safe_load has no alias expansion limit built in."
            )

    def test_safe_load_yaml_file_size_limit_blocks_disk_bomb(self):
        """safe_load_yaml() size limit blocks a large YAML file on disk.

        A YAML bomb written to disk that exceeds 10 MB will be rejected by
        safe_load_yaml() BEFORE parsing begins — so no memory explosion.
        """
        from scripts.safe_yaml import safe_load_yaml

        # Write a 10.1 MB YAML file (trivially — just a big string value)
        big_content = "key: '" + "x" * (10 * 1024 * 1024 + 100) + "'\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False, encoding="utf-8") as f:
            f.write(big_content)
            tmp = f.name
        try:
            with self.assertRaises(ValueError,
                                   msg="safe_load_yaml must reject files > 10 MB"):
                safe_load_yaml(tmp)
        finally:
            os.unlink(tmp)

    def test_safe_load_yaml_size_limit_is_10mb(self):
        """Default size limit in safe_load_yaml is 10 MB (10 * 1024 * 1024)."""
        from scripts import safe_yaml
        self.assertEqual(safe_yaml._DEFAULT_MAX_SIZE, 10 * 1024 * 1024)

    def test_safe_load_yaml_size_limit_can_be_disabled(self):
        """max_size_bytes=0 disables the size check (for tests/benchmarks)."""
        from scripts.safe_yaml import safe_load_yaml

        big_content = "key: '" + "x" * (11 * 1024 * 1024) + "'\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False, encoding="utf-8") as f:
            f.write(big_content)
            tmp = f.name
        try:
            # max_size_bytes=0 disables the limit — should not raise ValueError
            data = safe_load_yaml(tmp, max_size_bytes=0)
            self.assertIn("key", data)
        finally:
            os.unlink(tmp)

    def test_self_referential_anchor_behavior(self):
        """A self-referential anchor: document behavior (no assertion)."""
        payload = "a: &a *a"  # self-referential
        try:
            data = yaml.safe_load(payload)
        except (yaml.YAMLError, RecursionError, ValueError):
            pass  # Any error is acceptable


# ===========================================================================
# Theory 3 — Large file DoS
# ===========================================================================

class TestLargeFileDoS(unittest.TestCase):
    """Test behavior when feeding large YAML content to safe_load.

    The safe_load_yaml() wrapper rejects files > 10 MB before parsing.
    This prevents OOM from large files on disk. In-memory strings have no
    such guard.
    """

    def _build_large_yaml(self, num_keys):
        lines = [f"key_{i}: value_{i}" for i in range(num_keys)]
        return "\n".join(lines)

    def test_10k_key_yaml_loads(self):
        """10,000-key YAML dict should load without error."""
        content = self._build_large_yaml(10_000)
        data = yaml.safe_load(content)
        self.assertEqual(len(data), 10_000)

    def test_100k_key_yaml_memory_bound(self):
        """100,000-key YAML should not consume unbounded memory."""
        content = self._build_large_yaml(100_000)
        tracemalloc.start()
        snap_before = tracemalloc.take_snapshot()
        data = yaml.safe_load(content)
        snap_after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snap_after.compare_to(snap_before, 'lineno')
        total_mb = sum(s.size_diff for s in stats) / (1024 * 1024)

        self.assertLess(
            total_mb, 100,
            f"Loading 100k-key YAML consumed {total_mb:.1f} MB — unexpectedly high"
        )
        self.assertEqual(len(data), 100_000)

    def test_large_string_value_parses(self):
        """YAML with a 1 MB string value should parse cleanly (in-memory)."""
        big_str = "x" * (1024 * 1024)
        content = f"key: '{big_str}'"
        data = yaml.safe_load(content)
        self.assertEqual(len(data["key"]), 1024 * 1024)

    def test_deeply_nested_structure(self):
        """Deep nesting (500 levels) — document behavior."""
        content = "a:\n" + "  a:\n" * 500
        try:
            data = yaml.safe_load(content)
        except RecursionError:
            pass  # Acceptable
        except yaml.YAMLError:
            pass  # Also acceptable

    def test_safe_load_yaml_rejects_10mb_plus_file(self):
        """safe_load_yaml raises ValueError when file > 10 MB."""
        from scripts.safe_yaml import safe_load_yaml

        # Create an 11 MB file
        content = "key: '" + ("a" * 1000 + "\n") * 11_000 + "'\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp = f.name
        try:
            with self.assertRaises(ValueError) as ctx:
                safe_load_yaml(tmp)
            self.assertIn("too large", str(ctx.exception))
        finally:
            os.unlink(tmp)

    def test_safe_load_yaml_allows_9mb_file(self):
        """safe_load_yaml accepts files just under 10 MB."""
        from scripts.safe_yaml import safe_load_yaml

        # Build a valid YAML file that stays under 10 MB.
        # "k_NNNN: v_NNNN\n" is about 16 bytes; 600k lines = ~9.6 MB.
        # Use a short prefix to stay safely under 10 MB.
        lines = [f"k{i}: v{i}" for i in range(500_000)]
        content = "\n".join(lines)
        # Sanity check it's under 10 MB
        content_bytes = content.encode("utf-8")
        self.assertLess(len(content_bytes), 10 * 1024 * 1024)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp = f.name
        try:
            data = safe_load_yaml(tmp)
            self.assertIsNotNone(data)
        finally:
            os.unlink(tmp)

    def test_file_handle_load_matches_string_load(self):
        """Loading from a file handle matches loading from a string."""
        content = self._build_large_yaml(1_000)
        expected = yaml.safe_load(content)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp = f.name
        try:
            with open(tmp, "r", encoding="utf-8") as fh:
                actual = yaml.safe_load(fh)
            self.assertEqual(actual, expected)
        finally:
            os.unlink(tmp)


# ===========================================================================
# Theory 4 — Unicode BOM handling
# ===========================================================================

class TestUnicodeBOMHandling(unittest.TestCase):
    """Test YAML loading with various Unicode BOMs.

    Production code in safe_load_yaml() uses encoding='utf-8-sig' which
    automatically strips the UTF-8 BOM on read, ensuring clean parsing.
    """

    MINIMAL_YAML = "key: value\nother: 42\n"

    def test_utf8_no_bom_loads_correctly(self):
        """Plain UTF-8 YAML loads correctly."""
        data = yaml.safe_load(self.MINIMAL_YAML)
        self.assertEqual(data["key"], "value")

    def test_utf8_bom_in_string_loads_or_errors_cleanly(self):
        """UTF-8 BOM as Unicode char at start — PyYAML handles it."""
        bom = "\ufeff"
        content = bom + self.MINIMAL_YAML
        try:
            data = yaml.safe_load(content)
            # If it loads, BOM must not corrupt the first key
            self.assertIn("key", data)
        except yaml.YAMLError:
            pass  # Clean parse error is safe behavior

    def test_utf8_bom_from_file_utf8_encoding(self):
        """File with UTF-8 BOM bytes opened with encoding='utf-8'.

        Python's utf-8 codec passes through the BOM as \ufeff.
        PyYAML's YAML 1.1 BOM handling should absorb it.
        """
        bom_bytes = b"\xef\xbb\xbf"
        yaml_bytes = self.MINIMAL_YAML.encode("utf-8")

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            f.write(bom_bytes + yaml_bytes)
            tmp = f.name

        try:
            with open(tmp, "r", encoding="utf-8") as fh:
                raw = fh.read()

            if raw.startswith("\ufeff"):
                # BOM present — try loading, PyYAML may handle it
                try:
                    data = yaml.safe_load(raw)
                    if isinstance(data, dict):
                        self.assertIn("key", data)
                except yaml.YAMLError:
                    pass  # Clean failure is acceptable
            else:
                # Codec already stripped the BOM
                data = yaml.safe_load(raw)
                self.assertIn("key", data)
        finally:
            os.unlink(tmp)

    def test_utf8_bom_from_file_utf8sig_encoding(self):
        """Using encoding='utf-8-sig' correctly strips BOM on read."""
        bom_bytes = b"\xef\xbb\xbf"
        yaml_bytes = self.MINIMAL_YAML.encode("utf-8")

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            f.write(bom_bytes + yaml_bytes)
            tmp = f.name

        try:
            with open(tmp, "r", encoding="utf-8-sig") as fh:
                data = yaml.safe_load(fh)
            self.assertIsNotNone(data)
            self.assertIn("key", data)
        finally:
            os.unlink(tmp)

    def test_utf16_be_bom_raises_unicode_decode_error(self):
        """UTF-16 BE file opened as UTF-8 raises UnicodeDecodeError.

        safe_load_yaml() wraps this as ValueError. Verified by _base.py's
        except clause (now delegated to safe_load_yaml).
        """
        yaml_utf16 = self.MINIMAL_YAML.encode("utf-16-be")
        bom = b"\xfe\xff"

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            f.write(bom + yaml_utf16)
            tmp = f.name

        try:
            with self.assertRaises(UnicodeDecodeError):
                with open(tmp, "r", encoding="utf-8") as fh:
                    fh.read()
        finally:
            os.unlink(tmp)

    def test_utf16_le_bom_raises_unicode_decode_error(self):
        """UTF-16 LE file opened as UTF-8 raises UnicodeDecodeError."""
        yaml_utf16 = self.MINIMAL_YAML.encode("utf-16-le")
        bom = b"\xff\xfe"

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            f.write(bom + yaml_utf16)
            tmp = f.name

        try:
            with self.assertRaises(UnicodeDecodeError):
                with open(tmp, "r", encoding="utf-8") as fh:
                    fh.read()
        finally:
            os.unlink(tmp)

    def test_safe_load_yaml_wraps_unicode_error_as_value_error(self):
        """safe_load_yaml() wraps UnicodeDecodeError as ValueError."""
        from scripts.safe_yaml import safe_load_yaml

        bom = b"\xfe\xff"
        bad_utf16 = self.MINIMAL_YAML.encode("utf-16-be")

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            f.write(bom + bad_utf16)
            tmp = f.name

        try:
            with self.assertRaises(ValueError) as ctx:
                safe_load_yaml(tmp)
            self.assertIn("Non-UTF-8", str(ctx.exception))
        finally:
            os.unlink(tmp)

    def test_null_bytes_in_yaml(self):
        """YAML content with embedded null bytes — document behavior."""
        payload = "key: val\x00ue"
        try:
            data = yaml.safe_load(payload)
            # If it loads silently, the null byte handling should be noted
        except (yaml.YAMLError, ValueError):
            pass  # Clean error is the safe outcome


# ===========================================================================
# Theory 5 — Taxonomy test import chain / pyproject.toml PyYAML dep
# ===========================================================================

class TestTaxonomyImportChain(unittest.TestCase):
    """Verify that PyYAML is importable and version constraints are satisfied.

    Import chain under test:
        tests/ -> scripts/taxonomy/_base.py -> scripts/safe_yaml -> import yaml

    Checks pyproject.toml to confirm PyYAML is declared in dev deps.
    """

    def test_yaml_importable(self):
        """import yaml must succeed (PyYAML installed)."""
        try:
            import yaml as _yaml
            self.assertTrue(hasattr(_yaml, "safe_load"))
        except ImportError:
            self.fail(
                "PyYAML not importable. "
                "Ensure 'PyYAML>=6.0.1,<7' is in pyproject.toml dev deps "
                "and installed in the test environment."
            )

    def test_yaml_version_meets_minimum(self):
        """PyYAML version must be >= 6.0.1 for CVE-2017-18342 fix."""
        import yaml as _yaml
        version_str = getattr(_yaml, "__version__", "0.0.0")
        parts = [int(x) for x in version_str.split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        major, minor, patch = parts
        self.assertGreaterEqual(
            (major, minor, patch), (6, 0, 1),
            f"PyYAML {version_str} < 6.0.1 — upgrade required"
        )

    def test_yaml_version_below_7(self):
        """PyYAML version must be < 7 (upper bound in dev deps)."""
        import yaml as _yaml
        version_str = getattr(_yaml, "__version__", "0.0.0")
        major = int(version_str.split(".")[0])
        self.assertLess(
            major, 7,
            f"PyYAML {version_str} >= 7 violates pyproject.toml upper bound"
        )

    def test_pyproject_toml_has_pyyaml_in_dev(self):
        """pyproject.toml dev deps must declare PyYAML."""
        toml_path = PROJECT_ROOT / "pyproject.toml"
        self.assertTrue(toml_path.exists(), "pyproject.toml not found")
        content = toml_path.read_text(encoding="utf-8")
        self.assertIn(
            "PyYAML", content,
            "PyYAML not found in pyproject.toml dev deps"
        )

    def test_pyproject_toml_pyyaml_has_version_bound(self):
        """pyproject.toml must specify a version bound for PyYAML, not just bare name."""
        toml_path = PROJECT_ROOT / "pyproject.toml"
        content = toml_path.read_text(encoding="utf-8")
        # Should contain something like PyYAML>=6.0 or PyYAML>=6.0.1,<7
        import re
        matches = re.findall(r'PyYAML[>=<,\d.]+', content)
        self.assertTrue(
            any(">=" in m for m in matches),
            f"PyYAML in pyproject.toml lacks a minimum version bound. Found: {matches}"
        )

    def test_base_module_imports_safe_yaml_helper(self):
        """scripts/taxonomy/_base.py must import safe_load_yaml (not raw yaml)."""
        base_path = PROJECT_ROOT / "scripts" / "taxonomy" / "_base.py"
        content = base_path.read_text(encoding="utf-8")
        self.assertIn(
            "from scripts.safe_yaml import safe_load_yaml",
            content,
            "_base.py should use safe_load_yaml() not raw yaml.safe_load()"
        )
        # Must NOT import yaml directly (it's now delegated to safe_yaml.py)
        self.assertNotIn(
            "import yaml",
            content,
            "_base.py should not directly import yaml — delegate to safe_yaml.py"
        )

    def test_sync_datasets_imports_safe_yaml_helper(self):
        """sync_datasets.py must import safe_load_yaml (not raw yaml.safe_load)."""
        sync_path = PROJECT_ROOT / "scripts" / "sync_datasets.py"
        content = sync_path.read_text(encoding="utf-8")
        self.assertIn(
            "from scripts.safe_yaml import safe_load_yaml",
            content,
            "sync_datasets.py should use safe_load_yaml()"
        )

    def test_base_module_fully_importable(self):
        """scripts/taxonomy/_base.py must be importable without error."""
        try:
            import scripts.taxonomy._base as base_mod
            self.assertTrue(hasattr(base_mod, "_load_taxonomy"))
            self.assertTrue(hasattr(base_mod, "Probe"))
        except ImportError as exc:
            self.fail(
                f"Could not import scripts.taxonomy._base: {exc}\n"
                "This is the Python 3.11 CI failure — ensure PyYAML is "
                "installed in the test environment."
            )

    def test_safe_yaml_module_importable(self):
        """scripts/safe_yaml.py must be importable with the expected API."""
        try:
            from scripts.safe_yaml import safe_load_yaml
            self.assertTrue(callable(safe_load_yaml))
        except ImportError as exc:
            self.fail(f"Could not import scripts.safe_yaml: {exc}")


# ===========================================================================
# Theory 6 — Path traversal in taxonomy YAML loading
# ===========================================================================

class TestPathTraversalInTaxonomyLoader(unittest.TestCase):
    """Test path-containment validation in the taxonomy loader.

    The production code reads the path from TAXONOMY_YAML_PATH env var:
        _TAXONOMY_PATH = Path(os.environ.get("TAXONOMY_YAML_PATH", ...))

    Path-containment validation ensures the resolved path stays within
    PROJECT_ROOT/data/.  Paths outside that directory are rejected with
    ValueError before the file is ever opened.
    """

    def setUp(self):
        import scripts.taxonomy._base as mod
        self._mod = mod
        self._orig_path = mod._TAXONOMY_PATH
        mod.clear_taxonomy_cache()

    def tearDown(self):
        self._mod._TAXONOMY_PATH = self._orig_path
        self._mod.clear_taxonomy_cache()
        os.environ.pop("TAXONOMY_YAML_PATH", None)

    def test_absolute_path_to_passwd_blocked_by_containment(self):
        """Pointing TAXONOMY_YAML_PATH at /etc/passwd raises ValueError.

        The path-containment check rejects it before the file is opened.
        """
        passwd_path = "/etc/passwd"
        if not os.path.exists(passwd_path):
            self.skipTest("/etc/passwd not available on this platform")

        self._mod._TAXONOMY_PATH = Path(passwd_path)
        self._mod.clear_taxonomy_cache()

        with self.assertRaises(ValueError) as ctx:
            self._mod._load_taxonomy()
        self.assertIn("must be within data/ directory", str(ctx.exception))

    def test_traversal_path_blocked_by_containment(self):
        """Traversal paths like ../../tmp are blocked by path-containment check.

        The resolved path escapes data/, so ValueError is raised before
        the file is opened.
        """
        # Use a traversal-style path that resolves outside data/
        traversal = PROJECT_ROOT / "data" / ".." / ".." / "tmp"
        self._mod._TAXONOMY_PATH = traversal
        self._mod.clear_taxonomy_cache()

        with self.assertRaises(ValueError) as ctx:
            self._mod._load_taxonomy()
        self.assertIn("must be within data/ directory", str(ctx.exception))

    def test_symlink_traversal_blocked_by_containment(self):
        """A symlink pointing outside data/ is blocked by path-containment.

        resolve() dereferences symlinks, so the real target is checked.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            legit = os.path.join(tmpdir, "legit.yaml")
            with open(legit, "w") as f:
                f.write(
                    "version: '1.0'\n"
                    "categories:\n"
                    "  INJECTED:\n"
                    "    name: Injected via symlink\n"
                )

            symlink_dir = os.path.join(tmpdir, "data")
            os.makedirs(symlink_dir)
            symlink = os.path.join(symlink_dir, "taxonomy.yaml")
            os.symlink(legit, symlink)

            self._mod._TAXONOMY_PATH = Path(symlink)
            self._mod.clear_taxonomy_cache()

            # Symlink resolves outside data/ — blocked
            with self.assertRaises(ValueError) as ctx:
                self._mod._load_taxonomy()
            self.assertIn("must be within data/ directory", str(ctx.exception))

    def test_crafted_file_outside_data_dir_blocked(self):
        """A crafted YAML file in /tmp is blocked by path-containment.

        Even if the file has valid taxonomy structure, it is rejected
        because it is not within the data/ directory.
        """
        injected_yaml = (
            "version: 'evil'\n"
            "categories:\n"
            "  INJECTED_CATEGORY:\n"
            "    name: 'Injected via path traversal'\n"
            "    severity: 'critical'\n"
            "    tags: []\n"
            "    expected_layers: []\n"
            "    techniques: {}\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False) as f:
            f.write(injected_yaml)
            tmp = f.name

        self._mod._TAXONOMY_PATH = Path(tmp)
        self._mod.clear_taxonomy_cache()

        try:
            with self.assertRaises(ValueError) as ctx:
                self._mod._load_taxonomy()
            self.assertIn("must be within data/ directory", str(ctx.exception))
        finally:
            os.unlink(tmp)
            self._mod.clear_taxonomy_cache()

    def test_missing_file_in_data_dir_raises_file_not_found(self):
        """Missing file within data/ raises FileNotFoundError."""
        self._mod._TAXONOMY_PATH = PROJECT_ROOT / "data" / "nonexistent.yaml"
        self._mod.clear_taxonomy_cache()
        with self.assertRaises(FileNotFoundError):
            self._mod._load_taxonomy()

    def test_path_outside_project_raises_value_error(self):
        """Pointing to a file outside the project raises ValueError."""
        self._mod._TAXONOMY_PATH = Path("/tmp/evil.yaml")
        self._mod.clear_taxonomy_cache()
        with self.assertRaises(ValueError) as ctx:
            self._mod._load_taxonomy()
        self.assertIn("must be within data/ directory", str(ctx.exception))


# ===========================================================================
# Theory 7 — Existing taxonomy tests pass (integration smoke)
# ===========================================================================

class TestExistingTaxonomyTestsPass(unittest.TestCase):
    """Smoke tests that replicate existing taxonomy test suite coverage.

    Verifies yaml.safe_load() + safe_load_yaml() correctly loads
    data/taxonomy.yaml and data/datasets.yaml.
    """

    def setUp(self):
        import scripts.taxonomy._base as mod
        mod.clear_taxonomy_cache()

    def tearDown(self):
        import scripts.taxonomy._base as mod
        mod.clear_taxonomy_cache()

    def test_real_taxonomy_yaml_loads(self):
        """data/taxonomy.yaml loads without error."""
        from scripts.taxonomy._base import _load_taxonomy
        data = _load_taxonomy()
        self.assertIsNotNone(data)
        self.assertIsInstance(data, dict)

    def test_real_taxonomy_has_version(self):
        """data/taxonomy.yaml has a 'version' key."""
        from scripts.taxonomy._base import _load_taxonomy
        data = _load_taxonomy()
        self.assertIn("version", data)

    def test_real_taxonomy_has_categories(self):
        """data/taxonomy.yaml has a 'categories' dict."""
        from scripts.taxonomy._base import _load_taxonomy
        data = _load_taxonomy()
        self.assertIn("categories", data)
        self.assertIsInstance(data["categories"], dict)

    def test_real_taxonomy_has_expected_category_keys(self):
        """Spot-check D1, D2, D5 categories exist."""
        from scripts.taxonomy._base import _load_taxonomy
        data = _load_taxonomy()
        cats = data["categories"]
        for key in ["D1", "D2", "D5"]:
            self.assertIn(key, cats, f"Category {key} missing from taxonomy")

    def test_real_taxonomy_well_formed(self):
        """Every category has 'name' and 'severity' fields."""
        from scripts.taxonomy._base import _load_taxonomy
        data = _load_taxonomy()
        for cat_id, cat in data["categories"].items():
            self.assertIn("name", cat,
                          f"Category {cat_id} missing 'name'")
            self.assertIn("severity", cat,
                          f"Category {cat_id} missing 'severity'")

    def test_real_datasets_yaml_loads(self):
        """data/datasets.yaml loads without error via safe_load_yaml."""
        from scripts.safe_yaml import safe_load_yaml
        datasets_path = PROJECT_ROOT / "data" / "datasets.yaml"
        self.assertTrue(datasets_path.exists(),
                        f"data/datasets.yaml not found at {datasets_path}")
        data = safe_load_yaml(str(datasets_path))
        self.assertIsNotNone(data)
        self.assertIn("sources", data)
        self.assertIn("version", data)

    def test_datasets_yaml_sources_are_well_formed(self):
        """Each source in datasets.yaml has 'type' and 'output' keys."""
        from scripts.safe_yaml import safe_load_yaml
        datasets_path = PROJECT_ROOT / "data" / "datasets.yaml"
        data = safe_load_yaml(str(datasets_path))

        sources = data.get("sources", {})
        self.assertGreater(len(sources), 0, "datasets.yaml has no sources")
        for name, cfg in sources.items():
            self.assertIsInstance(cfg, dict, f"Source '{name}' must be a dict")
            self.assertIn("type", cfg, f"Source '{name}' missing 'type'")
            self.assertIn("output", cfg, f"Source '{name}' missing 'output'")

    def test_real_taxonomy_probe_instantiates(self):
        """A Probe subclass using category D1 can be instantiated."""
        from scripts.taxonomy._base import Probe, clear_taxonomy_cache

        class SmokeProbe(Probe):
            category_id = "D1"
            def generate(self):
                return []

        clear_taxonomy_cache()
        probe = SmokeProbe()
        self.assertEqual(probe.category_id, "D1")
        self.assertIsNotNone(probe.name)
        self.assertEqual(probe.severity, "critical")
        clear_taxonomy_cache()

    def test_safe_load_yaml_direct_call(self):
        """Direct call to safe_load_yaml() on the real taxonomy file works."""
        from scripts.safe_yaml import safe_load_yaml
        taxonomy_path = PROJECT_ROOT / "data" / "taxonomy.yaml"
        data = safe_load_yaml(str(taxonomy_path))
        self.assertIn("categories", data)


# ===========================================================================
# Bonus — safe_load_yaml() unit tests (scripts/safe_yaml.py)
# ===========================================================================

class TestSafeLoadYamlHelper(unittest.TestCase):
    """Unit tests for scripts/safe_yaml.py — the hardened YAML loader.

    This is the wrapper that _base.py and sync_datasets.py both call.
    """

    def setUp(self):
        from scripts.safe_yaml import safe_load_yaml
        self.load = safe_load_yaml

    def test_loads_valid_yaml(self):
        """Loads a valid YAML file correctly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False) as f:
            f.write("key: value\nnum: 42\n")
            tmp = f.name
        try:
            data = self.load(tmp)
            self.assertEqual(data["key"], "value")
            self.assertEqual(data["num"], 42)
        finally:
            os.unlink(tmp)

    def test_raises_file_not_found_for_missing_file(self):
        """FileNotFoundError when file doesn't exist."""
        with self.assertRaises(FileNotFoundError):
            self.load("/nonexistent/path/file.yaml")

    def test_raises_file_not_found_for_directory(self):
        """FileNotFoundError when path is a directory (is_file() check)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(FileNotFoundError) as ctx:
                self.load(tmpdir)
            self.assertIn("not a file", str(ctx.exception))

    def test_raises_value_error_for_invalid_yaml(self):
        """ValueError for malformed YAML."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False) as f:
            f.write(": :\n  bad: [unterminated\n")
            tmp = f.name
        try:
            with self.assertRaises(ValueError) as ctx:
                self.load(tmp)
            self.assertIn("Invalid YAML", str(ctx.exception))
        finally:
            os.unlink(tmp)

    def test_raises_value_error_for_oversized_file(self):
        """ValueError for files exceeding max_size_bytes."""
        content = "k: v\n" * 100
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False) as f:
            f.write(content)
            tmp = f.name
        try:
            with self.assertRaises(ValueError) as ctx:
                self.load(tmp, max_size_bytes=10)  # Only 10 bytes allowed
            self.assertIn("too large", str(ctx.exception))
        finally:
            os.unlink(tmp)

    def test_size_check_disabled_with_zero(self):
        """max_size_bytes=0 disables the size check."""
        content = "k: v\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False) as f:
            f.write(content)
            tmp = f.name
        try:
            data = self.load(tmp, max_size_bytes=0)
            self.assertEqual(data["k"], "v")
        finally:
            os.unlink(tmp)

    def test_accepts_pathlib_path(self):
        """Accepts pathlib.Path objects, not just strings."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False) as f:
            f.write("x: 1\n")
            tmp = f.name
        try:
            data = self.load(Path(tmp))
            self.assertEqual(data["x"], 1)
        finally:
            os.unlink(tmp)

    def test_rejects_python_tags_as_value_error(self):
        """!!python/* tags are blocked and wrapped as ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False) as f:
            f.write("!!python/object/apply:os.system ['id']\n")
            tmp = f.name
        try:
            with self.assertRaises(ValueError) as ctx:
                self.load(tmp)
            self.assertIn("Invalid YAML", str(ctx.exception))
        finally:
            os.unlink(tmp)

    def test_wraps_unicode_error_as_value_error(self):
        """Non-UTF-8 content is wrapped as ValueError."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            f.write(b"\xfe\xff" + "key: val\n".encode("utf-16-be"))
            tmp = f.name
        try:
            with self.assertRaises(ValueError) as ctx:
                self.load(tmp)
            self.assertIn("Non-UTF-8", str(ctx.exception))
        finally:
            os.unlink(tmp)

    def test_error_message_includes_path(self):
        """Error messages include the file path for debuggability."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                        delete=False) as f:
            f.write(": bad yaml [\n")
            tmp = f.name
        try:
            with self.assertRaises(ValueError) as ctx:
                self.load(tmp)
            self.assertIn(tmp, str(ctx.exception))
        finally:
            os.unlink(tmp)


# ===========================================================================
# Bonus — Safe loader vs unsafe loader contrast
# ===========================================================================

class TestSafeVsUnsafeLoader(unittest.TestCase):
    """Document the difference between yaml.safe_load() and yaml.load()."""

    MALICIOUS_PAYLOAD = "!!python/object/apply:os.getpid []"

    def test_safe_load_rejects_malicious_tag(self):
        """safe_load must reject !!python/* tags."""
        with self.assertRaises(yaml.constructor.ConstructorError):
            yaml.safe_load(self.MALICIOUS_PAYLOAD)

    def test_safe_load_does_not_produce_result(self):
        """safe_load must not return any result for a malicious payload."""
        with self.assertRaises(yaml.constructor.ConstructorError):
            result = yaml.safe_load(self.MALICIOUS_PAYLOAD)
            self.fail(f"safe_load returned {result!r} instead of raising")

    def test_full_load_with_safe_loader_is_equivalent(self):
        """yaml.load(s, Loader=yaml.SafeLoader) behaves same as safe_load."""
        payload = "key: value"
        result_safe = yaml.safe_load(payload)
        result_full = yaml.load(payload, Loader=yaml.SafeLoader)
        self.assertEqual(result_safe, result_full)

    def test_yaml_dump_round_trip(self):
        """yaml.dump() + yaml.safe_load() round-trip is lossless."""
        data = {"key": "value", "number": 42, "list": [1, 2, 3]}
        output = yaml.dump(data, default_flow_style=False)
        loaded = yaml.safe_load(output)
        self.assertEqual(loaded, data)


# ===========================================================================
# Theory 8 — Schema validation in _load_taxonomy()
# ===========================================================================

class TestTaxonomySchemaValidation(unittest.TestCase):
    """Test that _load_taxonomy() validates category structure.

    Each category must be a dict with at minimum a 'name' key.
    Files with missing or malformed categories are rejected.
    """

    def setUp(self):
        import scripts.taxonomy._base as mod
        self._mod = mod
        self._orig_path = mod._TAXONOMY_PATH
        mod.clear_taxonomy_cache()

    def tearDown(self):
        self._mod._TAXONOMY_PATH = self._orig_path
        self._mod.clear_taxonomy_cache()

    def _write_yaml_in_data_dir(self, content):
        """Write YAML content to a temp file inside the project data/ dir.

        Returns the path to the temporary file.  Caller must clean up.
        """
        data_dir = PROJECT_ROOT / "data"
        # Use a unique name to avoid collisions
        import uuid
        fname = "test_schema_{}.yaml".format(uuid.uuid4().hex[:8])
        fpath = data_dir / fname
        fpath.write_text(content, encoding="utf-8")
        return fpath

    def test_category_missing_name_rejected(self):
        """A category without 'name' field is rejected."""
        yaml_content = (
            "version: '1.0'\n"
            "categories:\n"
            "  BAD_CAT:\n"
            "    severity: critical\n"
            "    tags: []\n"
        )
        fpath = self._write_yaml_in_data_dir(yaml_content)
        try:
            self._mod._TAXONOMY_PATH = fpath
            self._mod.clear_taxonomy_cache()
            with self.assertRaises(ValueError) as ctx:
                self._mod._load_taxonomy()
            self.assertIn("missing required 'name' field", str(ctx.exception))
            self.assertIn("BAD_CAT", str(ctx.exception))
        finally:
            fpath.unlink(missing_ok=True)
            self._mod.clear_taxonomy_cache()

    def test_category_not_a_dict_rejected(self):
        """A category that is a string instead of dict is rejected."""
        yaml_content = (
            "version: '1.0'\n"
            "categories:\n"
            "  BAD_CAT: just_a_string\n"
        )
        fpath = self._write_yaml_in_data_dir(yaml_content)
        try:
            self._mod._TAXONOMY_PATH = fpath
            self._mod.clear_taxonomy_cache()
            with self.assertRaises(ValueError) as ctx:
                self._mod._load_taxonomy()
            self.assertIn("must be a dict", str(ctx.exception))
            self.assertIn("BAD_CAT", str(ctx.exception))
        finally:
            fpath.unlink(missing_ok=True)
            self._mod.clear_taxonomy_cache()

    def test_categories_not_a_dict_rejected(self):
        """A 'categories' value that is a list instead of dict is rejected."""
        yaml_content = (
            "version: '1.0'\n"
            "categories:\n"
            "  - item1\n"
            "  - item2\n"
        )
        fpath = self._write_yaml_in_data_dir(yaml_content)
        try:
            self._mod._TAXONOMY_PATH = fpath
            self._mod.clear_taxonomy_cache()
            with self.assertRaises(ValueError) as ctx:
                self._mod._load_taxonomy()
            self.assertIn("must be a dict", str(ctx.exception))
        finally:
            fpath.unlink(missing_ok=True)
            self._mod.clear_taxonomy_cache()

    def test_valid_category_with_name_accepted(self):
        """A well-formed category with 'name' is accepted."""
        yaml_content = (
            "version: '1.0'\n"
            "categories:\n"
            "  GOOD_CAT:\n"
            "    name: Good Category\n"
            "    severity: low\n"
        )
        fpath = self._write_yaml_in_data_dir(yaml_content)
        try:
            self._mod._TAXONOMY_PATH = fpath
            self._mod.clear_taxonomy_cache()
            data = self._mod._load_taxonomy()
            self.assertIn("GOOD_CAT", data["categories"])
            self.assertEqual(data["categories"]["GOOD_CAT"]["name"],
                             "Good Category")
        finally:
            fpath.unlink(missing_ok=True)
            self._mod.clear_taxonomy_cache()

    def test_mixed_valid_and_invalid_categories_rejected(self):
        """If any category is invalid, the whole load is rejected."""
        yaml_content = (
            "version: '1.0'\n"
            "categories:\n"
            "  GOOD:\n"
            "    name: Good One\n"
            "  BAD:\n"
            "    severity: critical\n"
        )
        fpath = self._write_yaml_in_data_dir(yaml_content)
        try:
            self._mod._TAXONOMY_PATH = fpath
            self._mod.clear_taxonomy_cache()
            with self.assertRaises(ValueError) as ctx:
                self._mod._load_taxonomy()
            self.assertIn("BAD", str(ctx.exception))
            self.assertIn("missing required 'name' field", str(ctx.exception))
        finally:
            fpath.unlink(missing_ok=True)
            self._mod.clear_taxonomy_cache()


# ===========================================================================
# Theory 9 — BOM handling with utf-8-sig in safe_load_yaml
# ===========================================================================

class TestSafeLoadYamlBOMHandling(unittest.TestCase):
    """Test that safe_load_yaml() correctly handles UTF-8 BOM via utf-8-sig.

    With encoding='utf-8-sig', the BOM is silently stripped on read,
    ensuring clean YAML parsing regardless of whether the file has a BOM.
    """

    MINIMAL_YAML = "key: value\nother: 42\n"

    def setUp(self):
        from scripts.safe_yaml import safe_load_yaml
        self.load = safe_load_yaml

    def test_bom_file_loads_cleanly_with_safe_load_yaml(self):
        """A UTF-8 file with BOM loads correctly via safe_load_yaml."""
        bom_bytes = b"\xef\xbb\xbf"
        yaml_bytes = self.MINIMAL_YAML.encode("utf-8")

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            f.write(bom_bytes + yaml_bytes)
            tmp = f.name

        try:
            data = self.load(tmp)
            self.assertIsNotNone(data)
            self.assertIn("key", data)
            self.assertEqual(data["key"], "value")
            self.assertEqual(data["other"], 42)
        finally:
            os.unlink(tmp)

    def test_no_bom_file_loads_cleanly_with_safe_load_yaml(self):
        """A UTF-8 file without BOM still loads correctly."""
        yaml_bytes = self.MINIMAL_YAML.encode("utf-8")

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            f.write(yaml_bytes)
            tmp = f.name

        try:
            data = self.load(tmp)
            self.assertIn("key", data)
            self.assertEqual(data["key"], "value")
        finally:
            os.unlink(tmp)


# ===========================================================================
# Theory 10 — Docstring limitation note
# ===========================================================================

class TestDocstringLimitationNote(unittest.TestCase):
    """Verify the safe_yaml module docstring documents the in-memory limitation."""

    def test_module_docstring_mentions_in_memory_limitation(self):
        """Module docstring must note that size limit is disk-only."""
        import scripts.safe_yaml as mod
        docstring = mod.__doc__
        self.assertIsNotNone(docstring, "safe_yaml module has no docstring")
        self.assertIn("in-memory", docstring.lower(),
                      "Docstring should mention in-memory limitation")

    def test_module_docstring_mentions_utf8_sig(self):
        """Module docstring must mention UTF-8-SIG encoding."""
        import scripts.safe_yaml as mod
        docstring = mod.__doc__
        self.assertIn("UTF-8-SIG", docstring,
                      "Docstring should mention UTF-8-SIG encoding")


if __name__ == "__main__":
    unittest.main(verbosity=2)
