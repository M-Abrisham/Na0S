import os
import sys
import tempfile
import pathlib
import unittest
from unittest.mock import patch, MagicMock
from io import BytesIO

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from layer0.input_loader import (
    load_input,
    InputLoadError,
    _is_url,
    _is_file_path,
    _validate_file_path,
    MAX_FILE_SIZE,
)


class TestTextPassthrough(unittest.TestCase):
    """Plain string inputs should pass through unchanged."""

    def test_simple_text(self):
        content, meta = load_input("Hello, world!")
        self.assertEqual(content, "Hello, world!")
        self.assertEqual(meta["source_type"], "text")
        self.assertIsNone(meta["source_path"])
        self.assertIsNone(meta["content_type"])
        self.assertIsNone(meta["file_size"])

    def test_empty_string(self):
        content, meta = load_input("")
        self.assertEqual(content, "")
        self.assertEqual(meta["source_type"], "text")

    def test_multiline_text(self):
        text = "Line 1\nLine 2\nLine 3"
        content, meta = load_input(text)
        self.assertEqual(content, text)
        self.assertEqual(meta["source_type"], "text")

    def test_unicode_text(self):
        text = "Hello \u4e16\u754c \U0001F600"
        content, meta = load_input(text)
        self.assertEqual(content, text)
        self.assertEqual(meta["source_type"], "text")

    def test_text_that_looks_like_path_but_doesnt_exist(self):
        content, meta = load_input("/nonexistent/path/to/file.txt")
        self.assertEqual(content, "/nonexistent/path/to/file.txt")
        self.assertEqual(meta["source_type"], "text")


class TestBytesPassthrough(unittest.TestCase):
    """Bytes inputs should pass through unchanged."""

    def test_simple_bytes(self):
        data = b"Hello, bytes!"
        content, meta = load_input(data)
        self.assertEqual(content, data)
        self.assertEqual(meta["source_type"], "bytes")
        self.assertIsNone(meta["source_path"])
        self.assertEqual(meta["file_size"], len(data))

    def test_empty_bytes(self):
        content, meta = load_input(b"")
        self.assertEqual(content, b"")
        self.assertEqual(meta["source_type"], "bytes")
        self.assertEqual(meta["file_size"], 0)

    def test_bytearray(self):
        data = bytearray(b"Hello, bytearray!")
        content, meta = load_input(data)
        self.assertEqual(content, data)
        self.assertEqual(meta["source_type"], "bytes")

    def test_binary_content(self):
        data = bytes(range(256))
        content, meta = load_input(data)
        self.assertEqual(content, data)
        self.assertEqual(meta["file_size"], 256)


class TestFileLoading(unittest.TestCase):
    """File path inputs should read file content."""

    def test_load_text_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("File content here")
            f.flush()
            filepath = f.name

        try:
            content, meta = load_input(filepath)
            self.assertEqual(content, b"File content here")
            self.assertEqual(meta["source_type"], "file")
            self.assertEqual(meta["source_path"], filepath)
            self.assertIn("text/plain", meta["content_type"] or "")
            self.assertEqual(meta["file_size"], 17)
        finally:
            os.unlink(filepath)

    def test_load_binary_file(self):
        data = bytes(range(256))
        with tempfile.NamedTemporaryFile(
            suffix=".bin", delete=False
        ) as f:
            f.write(data)
            f.flush()
            filepath = f.name

        try:
            content, meta = load_input(filepath)
            self.assertEqual(content, data)
            self.assertEqual(meta["source_type"], "file")
            self.assertEqual(meta["file_size"], 256)
        finally:
            os.unlink(filepath)

    def test_load_pathlib_path(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("pathlib content")
            f.flush()
            filepath = pathlib.Path(f.name)

        try:
            content, meta = load_input(filepath)
            self.assertEqual(content, b"pathlib content")
            self.assertEqual(meta["source_type"], "file")
        finally:
            os.unlink(str(filepath))

    def test_pathlib_nonexistent_raises(self):
        fake_path = pathlib.Path("/tmp/nonexistent_test_file_12345.txt")
        with self.assertRaises(InputLoadError) as ctx:
            load_input(fake_path)
        self.assertIn("File not found", str(ctx.exception))

    def test_load_empty_file(self):
        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False
        ) as f:
            filepath = f.name

        try:
            content, meta = load_input(filepath)
            self.assertEqual(content, b"")
            self.assertEqual(meta["source_type"], "file")
            self.assertEqual(meta["file_size"], 0)
        finally:
            os.unlink(filepath)


class TestFileSizeLimit(unittest.TestCase):
    """File size limit should be enforced."""

    def test_oversized_file_rejected(self):
        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False
        ) as f:
            filepath = f.name
            # Write a file slightly over the limit
            # We patch MAX_FILE_SIZE to a small value for testing
            f.write(b"x" * 1025)
            f.flush()

        try:
            import layer0.input_loader as loader
            orig = loader.MAX_FILE_SIZE
            loader.MAX_FILE_SIZE = 1024
            try:
                with self.assertRaises(InputLoadError) as ctx:
                    load_input(filepath)
                self.assertIn("exceeds limit", str(ctx.exception))
            finally:
                loader.MAX_FILE_SIZE = orig
        finally:
            os.unlink(filepath)

    def test_file_at_limit_passes(self):
        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False
        ) as f:
            filepath = f.name
            f.write(b"x" * 1024)
            f.flush()

        try:
            import layer0.input_loader as loader
            orig = loader.MAX_FILE_SIZE
            loader.MAX_FILE_SIZE = 1024
            try:
                content, meta = load_input(filepath)
                self.assertEqual(len(content), 1024)
            finally:
                loader.MAX_FILE_SIZE = orig
        finally:
            os.unlink(filepath)


class TestDirectoryTraversalRejection(unittest.TestCase):
    """Directory traversal attempts should be rejected."""

    def test_dotdot_in_path_direct(self):
        """Test _validate_file_path directly to verify .. rejection."""
        # _validate_file_path should reject any path containing ".."
        # regardless of whether it resolves to a real file.
        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False
        ) as f:
            f.write(b"test")
            f.flush()
            filepath = f.name

        try:
            dirpart = os.path.dirname(filepath)
            basename = os.path.basename(filepath)
            # Create the subdir so the path actually exists
            subdir = os.path.join(dirpart, "test_subdir_l0")
            os.makedirs(subdir, exist_ok=True)
            try:
                traversal_path = os.path.join(
                    dirpart, "test_subdir_l0", "..", basename
                )
                with self.assertRaises(InputLoadError) as ctx:
                    _validate_file_path(traversal_path)
                self.assertIn("Directory traversal", str(ctx.exception))
            finally:
                os.rmdir(subdir)
        finally:
            os.unlink(filepath)

    def test_dotdot_via_load_input(self):
        """Traversal path that exists on disk should still be rejected."""
        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False
        ) as f:
            f.write(b"test")
            f.flush()
            filepath = f.name

        try:
            dirpart = os.path.dirname(filepath)
            basename = os.path.basename(filepath)
            subdir = os.path.join(dirpart, "test_subdir_l0_2")
            os.makedirs(subdir, exist_ok=True)
            try:
                traversal_path = os.path.join(
                    dirpart, "test_subdir_l0_2", "..", basename
                )
                # Path with .. should be rejected even if it resolves to a real file
                with self.assertRaises(InputLoadError) as ctx:
                    load_input(traversal_path)
                self.assertIn("Directory traversal", str(ctx.exception))
            finally:
                os.rmdir(subdir)
        finally:
            os.unlink(filepath)

    def test_directory_rejected(self):
        tmpdir = tempfile.mkdtemp()
        try:
            with self.assertRaises(InputLoadError) as ctx:
                load_input(tmpdir)
            self.assertIn("directory", str(ctx.exception).lower())
        finally:
            os.rmdir(tmpdir)


class TestSymlinkRejection(unittest.TestCase):
    """Symlinks should be rejected."""

    def test_symlink_rejected(self):
        with tempfile.NamedTemporaryFile(
            suffix=".txt", delete=False
        ) as f:
            f.write(b"real content")
            f.flush()
            real_path = f.name

        link_path = real_path + ".link"
        try:
            os.symlink(real_path, link_path)
            with self.assertRaises(InputLoadError) as ctx:
                load_input(link_path)
            self.assertIn("Symlink", str(ctx.exception))
        finally:
            os.unlink(link_path)
            os.unlink(real_path)


class TestURLLoading(unittest.TestCase):
    """URL inputs should be fetched with urllib."""

    @patch("layer0.input_loader.urllib.request.urlopen")
    def test_https_url_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"<html>Hello</html>"
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        content, meta = load_input("https://example.com/page")
        self.assertEqual(content, b"<html>Hello</html>")
        self.assertEqual(meta["source_type"], "url")
        self.assertEqual(meta["source_path"], "https://example.com/page")
        self.assertEqual(meta["content_type"], "text/html; charset=utf-8")
        self.assertEqual(meta["file_size"], 18)

    def test_http_rejected_by_default(self):
        with self.assertRaises(InputLoadError) as ctx:
            load_input("http://example.com/page")
        self.assertIn("HTTPS only", str(ctx.exception))

    @patch("layer0.input_loader.HTTPS_ONLY", False)
    @patch("layer0.input_loader.urllib.request.urlopen")
    def test_http_allowed_when_configured(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"content"
        mock_resp.headers = {"Content-Type": "text/plain"}
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        content, meta = load_input("http://example.com/page")
        self.assertEqual(content, b"content")
        self.assertEqual(meta["source_type"], "url")

    @patch("layer0.input_loader.urllib.request.urlopen")
    def test_url_fetch_failure(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        with self.assertRaises(InputLoadError) as ctx:
            load_input("https://example.com/fail")
        self.assertIn("URL fetch failed", str(ctx.exception))

    @patch("layer0.input_loader.urllib.request.urlopen")
    def test_url_oversized_response(self, mock_urlopen):
        import layer0.input_loader as loader
        orig = loader.MAX_URL_RESPONSE_SIZE
        loader.MAX_URL_RESPONSE_SIZE = 100

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"x" * 101
        mock_resp.headers = {"Content-Type": "text/plain"}
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        try:
            with self.assertRaises(InputLoadError) as ctx:
                load_input("https://example.com/big")
            self.assertIn("byte limit", str(ctx.exception))
        finally:
            loader.MAX_URL_RESPONSE_SIZE = orig


class TestHelperFunctions(unittest.TestCase):
    """Test internal helper functions."""

    def test_is_url_https(self):
        self.assertTrue(_is_url("https://example.com"))

    def test_is_url_http(self):
        self.assertTrue(_is_url("http://example.com"))

    def test_is_url_not_url(self):
        self.assertFalse(_is_url("just some text"))
        self.assertFalse(_is_url("/path/to/file"))
        self.assertFalse(_is_url(123))

    def test_is_file_path_real_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            filepath = f.name
        try:
            self.assertTrue(_is_file_path(filepath))
        finally:
            os.unlink(filepath)

    def test_is_file_path_nonexistent(self):
        self.assertFalse(_is_file_path("/nonexistent/file.txt"))

    def test_is_file_path_url_not_treated_as_path(self):
        self.assertFalse(_is_file_path("https://example.com"))


class TestUnsupportedTypes(unittest.TestCase):
    """Unsupported types should pass through with 'unknown' metadata."""

    def test_integer_passthrough(self):
        content, meta = load_input(12345)
        self.assertEqual(content, 12345)
        self.assertEqual(meta["source_type"], "unknown")

    def test_none_passthrough(self):
        content, meta = load_input(None)
        self.assertIsNone(content)
        self.assertEqual(meta["source_type"], "unknown")

    def test_list_passthrough(self):
        content, meta = load_input([1, 2, 3])
        self.assertEqual(content, [1, 2, 3])
        self.assertEqual(meta["source_type"], "unknown")


class TestIntegrationWithSanitizer(unittest.TestCase):
    """End-to-end: file path -> layer0_sanitize -> Layer0Result."""

    def test_file_through_sanitizer(self):
        from layer0 import layer0_sanitize

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("This is a normal test input for sanitization.")
            f.flush()
            filepath = f.name

        try:
            result = layer0_sanitize(filepath)
            self.assertFalse(result.rejected)
            self.assertIn("sanitiz", result.sanitized_text.lower())
            self.assertEqual(result.source_metadata["source_type"], "file")
            self.assertIn("input_loaded_from_file", result.anomaly_flags)
        finally:
            os.unlink(filepath)

    def test_plain_text_no_source_metadata(self):
        from layer0 import layer0_sanitize

        result = layer0_sanitize("Hello world, this is a test.")
        self.assertFalse(result.rejected)
        # Plain text should have empty source_metadata (no loading needed)
        self.assertEqual(result.source_metadata, {})

    @patch("layer0.input_loader.urllib.request.urlopen")
    def test_url_through_sanitizer(self, mock_urlopen):
        from layer0 import layer0_sanitize

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"URL content for testing purposes."
        mock_resp.headers = {"Content-Type": "text/plain"}
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = layer0_sanitize("https://example.com/test")
        self.assertFalse(result.rejected)
        self.assertEqual(result.source_metadata["source_type"], "url")
        self.assertIn("input_loaded_from_url", result.anomaly_flags)

    def test_bytes_still_works(self):
        from layer0 import layer0_sanitize

        result = layer0_sanitize(b"Bytes input for testing.")
        self.assertFalse(result.rejected)
        self.assertIn("testing", result.sanitized_text.lower())


if __name__ == "__main__":
    unittest.main()
