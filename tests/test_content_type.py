"""Tests for src/layer0/content_type.py — magic byte detection module.

Run: python -m unittest tests/test_content_type.py -v
"""

import unittest

from src.layer0.content_type import (
    ContentTypeResult,
    detect_content_type,
    sniff_binary,
    _BASE64_BLOB_RE,
    _DATA_URI_RE,
)


# ---------------------------------------------------------------------------
# Helper to build minimal byte payloads
# ---------------------------------------------------------------------------

def _pad(header, length=64):
    """Pad *header* with null bytes to *length*."""
    return header + b"\x00" * (length - len(header))


class TestContentTypeResult(unittest.TestCase):
    """Smoke test for the dataclass defaults."""

    def test_empty_result(self):
        r = ContentTypeResult()
        self.assertEqual(r.detected_type, "")
        self.assertEqual(r.flags, [])
        self.assertFalse(r.reject)


# ===================================================================
# CRITICAL tier — executables
# ===================================================================

class TestExecutables(unittest.TestCase):
    """Executables must be detected and flagged for rejection."""

    def test_pe_exe(self):
        r = detect_content_type(_pad(b"MZ"))
        self.assertEqual(r.detected_type, "exe_pe")
        self.assertEqual(r.tier, "CRITICAL")
        self.assertTrue(r.reject)
        self.assertIn("embedded_exe", r.flags)
        self.assertIn("embedded_executable", r.flags)

    def test_elf(self):
        r = detect_content_type(_pad(b"\x7fELF"))
        self.assertEqual(r.detected_type, "exe_elf")
        self.assertTrue(r.reject)
        self.assertIn("embedded_elf", r.flags)

    def test_macho_32(self):
        r = detect_content_type(_pad(b"\xfe\xed\xfa\xce"))
        self.assertEqual(r.detected_type, "exe_macho32")
        self.assertTrue(r.reject)

    def test_macho_64(self):
        r = detect_content_type(_pad(b"\xfe\xed\xfa\xcf"))
        self.assertEqual(r.detected_type, "exe_macho64")
        self.assertTrue(r.reject)

    def test_macho_32_reversed(self):
        r = detect_content_type(_pad(b"\xce\xfa\xed\xfe"))
        self.assertEqual(r.detected_type, "exe_macho32r")
        self.assertTrue(r.reject)

    def test_macho_64_reversed(self):
        r = detect_content_type(_pad(b"\xcf\xfa\xed\xfe"))
        self.assertEqual(r.detected_type, "exe_macho64r")
        self.assertTrue(r.reject)

    def test_java_class(self):
        r = detect_content_type(_pad(b"\xca\xfe\xba\xbe"))
        self.assertEqual(r.detected_type, "java_class")
        self.assertTrue(r.reject)
        self.assertIn("embedded_java_class", r.flags)

    def test_wasm(self):
        r = detect_content_type(_pad(b"\x00asm"))
        self.assertEqual(r.detected_type, "wasm")
        self.assertTrue(r.reject)
        self.assertIn("embedded_wasm", r.flags)

    def test_shebang(self):
        r = detect_content_type(b"#!/bin/bash\necho hello")
        self.assertEqual(r.detected_type, "shebang")
        self.assertTrue(r.reject)
        self.assertIn("embedded_shebang", r.flags)

    def test_reject_reason_not_empty(self):
        r = detect_content_type(_pad(b"MZ"))
        self.assertIn("exe_pe", r.reject_reason)


# ===================================================================
# HIGH tier — Documents
# ===================================================================

class TestDocuments(unittest.TestCase):
    """Document formats: PDF, RTF, OLE2, OOXML."""

    def test_pdf(self):
        r = detect_content_type(b"%PDF-1.7 some content here")
        self.assertEqual(r.detected_type, "pdf")
        self.assertEqual(r.tier, "HIGH")
        self.assertFalse(r.reject)
        self.assertIn("embedded_pdf", r.flags)
        self.assertIn("embedded_document", r.flags)

    def test_rtf(self):
        r = detect_content_type(b"{\\rtf1\\ansi some content here")
        self.assertEqual(r.detected_type, "rtf")
        self.assertIn("embedded_rtf", r.flags)

    def test_ole2(self):
        r = detect_content_type(
            _pad(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        )
        self.assertEqual(r.detected_type, "ole2")
        self.assertIn("embedded_ole2", r.flags)
        self.assertIn("embedded_document", r.flags)

    def test_docx(self):
        """PK header + 'word/' marker -> DOCX."""
        payload = b"PK\x03\x04" + b"\x00" * 26 + b"word/document.xml"
        r = detect_content_type(payload)
        self.assertEqual(r.detected_type, "docx")
        self.assertIn("embedded_docx", r.flags)
        self.assertIn("embedded_document", r.flags)

    def test_xlsx(self):
        """PK header + 'xl/' marker -> XLSX."""
        payload = b"PK\x03\x04" + b"\x00" * 26 + b"xl/workbook.xml"
        r = detect_content_type(payload)
        self.assertEqual(r.detected_type, "xlsx")
        self.assertIn("embedded_xlsx", r.flags)

    def test_pptx(self):
        """PK header + 'ppt/' marker -> PPTX."""
        payload = b"PK\x03\x04" + b"\x00" * 26 + b"ppt/presentation.xml"
        r = detect_content_type(payload)
        self.assertEqual(r.detected_type, "pptx")
        self.assertIn("embedded_pptx", r.flags)

    def test_generic_ooxml(self):
        """PK header + [Content_Types] -> generic OOXML."""
        payload = b"PK\x03\x04" + b"\x00" * 26 + b"[Content_Types].xml"
        r = detect_content_type(payload)
        self.assertEqual(r.detected_type, "ooxml")

    def test_odf(self):
        """PK header + content.xml -> OpenDocument."""
        payload = b"PK\x03\x04" + b"\x00" * 26 + b"content.xml"
        r = detect_content_type(payload)
        self.assertEqual(r.detected_type, "odf")

    def test_jar(self):
        """PK header + META-INF/ -> JAR (archive, not document)."""
        payload = b"PK\x03\x04" + b"\x00" * 26 + b"META-INF/MANIFEST.MF"
        r = detect_content_type(payload)
        self.assertEqual(r.detected_type, "jar")
        self.assertIn("embedded_archive", r.flags)

    def test_plain_zip(self):
        """PK header with no recognized internal structure -> ZIP."""
        payload = b"PK\x03\x04" + b"\x00" * 100
        r = detect_content_type(payload)
        self.assertEqual(r.detected_type, "zip")
        self.assertIn("embedded_zip", r.flags)
        self.assertIn("embedded_archive", r.flags)


# ===================================================================
# HIGH tier — Images
# ===================================================================

class TestImages(unittest.TestCase):
    """Image format signatures."""

    def test_png(self):
        r = detect_content_type(
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
        )
        self.assertEqual(r.detected_type, "png")
        self.assertEqual(r.tier, "HIGH")
        self.assertIn("embedded_png", r.flags)
        self.assertIn("embedded_image", r.flags)

    def test_jpeg(self):
        r = detect_content_type(b"\xff\xd8\xff\xe0" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "jpeg")
        self.assertIn("embedded_jpeg", r.flags)

    def test_gif87a(self):
        r = detect_content_type(b"GIF87a" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "gif")
        self.assertIn("embedded_gif", r.flags)

    def test_gif89a(self):
        r = detect_content_type(b"GIF89a" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "gif")

    def test_bmp(self):
        r = detect_content_type(b"BM" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "bmp")
        self.assertIn("embedded_bmp", r.flags)

    def test_tiff_little_endian(self):
        r = detect_content_type(b"II*\x00" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "tiff_le")
        self.assertIn("embedded_tiff", r.flags)

    def test_tiff_big_endian(self):
        r = detect_content_type(b"MM\x00*" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "tiff_be")
        self.assertIn("embedded_tiff", r.flags)

    def test_psd(self):
        r = detect_content_type(b"8BPS" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "psd")
        self.assertIn("embedded_psd", r.flags)

    def test_ico(self):
        r = detect_content_type(b"\x00\x00\x01\x00" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "ico")
        self.assertIn("embedded_ico", r.flags)

    def test_webp(self):
        """RIFF + WEBP -> WebP image (HIGH tier)."""
        r = detect_content_type(b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "webp")
        self.assertEqual(r.tier, "HIGH")
        self.assertIn("embedded_webp", r.flags)
        self.assertIn("embedded_image", r.flags)


# ===================================================================
# HIGH tier — Archives
# ===================================================================

class TestArchives(unittest.TestCase):
    """Archive format signatures."""

    def test_gzip(self):
        r = detect_content_type(b"\x1f\x8b\x08" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "gzip")
        self.assertIn("embedded_gzip", r.flags)
        self.assertIn("embedded_archive", r.flags)

    def test_7z(self):
        r = detect_content_type(b"7z\xbc\xaf'\x1c" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "7z")
        self.assertIn("embedded_7z", r.flags)

    def test_rar(self):
        r = detect_content_type(b"Rar!\x1a\x07" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "rar")
        self.assertIn("embedded_rar", r.flags)

    def test_bzip2(self):
        r = detect_content_type(b"BZh9" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "bzip2")
        self.assertIn("embedded_bzip2", r.flags)

    def test_tar(self):
        """TAR: 'ustar' at offset 257."""
        data = b"\x00" * 257 + b"ustar" + b"\x00" * 20
        r = detect_content_type(data)
        self.assertEqual(r.detected_type, "tar")
        self.assertIn("embedded_tar", r.flags)
        self.assertIn("embedded_archive", r.flags)


# ===================================================================
# MEDIUM tier — Audio
# ===================================================================

class TestAudio(unittest.TestCase):
    """Audio format signatures."""

    def test_mp3_id3(self):
        r = detect_content_type(b"ID3\x04\x00" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "mp3_id3")
        self.assertEqual(r.tier, "MEDIUM")
        self.assertIn("embedded_mp3", r.flags)
        self.assertIn("embedded_audio", r.flags)

    def test_mp3_sync_fb(self):
        r = detect_content_type(b"\xff\xfb\x90\x00" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "mp3_sync")
        self.assertIn("embedded_mp3", r.flags)

    def test_mp3_sync_f3(self):
        r = detect_content_type(b"\xff\xf3\x90\x00" + b"\x00" * 20)
        self.assertIn("embedded_mp3", r.flags)

    def test_mp3_sync_f2(self):
        r = detect_content_type(b"\xff\xf2\x90\x00" + b"\x00" * 20)
        self.assertIn("embedded_mp3", r.flags)

    def test_flac(self):
        r = detect_content_type(b"fLaC" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "flac")
        self.assertIn("embedded_flac", r.flags)
        self.assertIn("embedded_audio", r.flags)

    def test_ogg(self):
        r = detect_content_type(b"OggS" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "ogg")
        self.assertIn("embedded_ogg", r.flags)

    def test_aac_f1(self):
        r = detect_content_type(b"\xff\xf1" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "aac")
        self.assertIn("embedded_aac", r.flags)

    def test_aac_f9(self):
        r = detect_content_type(b"\xff\xf9" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "aac")

    def test_midi(self):
        r = detect_content_type(b"MThd" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "midi")
        self.assertIn("embedded_midi", r.flags)

    def test_wav(self):
        """RIFF + WAVE -> WAV audio."""
        r = detect_content_type(b"RIFF\x00\x00\x00\x00WAVE" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "wav")
        self.assertEqual(r.tier, "MEDIUM")
        self.assertIn("embedded_wav", r.flags)
        self.assertIn("embedded_audio", r.flags)

    def test_aiff(self):
        """FORM + AIFF -> AIFF audio."""
        r = detect_content_type(b"FORM\x00\x00\x00\x00AIFF" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "aiff")
        self.assertIn("embedded_aiff", r.flags)
        self.assertIn("embedded_audio", r.flags)

    def test_aifc(self):
        """FORM + AIFC -> AIFF-C audio."""
        r = detect_content_type(b"FORM\x00\x00\x00\x00AIFC" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "aiff")
        self.assertIn("embedded_aiff", r.flags)


# ===================================================================
# MEDIUM tier — Video
# ===================================================================

class TestVideo(unittest.TestCase):
    """Video format signatures."""

    def test_avi(self):
        """RIFF + AVI -> AVI video."""
        r = detect_content_type(b"RIFF\x00\x00\x00\x00AVI " + b"\x00" * 20)
        self.assertEqual(r.detected_type, "avi")
        self.assertEqual(r.tier, "MEDIUM")
        self.assertIn("embedded_avi", r.flags)
        self.assertIn("embedded_video", r.flags)

    def test_webm_mkv(self):
        """EBML header -> WebM/MKV."""
        r = detect_content_type(b"\x1aE\xdf\xa3" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "ebml")
        self.assertIn("embedded_webm", r.flags)
        self.assertIn("embedded_video", r.flags)

    def test_mp4(self):
        """ftyp box at offset 4 -> MP4."""
        r = detect_content_type(b"\x00\x00\x00\x18ftypisom" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "mp4")
        self.assertIn("embedded_mp4", r.flags)
        self.assertIn("embedded_video", r.flags)

    def test_flv(self):
        r = detect_content_type(b"FLV\x01" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "flv")
        self.assertIn("embedded_flv", r.flags)

    def test_wmv(self):
        r = detect_content_type(b"0&\xb2u" + b"\x00" * 20)
        self.assertEqual(r.detected_type, "wmv")
        self.assertIn("embedded_wmv", r.flags)


# ===================================================================
# RIFF disambiguation
# ===================================================================

class TestRIFFDisambiguation(unittest.TestCase):
    """RIFF container must be disambiguated by bytes 8-11."""

    def test_riff_wav(self):
        r = detect_content_type(b"RIFF\x00\x00\x00\x00WAVE")
        self.assertEqual(r.detected_type, "wav")
        self.assertEqual(r.category, "embedded_audio")

    def test_riff_avi(self):
        r = detect_content_type(b"RIFF\x00\x00\x00\x00AVI ")
        self.assertEqual(r.detected_type, "avi")
        self.assertEqual(r.category, "embedded_video")

    def test_riff_webp(self):
        r = detect_content_type(b"RIFF\x00\x00\x00\x00WEBP")
        self.assertEqual(r.detected_type, "webp")
        self.assertEqual(r.category, "embedded_image")
        self.assertEqual(r.tier, "HIGH")

    def test_riff_unknown(self):
        r = detect_content_type(b"RIFF\x00\x00\x00\x00XXXX")
        self.assertEqual(r.detected_type, "riff_unknown")
        self.assertIn("embedded_riff_unknown", r.flags)


# ===================================================================
# Edge cases / negative cases
# ===================================================================

class TestEdgeCases(unittest.TestCase):
    """Boundary conditions and non-binary inputs."""

    def test_plain_text(self):
        r = detect_content_type(b"Hello, this is plain text.")
        self.assertEqual(r.detected_type, "")
        self.assertEqual(r.flags, [])
        self.assertFalse(r.reject)

    def test_empty_bytes(self):
        r = detect_content_type(b"")
        self.assertEqual(r.detected_type, "")

    def test_single_byte(self):
        r = detect_content_type(b"\x00")
        self.assertEqual(r.detected_type, "")

    def test_non_bytes_input(self):
        r = detect_content_type("this is a string, not bytes")
        self.assertEqual(r.detected_type, "")

    def test_none_input(self):
        r = detect_content_type(None)
        self.assertEqual(r.detected_type, "")

    def test_bytearray_input(self):
        r = detect_content_type(bytearray(b"%PDF-1.7"))
        self.assertEqual(r.detected_type, "pdf")

    def test_form_without_known_subtype(self):
        """FORM container with unknown sub-type should not match."""
        r = detect_content_type(b"FORM\x00\x00\x00\x00ZZZZ")
        # Should fall through to linear scan; FORM is not in _SIGNATURES
        # so result should be empty.
        self.assertEqual(r.detected_type, "")


# ===================================================================
# sniff_binary() — string-input path
# ===================================================================

class TestSniffBinary(unittest.TestCase):
    """sniff_binary() takes a string and returns anomaly flags."""

    def test_plain_text_string(self):
        flags = sniff_binary("Hello world, just a normal sentence.")
        self.assertEqual(flags, [])

    def test_pdf_string(self):
        flags = sniff_binary("%PDF-1.7 some document text")
        self.assertIn("embedded_pdf", flags)
        self.assertIn("embedded_document", flags)

    def test_rtf_string(self):
        flags = sniff_binary("{\\rtf1\\ansi document text here")
        self.assertIn("embedded_rtf", flags)

    def test_shebang_string(self):
        flags = sniff_binary("#!/usr/bin/env python3\nprint('hi')")
        self.assertIn("embedded_shebang", flags)
        self.assertIn("embedded_executable", flags)

    def test_gif_string(self):
        flags = sniff_binary("GIF89a" + "\x00" * 20)
        self.assertIn("embedded_gif", flags)


# ===================================================================
# Base64 blob detection
# ===================================================================

class TestBase64BlobDetection(unittest.TestCase):
    """Base64 blobs in text should be flagged."""

    def test_long_base64_blob(self):
        # 64+ chars of valid base64 (16 groups of 4)
        blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJz"
        blob += "dHV2d3h5ejAxMjM0NTY3ODk="
        flags = sniff_binary("Here is a payload: " + blob)
        self.assertIn("base64_blob_detected", flags)

    def test_short_base64_not_flagged(self):
        # Only 12 chars — too short to trigger (min 64)
        flags = sniff_binary("Token: QUJDRA==")
        self.assertNotIn("base64_blob_detected", flags)

    def test_regex_matches_valid_base64(self):
        blob = "A" * 64  # 16 groups of 4
        self.assertTrue(_BASE64_BLOB_RE.search(blob))

    def test_regex_no_match_short(self):
        self.assertFalse(_BASE64_BLOB_RE.search("ABCD"))


# ===================================================================
# Data URI detection
# ===================================================================

class TestDataURIDetection(unittest.TestCase):
    """data: URI schemes in text should be flagged."""

    def test_data_uri_png(self):
        uri = "data:image/png;base64," + "A" * 100
        flags = sniff_binary("Image: " + uri)
        self.assertIn("data_uri_detected", flags)
        self.assertIn("data_uri_type_image_png", flags)

    def test_data_uri_jpeg(self):
        uri = "data:image/jpeg;base64," + "B" * 100
        flags = sniff_binary(uri)
        self.assertIn("data_uri_detected", flags)
        self.assertIn("data_uri_type_image_jpeg", flags)

    def test_data_uri_pdf(self):
        uri = "data:application/pdf;base64," + "C" * 100
        flags = sniff_binary(uri)
        self.assertIn("data_uri_detected", flags)
        self.assertIn("data_uri_type_application_pdf", flags)

    def test_data_uri_no_media_type(self):
        uri = "data:;base64," + "D" * 100
        flags = sniff_binary("payload: " + uri)
        self.assertIn("data_uri_detected", flags)

    def test_no_data_uri_in_plain_text(self):
        flags = sniff_binary("This is just plain text with no URIs.")
        self.assertNotIn("data_uri_detected", flags)

    def test_data_uri_regex_match(self):
        uri = "data:text/html;base64," + "Z" * 30
        self.assertTrue(_DATA_URI_RE.search(uri))

    def test_data_uri_regex_too_short_payload(self):
        # Only 5 chars of base64 — below the 20-char minimum
        uri = "data:text/html;base64,ABCDE"
        self.assertFalse(_DATA_URI_RE.search(uri))


# ===================================================================
# Sanitizer integration — executables rejected
# ===================================================================

class TestSanitizerRejectsExecutables(unittest.TestCase):
    """Verify that layer0_sanitize() rejects executable binaries."""

    def test_exe_rejected_by_sanitizer(self):
        """PE executable bytes should produce a rejected Layer0Result."""
        try:
            from src.layer0.sanitizer import layer0_sanitize
        except ImportError:
            self.skipTest("Sanitizer import requires all L0 modules")
            return

        exe_bytes = b"MZ" + b"\x00" * 200
        result = layer0_sanitize(exe_bytes)
        self.assertTrue(result.rejected)
        self.assertIn("exe_pe", result.rejection_reason)

    def test_elf_rejected_by_sanitizer(self):
        """ELF executable bytes should produce a rejected Layer0Result."""
        try:
            from src.layer0.sanitizer import layer0_sanitize
        except ImportError:
            self.skipTest("Sanitizer import requires all L0 modules")
            return

        elf_bytes = b"\x7fELF" + b"\x00" * 200
        result = layer0_sanitize(elf_bytes)
        self.assertTrue(result.rejected)
        self.assertIn("embedded_executable", result.anomaly_flags)

    def test_pdf_not_rejected_by_sanitizer(self):
        """PDF is HIGH tier — flagged but NOT rejected."""
        try:
            from src.layer0.sanitizer import layer0_sanitize
        except ImportError:
            self.skipTest("Sanitizer import requires all L0 modules")
            return

        pdf_bytes = b"%PDF-1.7 This is a test document with enough content to pass validation checks"
        result = layer0_sanitize(pdf_bytes)
        self.assertFalse(result.rejected)
        self.assertIn("embedded_pdf", result.anomaly_flags)


# ===================================================================
# html_extractor integration — binary formats bypass HTML parsing
# ===================================================================

class TestHTMLExtractorIntegration(unittest.TestCase):
    """Verify html_extractor delegates binary detection to content_type."""

    def test_pdf_flagged_via_sniff_content_type(self):
        """sniff_content_type should flag PDF via content_type module."""
        from src.layer0.html_extractor import sniff_content_type

        flags = sniff_content_type("%PDF-1.7 some text here")
        self.assertIn("embedded_pdf", flags)

    def test_pdf_bypasses_html_parsing(self):
        """extract_safe_text should flag PDF and skip HTML parsing."""
        from src.layer0.html_extractor import extract_safe_text

        # PDF magic survives string encoding (all ASCII-range bytes)
        text = "%PDF-1.7 some <b>text</b> content"
        result_text, flags = extract_safe_text(text)
        self.assertIn("embedded_pdf", flags)
        self.assertIn("embedded_document", flags)
        # Binary content should NOT be parsed as HTML — raw text returned
        self.assertEqual(result_text, text)

    def test_gif_bypasses_html_parsing(self):
        """extract_safe_text should flag GIF and skip HTML parsing."""
        from src.layer0.html_extractor import extract_safe_text

        # GIF magic bytes are ASCII-safe and survive string round-trip
        text = "GIF89a" + "\x00" * 30
        result_text, flags = extract_safe_text(text)
        self.assertIn("embedded_gif", flags)
        self.assertIn("embedded_image", flags)
        # Binary content should NOT be parsed as HTML
        self.assertEqual(result_text, text)

    def test_high_byte_magic_needs_bytes_path(self):
        """Formats with high bytes (e.g. PNG 0x89) cannot be detected
        via string path because UTF-8 encoding expands them.  This is
        expected: use detect_content_type(bytes) for those."""
        from src.layer0.html_extractor import extract_safe_text

        # \x89 in Python str is U+0089 -> 2 bytes in UTF-8 (c2 89)
        text = "\x89PNG\r\n\x1a\n" + "\x00" * 30
        result_text, flags = extract_safe_text(text)
        # No binary flag expected: high bytes don't survive str->bytes
        self.assertNotIn("embedded_png", flags)

    def test_html_still_parsed(self):
        """Plain HTML should still be parsed and stripped normally."""
        from src.layer0.html_extractor import extract_safe_text

        text = "<html><body><p>Hello world</p></body></html>"
        result_text, flags = extract_safe_text(text)
        self.assertIn("magic_bytes_html", flags)
        self.assertIn("Hello world", result_text)


if __name__ == "__main__":
    unittest.main()
