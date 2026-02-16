"""Tests for chunked ML analysis in predict.py.

Run: python3 -m unittest tests/test_chunked_analysis.py -v
"""

import os
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from predict import (
    _chunk_text,
    _head_tail_extract,
    _CHUNK_WORD_THRESHOLD,
    _CHUNK_MAX_TOKENS,
    _CHUNK_OVERLAP,
    _HEAD_TOKENS,
    _TAIL_TOKENS,
)


class TestChunkText(unittest.TestCase):
    """Test _chunk_text() splitting logic."""

    def test_short_text_single_chunk(self):
        text = "word " * 100
        chunks = _chunk_text(text.strip())
        self.assertEqual(len(chunks), 1)

    def test_exact_threshold_single_chunk(self):
        text = " ".join(["word"] * _CHUNK_MAX_TOKENS)
        chunks = _chunk_text(text)
        self.assertEqual(len(chunks), 1)

    def test_above_threshold_multiple_chunks(self):
        text = " ".join(["word"] * (_CHUNK_MAX_TOKENS + 100))
        chunks = _chunk_text(text)
        self.assertGreater(len(chunks), 1)

    def test_all_words_covered(self):
        """Every word from the original text should appear in at least one chunk."""
        words = ["w{}".format(i) for i in range(800)]
        text = " ".join(words)
        chunks = _chunk_text(text)
        covered = set()
        for chunk in chunks:
            covered.update(chunk.split())
        self.assertEqual(covered, set(words))

    def test_overlap_exists(self):
        """Adjacent chunks should share overlapping words."""
        words = ["w{}".format(i) for i in range(1024)]
        text = " ".join(words)
        chunks = _chunk_text(text, max_tokens=512, overlap=64)
        if len(chunks) >= 2:
            first_words = set(chunks[0].split())
            second_words = set(chunks[1].split())
            overlap = first_words & second_words
            self.assertGreater(len(overlap), 0)

    def test_empty_text(self):
        chunks = _chunk_text("")
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0], "")

    def test_single_word(self):
        chunks = _chunk_text("hello")
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0], "hello")

    def test_very_long_text(self):
        text = " ".join(["word"] * 5000)
        chunks = _chunk_text(text)
        self.assertGreater(len(chunks), 5)


class TestHeadTailExtract(unittest.TestCase):
    """Test _head_tail_extract() logic."""

    def test_short_text_unchanged(self):
        text = " ".join(["word"] * 100)
        result = _head_tail_extract(text)
        self.assertEqual(result, text)

    def test_exact_threshold_unchanged(self):
        text = " ".join(["word"] * (_HEAD_TOKENS + _TAIL_TOKENS))
        result = _head_tail_extract(text)
        self.assertEqual(result, text)

    def test_long_text_extracted(self):
        words = ["w{}".format(i) for i in range(2000)]
        text = " ".join(words)
        result = _head_tail_extract(text)
        result_words = result.split()
        # Should contain head + tail tokens
        self.assertEqual(len(result_words), _HEAD_TOKENS + _TAIL_TOKENS)

    def test_head_preserved(self):
        words = ["w{}".format(i) for i in range(2000)]
        text = " ".join(words)
        result = _head_tail_extract(text)
        result_words = result.split()
        # First N words should be the head
        for i in range(_HEAD_TOKENS):
            self.assertEqual(result_words[i], "w{}".format(i))

    def test_tail_preserved(self):
        words = ["w{}".format(i) for i in range(2000)]
        text = " ".join(words)
        result = _head_tail_extract(text)
        result_words = result.split()
        # Last N words should be the tail
        for i in range(_TAIL_TOKENS):
            expected_idx = 2000 - _TAIL_TOKENS + i
            self.assertEqual(
                result_words[_HEAD_TOKENS + i],
                "w{}".format(expected_idx),
            )

    def test_middle_dropped(self):
        """Words in the middle should NOT be in the result."""
        words = ["w{}".format(i) for i in range(2000)]
        text = " ".join(words)
        result = _head_tail_extract(text)
        # A word from the dead middle should be gone
        self.assertNotIn("w1000", result)

    def test_empty_text(self):
        result = _head_tail_extract("")
        self.assertEqual(result, "")


class TestChunkedAnalysisConstants(unittest.TestCase):
    """Verify sensible default constants."""

    def test_threshold(self):
        self.assertEqual(_CHUNK_WORD_THRESHOLD, 512)

    def test_max_tokens(self):
        self.assertEqual(_CHUNK_MAX_TOKENS, 512)

    def test_overlap(self):
        self.assertEqual(_CHUNK_OVERLAP, 64)

    def test_head_tokens(self):
        self.assertEqual(_HEAD_TOKENS, 256)

    def test_tail_tokens(self):
        self.assertEqual(_TAIL_TOKENS, 256)


if __name__ == "__main__":
    unittest.main()
