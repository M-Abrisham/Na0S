"""Buff mutation transforms for combinatorial evasion testing.

Each Buff takes a text string and returns a mutated version.
When combined with probes, this creates an N-probes x M-buffs test matrix
that reveals which encoding evasions the detector is blind to.
"""

import base64
import codecs


class Buff:
    """Base class for prompt mutation transforms."""
    name = ""

    def apply(self, text):
        raise NotImplementedError


class Base64Buff(Buff):
    name = "base64"

    def apply(self, text):
        return base64.b64encode(text.encode("utf-8")).decode("ascii")


class ROT13Buff(Buff):
    name = "rot13"

    def apply(self, text):
        return codecs.encode(text, "rot_13")


class LeetBuff(Buff):
    name = "leet"

    _MAP = str.maketrans({
        "a": "4", "A": "4",
        "e": "3", "E": "3",
        "i": "1", "I": "1",
        "o": "0", "O": "0",
        "s": "5", "S": "5",
        "t": "7", "T": "7",
    })

    def apply(self, text):
        return text.translate(self._MAP)


class FullwidthBuff(Buff):
    name = "fullwidth"

    def apply(self, text):
        result = []
        for ch in text:
            cp = ord(ch)
            # ASCII printable range 0x21-0x7E -> fullwidth 0xFF01-0xFF5E
            if 0x21 <= cp <= 0x7E:
                result.append(chr(cp + 0xFEE0))
            elif ch == " ":
                result.append("\u3000")  # ideographic space
            else:
                result.append(ch)
        return "".join(result)


class ZeroWidthBuff(Buff):
    name = "zwj"

    _ZWJ = "\u200D"  # zero-width joiner

    def apply(self, text):
        return self._ZWJ.join(text)


class HomoglyphBuff(Buff):
    name = "homoglyph"

    _MAP = str.maketrans({
        "a": "\u0430",  # Cyrillic а
        "c": "\u0441",  # Cyrillic с
        "e": "\u0435",  # Cyrillic е
        "o": "\u043E",  # Cyrillic о
        "p": "\u0440",  # Cyrillic р
        "s": "\u0455",  # Cyrillic ѕ
        "x": "\u0445",  # Cyrillic х
        "y": "\u0443",  # Cyrillic у
    })

    def apply(self, text):
        return text.translate(self._MAP)


class ReverseBuff(Buff):
    name = "reverse"

    def apply(self, text):
        return text[::-1]


class CaseAlternatingBuff(Buff):
    name = "altcase"

    def apply(self, text):
        result = []
        i = 0
        for ch in text:
            if ch.isalpha():
                result.append(ch.upper() if i % 2 == 0 else ch.lower())
                i += 1
            else:
                result.append(ch)
        return "".join(result)


ALL_BUFFS = [
    Base64Buff,
    ROT13Buff,
    LeetBuff,
    FullwidthBuff,
    ZeroWidthBuff,
    HomoglyphBuff,
    ReverseBuff,
    CaseAlternatingBuff,
]
