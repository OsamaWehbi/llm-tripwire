"""Find canaries in text, including copies a model or an attacker has reformatted or encoded.

A model that leaks a system prompt rarely copies it byte for byte. It may change case, add spaces or dashes, swap in
look-alike letters, spell the value backwards, or wrap it in base64 to slip past a filter. The detector reduces text
to lower-case letters and digits (after folding full-width and Cyrillic or Greek look-alikes to ASCII) and searches
for each canary's ID there, keeping a map back to the original offsets. It also searches the base64, hex,
percent-encoded and ROT13 decodings of the text.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote_plus

from pydantic import BaseModel

from llm_tripwire.registry import Canary, Registry

# Cyrillic and Greek letters that look like Latin ones, written as code points so the source stays ASCII.
_CONFUSABLES = {
    **dict.fromkeys((0x0430, 0x0410, 0x0391, 0x03B1), "a"),
    **dict.fromkeys((0x0412, 0x0392, 0x0432), "b"),
    **dict.fromkeys((0x0441, 0x0421, 0x03F2), "c"),
    **dict.fromkeys((0x0435, 0x0415, 0x0395), "e"),
    **dict.fromkeys((0x041D, 0x043D, 0x0397), "h"),
    **dict.fromkeys((0x0456, 0x0406, 0x0399, 0x03B9), "i"),
    **dict.fromkeys((0x0458, 0x0408), "j"),
    **dict.fromkeys((0x043A, 0x041A, 0x039A, 0x03BA), "k"),
    **dict.fromkeys((0x041C, 0x043C, 0x039C), "m"),
    **dict.fromkeys((0x039D,), "n"),
    **dict.fromkeys((0x043E, 0x041E, 0x039F, 0x03BF), "o"),
    **dict.fromkeys((0x0440, 0x0420, 0x03A1, 0x03C1), "p"),
    **dict.fromkeys((0x0455, 0x0405), "s"),
    **dict.fromkeys((0x0442, 0x0422, 0x03A4, 0x03C4), "t"),
    **dict.fromkeys((0x0445, 0x0425, 0x03A7, 0x03C7), "x"),
    **dict.fromkeys((0x0443, 0x0423, 0x03A5, 0x03B3), "y"),
    **dict.fromkeys((0x0396,), "z"),
}

_BASE64_RUN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
# A run of URL characters that contains at least three percent-escapes.
_PERCENT_RUN = re.compile(r"[A-Za-z0-9._~+-]*(?:%[0-9A-Fa-f]{2}[A-Za-z0-9._~+-]*){3,}")
MAX_DEPTH = 2
MAX_TEXT = 10_000_000


class Hit(BaseModel):
    canary_id: str
    kind: str
    label: str
    transform: str
    source: str = ""
    line: int | None = None
    snippet: str = ""

    @property
    def obfuscated(self) -> bool:
        return self.transform != "verbatim"


@dataclass
class _Normalized:
    text: str
    positions: list[int]


def normalize(text: str) -> _Normalized:
    """Lower-case letters and digits only, with a map from each kept character to its offset in `text`."""
    out: list[str] = []
    positions: list[int] = []
    for i, ch in enumerate(text):
        if ch.isascii():
            if ch.isalnum():
                out.append(ch.lower())
                positions.append(i)
            continue
        mapped = _CONFUSABLES.get(ord(ch))
        if mapped is None:
            folded = unicodedata.normalize("NFKC", ch)
            mapped = folded.lower() if folded.isascii() and folded.isalnum() else ""
        for c in mapped:
            out.append(c)
            positions.append(i)
    return _Normalized("".join(out), positions)


def _snippet(text: str, start: int, end: int, width: int = 30) -> str:
    lo, hi = max(0, start - width), min(len(text), end + width)
    s = re.sub(r"\s+", " ", text[lo:hi]).strip()
    # ASCII only: look-alike letters stay visible as escapes, and logs survive any console encoding.
    s = "".join(c if c.isascii() and c.isprintable() else f"\\u{ord(c):04x}" for c in s)
    return ("..." if lo else "") + s + ("..." if hi < len(text) else "")


def _printable_ratio(s: str) -> float:
    return sum(c.isprintable() or c.isspace() for c in s) / len(s) if s else 0.0


def _b64(run: str) -> str | None:
    stripped = run.rstrip("=")
    padded = stripped + "=" * (-len(stripped) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            text = decoder(padded).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _printable_ratio(text) > 0.85:
            return text
    return None


def _hex(run: str) -> str | None:
    try:
        text = bytes.fromhex(run).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _printable_ratio(text) > 0.85 else None


class Detector:
    def __init__(self, canaries: list[Canary] | Registry) -> None:
        items = canaries.active if isinstance(canaries, Registry) else [c for c in canaries if c.active]
        self.by_core = {c.core: c for c in items}
        self._forward = re.compile("|".join(map(re.escape, self.by_core))) if self.by_core else None
        self._reversed = re.compile("|".join(re.escape(k[::-1]) for k in self.by_core)) if self.by_core else None

    @property
    def longest(self) -> int:
        return max((len(c.value) for c in self.by_core.values()), default=0)

    def scan(self, text: str, source: str = "") -> list[Hit]:
        if self._forward is None or not text:
            return []
        text = text[:MAX_TEXT]
        hits: list[Hit] = []
        self._scan(text, text, source, "", 0, hits)
        seen: set[tuple[str, str, int | None]] = set()
        unique = []
        for h in hits:
            key = (h.canary_id, h.transform, h.line)
            if key not in seen:
                seen.add(key)
                unique.append(h)
        return sorted(unique, key=lambda h: (h.line or 0, h.canary_id, h.transform))

    def _hit(self, canary: Canary, transform: str, original: str, start: int, end: int, source: str) -> Hit:
        line = original.count("\n", 0, start) + 1
        return Hit(
            canary_id=canary.id,
            kind=str(canary.kind),
            label=canary.label,
            transform=transform,
            source=source,
            line=line,
            snippet=_snippet(original, start, end),
        )

    def _scan(self, text: str, original: str, source: str, chain: str, anchor: int, hits: list[Hit]) -> None:
        """Search `text`. When it is a decoding of part of `original`, `anchor` is where that part starts."""
        if self._forward is None or self._reversed is None:
            return
        decoded = bool(chain)
        norm = normalize(text)
        lowered = text.lower()
        for regex, reverse in ((self._forward, False), (self._reversed, True)):
            for m in regex.finditer(norm.text):
                core = m.group(0)[::-1] if reverse else m.group(0)
                canary = self.by_core[core]
                start, end = norm.positions[m.start()], norm.positions[m.end() - 1] + 1
                if reverse:
                    transform = "reversed"
                elif lowered[start:end] == core:
                    transform = "verbatim"
                else:
                    transform = "reformatted"
                if decoded:
                    transform = chain if transform == "verbatim" else f"{chain}+{transform}"
                    hits.append(self._hit(canary, transform, original, anchor, anchor + 1, source))
                else:
                    hits.append(self._hit(canary, transform, original, start, end, source))

        depth = chain.count("+") + 1 if chain else 0
        if depth >= MAX_DEPTH:
            return
        prefix = f"{chain}+" if chain else ""

        def at(offset: int) -> int:
            return anchor if decoded else offset

        for m in _BASE64_RUN.finditer(text):
            payload = _b64(m.group(0))
            if payload:
                self._scan(payload, original, source, prefix + "base64", at(m.start()), hits)
        for m in _HEX_RUN.finditer(text):
            payload = _hex(m.group(0))
            if payload:
                self._scan(payload, original, source, prefix + "hex", at(m.start()), hits)
        for m in _PERCENT_RUN.finditer(text):
            self._scan(unquote_plus(m.group(0)), original, source, prefix + "url-encoded", at(m.start()), hits)
        if not chain:
            # Rotate the normalised text, so characters that only become ASCII letters after folding are not
            # mistaken for ROT13.
            rotated = codecs.encode(norm.text, "rot13")
            for m in self._forward.finditer(rotated):
                canary = self.by_core[m.group(0)]
                start, end = norm.positions[m.start()], norm.positions[m.end() - 1] + 1
                hits.append(self._hit(canary, "rot13", original, start, end, source))

    def redact(self, text: str, replacement: str = "[redacted]") -> str:
        """Replace verbatim and reformatted canaries in `text`. Encoded copies cannot be cut out cleanly; use scan()."""
        if self._forward is None:
            return text
        norm = normalize(text)
        spans = [
            (norm.positions[m.start()], norm.positions[m.end() - 1] + 1) for m in self._forward.finditer(norm.text)
        ]
        for start, end in sorted(spans, reverse=True):
            text = text[:start] + replacement + text[end:]
        return text

    def stream(self) -> StreamScanner:
        return StreamScanner(self)


class StreamScanner:
    """Scan text that arrives in pieces, such as a streamed model response.

    A canary split across two chunks is still found, because the scanner keeps a tail of recent text. Each canary is
    reported once per stream.
    """

    def __init__(self, detector: Detector, source: str = "stream") -> None:
        self.detector = detector
        self.source = source
        self.window = max(256, detector.longest * 8)
        self.buffer = ""
        self.reported: set[str] = set()

    def feed(self, chunk: str) -> list[Hit]:
        self.buffer = (self.buffer + chunk)[-self.window * 2 :]
        new = []
        for hit in self.detector.scan(self.buffer, self.source):
            if hit.canary_id not in self.reported:
                self.reported.add(hit.canary_id)
                hit.line = None
                new.append(hit)
        if len(self.buffer) > self.window:
            self.buffer = self.buffer[-self.window :]
        return new
