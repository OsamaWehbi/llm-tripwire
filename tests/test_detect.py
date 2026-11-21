import base64
import codecs
import random

import pytest

from llm_tripwire import Canary, Detector, Kind
from llm_tripwire.detect import normalize
from llm_tripwire.tokens import ALPHABET, api_key, new_id, phrase

CID = "7QK3XM9PAE"  # contains letters with Cyrillic look-alikes (A, E, K, M, P, X)
PHRASE = f"AMBER-HERON-{CID}"
OTHER = "Z2Z2Z2Z2Z2"


@pytest.fixture
def detector():
    return Detector(
        [
            Canary(id=CID, kind=Kind.phrase, value=PHRASE, label="system prompt"),
            Canary(id=OTHER, kind=Kind.key, value=api_key(OTHER), label="tool config"),
        ]
    )


def transforms(hits):
    return [(h.canary_id, h.transform) for h in hits]


CYRILLIC = {"A": 0x0410, "E": 0x0415, "K": 0x041A, "M": 0x041C, "P": 0x0420, "X": 0x0425}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"The code is {PHRASE}.", "verbatim"),
        (f"the code is {PHRASE.lower()}", "verbatim"),
        ("spaced " + " ".join(CID), "reformatted"),
        ("dotted " + ".".join(CID.lower()), "reformatted"),
        ("split 7QK3X-M9PAE", "reformatted"),
        ("cyrillic " + "".join(chr(CYRILLIC[c]) if c in CYRILLIC else c for c in CID), "reformatted"),
        ("fullwidth " + "".join(chr(ord(c) + 0xFEE0) for c in CID), "reformatted"),
        ("backwards " + CID[::-1], "reversed"),
        ("b64 " + base64.b64encode(f"ref={PHRASE}".encode()).decode(), "base64"),
        ("b64url " + base64.urlsafe_b64encode(f"ref={PHRASE}??".encode()).decode().rstrip("="), "base64"),
        ("hex " + PHRASE.encode().hex(), "hex"),
        ("url https://x.example/?q=" + "".join(f"%{b:02X}" for b in CID.encode()), "url-encoded"),
        ("rot13 " + codecs.encode(PHRASE, "rot13"), "rot13"),
        ("double " + base64.b64encode(base64.b64encode(PHRASE.encode())).decode(), "base64+base64"),
    ],
)
def test_transforms_are_detected(detector, text, expected):
    hits = detector.scan(text)
    assert (CID, expected) in transforms(hits)


def test_line_numbers_and_sources(detector):
    hits = detector.scan(f"line one\nline two\nleak: {PHRASE}\n", source="chat.log")
    assert [(h.source, h.line, h.transform) for h in hits] == [("chat.log", 3, "verbatim")]
    assert PHRASE in hits[0].snippet


def test_encoded_hits_point_at_the_encoded_line(detector):
    text = "ok\nok\npayload " + base64.b64encode(PHRASE.encode()).decode() + "\n" + "%41%42%43 harmless"
    hits = detector.scan(text)
    assert [(h.line, h.transform) for h in hits] == [(3, "base64")]


def test_unrelated_text_has_no_hits(detector):
    rng = random.Random(7)
    noise = "".join(rng.choice(ALPHABET + " -_\n") for _ in range(20000))
    assert detector.scan(noise) == []
    assert detector.scan("AMBER-HERON-7QK3XM9PAF") == []  # one character off


def test_snippets_are_ascii(detector):
    text = "fullwidth " + "".join(chr(ord(c) + 0xFEE0) for c in CID)
    (hit,) = detector.scan(text)
    assert hit.snippet.isascii()
    assert "\\uff17" in hit.snippet


def test_revoked_canaries_are_ignored():
    revoked = Canary(id=CID, kind=Kind.phrase, value=PHRASE, active=False)
    assert Detector([revoked]).scan(PHRASE) == []
    assert Detector([]).scan(PHRASE) == []


def test_redact(detector):
    text = f"key {api_key(OTHER)} and code {' '.join(CID)} end"
    redacted = detector.redact(text)
    assert OTHER not in redacted
    assert "[redacted]" in redacted
    assert detector.scan(redacted) == []
    assert redacted.endswith(" end")


def test_stream_finds_canary_split_across_chunks(detector):
    stream = detector.stream()
    pieces = ["Sure, the internal reference is AMBER-HER", "ON-7QK3", "XM9PAE. Anything else?"]
    found = []
    for piece in pieces:
        found.extend(stream.feed(piece))
    assert [(h.canary_id, h.transform) for h in found] == [(CID, "verbatim")]
    assert stream.feed(f" again {PHRASE}") == []  # reported once per stream


def test_stream_buffer_is_bounded(detector):
    stream = detector.stream()
    for _ in range(200):
        stream.feed("x" * 1000)
    assert len(stream.buffer) <= stream.window


def test_normalize_keeps_positions():
    norm = normalize("A-b C")
    assert norm.text == "abc"
    assert norm.positions == [0, 2, 4]


def test_minted_values_contain_their_id():
    cid = new_id()
    assert len(cid) == 10
    assert set(cid) <= set(ALPHABET)
    for value in (phrase(cid), api_key(cid)):
        assert cid in value
    assert api_key(cid).startswith("twk_")


def test_stream_guard_example_blocks_the_leak(capsys):
    import runpy

    example = runpy.run_path(
        str(__import__("pathlib").Path(__file__).resolve().parent.parent / "examples" / "stream_guard.py")
    )
    assert example["main"]() == 1
    assert "[blocked: canary" in capsys.readouterr().out
