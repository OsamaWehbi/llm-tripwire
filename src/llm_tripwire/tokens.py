"""Minting canary values.

Every canary carries a random 10-character ID from a 32-letter alphabet without look-alike characters (no 0, 1, I or
O). That is 50 bits of randomness, so an ID never shows up in text by chance, and the detector only has to find the
ID to recognise any form of the canary: a phrase, a fake API key, a URL or an email address.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from enum import StrEnum

ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
ID_LENGTH = 10
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

ADJECTIVES = (
    "AMBER", "AZURE", "BRISK", "CEDAR", "COBALT", "COPPER", "CRIMSON", "DUSTY", "EMBER", "FALLOW", "GILDED", "GRANITE",
    "HOLLOW", "IVORY", "JADE", "LUNAR", "MAPLE", "MISTY", "NORTHERN", "OBSIDIAN", "PALE", "QUIET", "RUSTY", "SABLE",
    "SILVER", "SOLAR", "STORMY", "TAWNY", "UMBER", "VELVET", "WINTER", "ZEPHYR",
)  # fmt: skip
NOUNS = (
    "ALBATROSS", "BADGER", "BEACON", "CANYON", "CITADEL", "COMET", "CONDOR", "DELTA", "FALCON", "FJORD", "GLACIER",
    "HARBOR", "HERON", "JUNIPER", "KESTREL", "LANTERN", "MERIDIAN", "OSPREY", "PINNACLE", "QUARRY", "RAVEN", "SUMMIT",
    "TALON", "THICKET", "TUNDRA", "VALLEY", "VERTEX", "WILLOW", "ZENITH", "ORCHARD", "PRAIRIE", "MONSOON",
)  # fmt: skip


class Kind(StrEnum):
    phrase = "phrase"
    key = "key"
    url = "url"
    email = "email"
    doc = "doc"


@dataclass(frozen=True)
class Minted:
    id: str
    value: str


def new_id() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(ID_LENGTH))


def phrase(canary_id: str) -> str:
    return f"{secrets.choice(ADJECTIVES)}-{secrets.choice(NOUNS)}-{canary_id}"


def api_key(canary_id: str) -> str:
    """A fake key. The `twk_` prefix is not used by any real provider, so secret scanners do not mistake it for one."""
    return "twk_" + canary_id + "".join(secrets.choice(BASE62) for _ in range(30))


def url(canary_id: str, callback: str) -> str:
    return callback.rstrip("/") + "/t/" + canary_id


def email(canary_id: str, domain: str, local: str = "audit") -> str:
    return f"{local}.{canary_id.lower()}@{domain.lstrip('@')}"


def mint(kind: Kind, *, callback: str | None = None, domain: str | None = None) -> Minted:
    canary_id = new_id()
    if kind is Kind.phrase:
        value = phrase(canary_id)
    elif kind is Kind.key:
        value = api_key(canary_id)
    elif kind is Kind.url:
        if not callback:
            raise ValueError("a url canary needs --callback, the base URL of your `llm-tripwire serve` endpoint")
        value = url(canary_id, callback)
    elif kind is Kind.email:
        if not domain:
            raise ValueError("an email canary needs --domain, a mail domain you control")
        value = email(canary_id, domain)
    else:
        value = phrase(canary_id)  # a decoy document's headline value; see decoy.py
    return Minted(canary_id, value)
