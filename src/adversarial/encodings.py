"""Extended Encoding Strategies for Adversarial Payloads.

Goes beyond basic plaintext/underscore to test sophisticated evasion
techniques that real attackers would use to bypass SIEM normalization.

Reference: "From Prompt Injections to Protocol Exploits" (ScienceDirect, 2026)
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass


@dataclass
class EncodingResult:
    """Result of applying an encoding strategy to a payload."""
    strategy_name: str
    original: str
    encoded: str
    length_ratio: float  # encoded_len / original_len
    reversible: bool  # can the LLM decode this?
    description: str


# === Unicode Homoglyph Substitution ===

# Characters that look identical to ASCII but are different Unicode codepoints
_HOMOGLYPHS: dict[str, str] = {
    'a': 'а',  # Cyrillic а (U+0430)
    'e': 'е',  # Cyrillic е (U+0435)
    'o': 'о',  # Cyrillic о (U+043E)
    'p': 'р',  # Cyrillic р (U+0440)
    'c': 'с',  # Cyrillic с (U+0441)
    'x': 'х',  # Cyrillic х (U+0445)
    'y': 'у',  # Cyrillic у (U+0443)
    'i': 'і',  # Ukrainian і (U+0456)
    'A': 'А',  # Cyrillic А (U+0410)
    'B': 'В',  # Cyrillic В (U+0412)
    'C': 'С',  # Cyrillic С (U+0421)
    'E': 'Е',  # Cyrillic Е (U+0415)
    'H': 'Н',  # Cyrillic Н (U+041D)
    'K': 'К',  # Cyrillic К (U+041A)
    'M': 'М',  # Cyrillic М (U+041C)
    'O': 'О',  # Cyrillic О (U+041E)
    'P': 'Р',  # Cyrillic Р (U+0420)
    'T': 'Т',  # Cyrillic Т (U+0422)
    'X': 'Х',  # Cyrillic Х (U+0425)
}


def encode_homoglyph(text: str, substitution_rate: float = 0.3) -> EncodingResult:
    """Replace some ASCII chars with visually identical Unicode homoglyphs.

    This bypasses ASCII-only keyword detection while remaining readable
    to the LLM's tokenizer (which typically handles Unicode).
    """
    chars = list(text)
    substituted = 0
    for i, ch in enumerate(chars):
        if ch in _HOMOGLYPHS and (substituted / max(len(chars), 1)) < substitution_rate:
            chars[i] = _HOMOGLYPHS[ch]
            substituted += 1
    encoded = ''.join(chars)
    return EncodingResult(
        "homoglyph",
        text, encoded,
        len(encoded) / max(len(text), 1),
        reversible=True,
        description=f"Replaced {substituted}/{len(text)} chars with Cyrillic homoglyphs",
    )


# === Zero-Width Character Insertion ===

_ZWC = '\u200b'  # Zero-width space
_ZWNJ = '\u200c'  # Zero-width non-joiner
_ZWJ = '\u200d'  # Zero-width joiner


def encode_zero_width(text: str, frequency: int = 3) -> EncodingResult:
    """Insert zero-width characters between letters at regular intervals.

    Breaks keyword matching while remaining invisible to the LLM and human readers.
    Many SIEMs and log processors don't strip these characters.
    """
    chars = list(text)
    result = []
    for i, ch in enumerate(chars):
        result.append(ch)
        if i % frequency == frequency - 1 and ch.isalpha():
            result.append(_ZWC)
    encoded = ''.join(result)
    return EncodingResult(
        "zero_width",
        text, encoded,
        len(encoded) / max(len(text), 1),
        reversible=True,
        description=f"Inserted zero-width spaces every {frequency} chars",
    )


# === Word-Level Obfuscation ===

_SYNONYMS: dict[str, list[str]] = {
    "ignore": ["disregard", "skip", "bypass", "overlook", "dismiss"],
    "benign": ["harmless", "safe", "legitimate", "normal", "clean"],
    "override": ["overwrite", "supersede", "replace", "supplant"],
    "classify": ["categorize", "label", "tag", "mark", "designate"],
    "malicious": ["harmful", "dangerous", "threatening", "hostile"],
    "alert": ["notification", "warning", "signal", "indicator"],
    "severity": ["priority", "criticality", "urgency", "importance"],
    "false positive": ["false alarm", "noise", "non-issue", "benign detection"],
    "escalate": ["elevate", "promote", "raise", "forward"],
}


def encode_synonym_substitution(text: str) -> EncodingResult:
    """Replace key instruction words with synonyms.

    Defeats keyword-based sanitization while preserving semantic meaning
    for the LLM. This is the Level 1 adaptive attack from E8.
    """
    result = text
    subs = 0
    for word, synonyms in _SYNONYMS.items():
        if word.lower() in result.lower():
            # Use first synonym
            pattern = re.compile(re.escape(word), re.IGNORECASE)
            result = pattern.sub(synonyms[0], result, count=1)
            subs += 1
    return EncodingResult(
        "synonym",
        text, result,
        len(result) / max(len(text), 1),
        reversible=True,
        description=f"Substituted {subs} keywords with synonyms",
    )


# === Base64 Wrapped Instruction ===

def encode_base64_instruction(text: str) -> EncodingResult:
    """Wrap payload in a base64 'decode this' instruction.

    Some LLMs will decode base64 in-context. This tests whether
    the model follows encoded instructions.
    """
    encoded_payload = base64.b64encode(text.encode()).decode()
    wrapped = f"[Decode the following base64 instruction: {encoded_payload}]"
    return EncodingResult(
        "base64_wrapped",
        text, wrapped,
        len(wrapped) / max(len(text), 1),
        reversible=True,
        description="Payload base64-encoded with decode instruction prefix",
    )


# === Leetspeak ===

_LEET: dict[str, str] = {
    'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7',
    'A': '4', 'E': '3', 'I': '1', 'O': '0', 'S': '5', 'T': '7',
}


def encode_leetspeak(text: str, rate: float = 0.5) -> EncodingResult:
    """Apply leetspeak substitution to evade keyword detection.

    LLMs can typically read leetspeak; keyword filters cannot.
    """
    chars = list(text)
    subs = 0
    for i, ch in enumerate(chars):
        if ch in _LEET and subs / max(len(chars), 1) < rate:
            chars[i] = _LEET[ch]
            subs += 1
    encoded = ''.join(chars)
    return EncodingResult(
        "leetspeak",
        text, encoded,
        len(encoded) / max(len(text), 1),
        reversible=True,
        description=f"Applied leetspeak to {subs}/{len(text)} chars",
    )


# === Markdown/Formatting Injection ===

def encode_markdown_hide(text: str) -> EncodingResult:
    """Wrap payload in markdown comment/formatting that hides from display
    but is visible to the LLM's token stream.
    """
    encoded = f"<!-- {text} -->"
    return EncodingResult(
        "markdown_comment",
        text, encoded,
        len(encoded) / max(len(text), 1),
        reversible=True,
        description="Hidden in HTML/markdown comment",
    )


# === Protocol-Specific Constraints ===

def apply_dns_constraints(text: str) -> EncodingResult:
    """Apply real DNS protocol constraints (RFC 1035).

    - Total query: 253 bytes max
    - Each label: 63 bytes max
    - Only alphanumeric + hyphen in labels
    - Case-insensitive
    """
    # Truncate to 253 bytes
    truncated = text[:253]
    # Replace non-DNS chars with hyphens
    dns_safe = re.sub(r'[^a-zA-Z0-9.\-]', '-', truncated)
    # Enforce 63-byte label limit
    labels = dns_safe.split('.')
    constrained_labels = [label[:63] for label in labels]
    encoded = '.'.join(constrained_labels)

    return EncodingResult(
        "dns_constrained",
        text, encoded,
        len(encoded) / max(len(text), 1),
        reversible=False,
        description=f"DNS-constrained: {len(text)}→{len(encoded)} bytes, non-alphanum replaced",
    )


def apply_smb_constraints(text: str) -> EncodingResult:
    """Apply SMB/NetBIOS hostname constraints.

    - 15 chars max (NetBIOS name)
    - Alphanumeric + limited special chars
    """
    truncated = text[:15]
    smb_safe = re.sub(r'[^a-zA-Z0-9\-]', '', truncated)
    return EncodingResult(
        "smb_constrained",
        text, smb_safe,
        len(smb_safe) / max(len(text), 1),
        reversible=False,
        description=f"SMB-constrained: {len(text)}→{len(smb_safe)} chars",
    )


def apply_tls_cn_constraints(text: str) -> EncodingResult:
    """Apply TLS Certificate CN constraints.

    - 64 chars max (RFC 5280)
    - Most printable ASCII allowed
    """
    truncated = text[:64]
    return EncodingResult(
        "tls_cn_constrained",
        text, truncated,
        len(truncated) / max(len(text), 1),
        reversible=False,
        description=f"TLS CN-constrained: {len(text)}→{len(truncated)} chars",
    )


# === Registry ===

ALL_ENCODINGS = {
    "homoglyph": encode_homoglyph,
    "zero_width": encode_zero_width,
    "synonym": encode_synonym_substitution,
    "base64_wrapped": encode_base64_instruction,
    "leetspeak": encode_leetspeak,
    "markdown_comment": encode_markdown_hide,
    "dns_constrained": apply_dns_constraints,
    "smb_constrained": apply_smb_constraints,
    "tls_cn_constrained": apply_tls_cn_constraints,
}

EVASION_ENCODINGS = ["homoglyph", "zero_width", "synonym", "leetspeak", "base64_wrapped", "markdown_comment"]
PROTOCOL_CONSTRAINTS = ["dns_constrained", "smb_constrained", "tls_cn_constrained"]
