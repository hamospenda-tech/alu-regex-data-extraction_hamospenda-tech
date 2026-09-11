#!/usr/bin/env python3
"""
main.py — Data Extraction & Secure Validation

Reads raw, messy production-style text (e.g. a support ticket export) and:
  1. Extracts structured data (emails, credit cards, phone numbers, URLs,
     time values, HTML tags, hashtags, currency amounts) using regex.
  2. Validates that extracted data is well-formed (not just pattern-matched —
     e.g. credit cards are checksum-validated with the Luhn algorithm).
  3. Treats the input as untrusted: content that looks like it's trying to
     manipulate parsing (script tags, SQL-injection keywords, header
     injection, path traversal, oversized junk fields) is detected and
     excluded from "valid" results rather than silently accepted.
  4. Produces a human-readable console summary and a JSON output file,
     with sensitive fields (emails, card numbers) masked before they are
     ever printed or written to disk/logs.

Usage:
    python3 main.py
    (reads ../input/raw-text.txt relative to this file, writes
     ../output/sample-output.json)
"""

import json
import os
import re
import html as html_lib
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# 1. REGEX PATTERNS
# ---------------------------------------------------------------------------
# Each pattern is written to be "good enough for realistic, messy text" —
# not a perfect RFC-compliant implementation (email/URL specs are notoriously
# huge). The goal is correctness on real-world variation, not academic
# completeness.

# --- Email -------------------------------------------------------------
# Standard local-part@domain.tld shape. Because the domain half REQUIRES a
# literal "." followed by 2+ letters, this pattern naturally rejects junk
# like "alsoNotReal@nodot" (no dot in domain) and "@missingusername.com"
# (empty local part) without any extra code — the regex IS the validation
# for those cases.
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

# ALU-specific domains. Order matters: si.alueducation.com and
# alumni.alueducation.com are SUBDOMAINS of alueducation.com, so the more
# specific ones must be checked first or every ALU address would be
# misclassified as generic "ALU official".
ALU_DOMAINS_IN_PRIORITY_ORDER = [
    ("si.alueducation.com", "ALU SI"),
    ("alumni.alueducation.com", "ALU Alumni"),
    ("alueducation.com", "ALU Official"),
]

# --- Credit card ---------------------------------------------------------
# Matches 13-19 digit sequences, optionally grouped with spaces or dashes
# (the common real-world formats: "4111111111111111", "4539 1488 0343 6467",
# "5555-4444-3333-1111"). Pattern match alone is NOT treated as "valid" —
# see luhn_check() below. A regex can only tell you "this looks card-shaped",
# never "this is a real card number".
CREDIT_CARD_RE = re.compile(r'\b(?:\d[ -]?){12,18}\d\b')

# --- Phone number ----------------------------------------------------------
# Handles: "+250 788 123 456", "078-812-3456", "(078) 812 3456",
# "0788.123.456". Negative lookbehind/lookahead prevent it from matching
# inside a longer uninterrupted digit run (so it won't accidentally grab a
# chunk out of a 16-digit credit card number). Total digit count is capped
# low enough that it structurally cannot match a card number.
PHONE_RE = re.compile(
    r'(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{2,4}[\s.-]?)'
    r'\d{3}[\s.-]?\d{3,4}(?!\d)'
)

# --- URL ---------------------------------------------------------------
# Covers both "https://..." and bare "www...." links (very common in raw
# scraped/pasted text where the protocol is dropped by whoever typed it).
URL_RE = re.compile(r'\b(?:https?://|www\.)[^\s<>"\']+', re.IGNORECASE)

# --- Time (12h and 24h) -----------------------------------------------------
TIME_RE = re.compile(r'\b([01]?\d|2[0-3]):[0-5]\d\s?(?:[APap][Mm])?\b')

# --- HTML tags -----------------------------------------------------------
# Deliberately broad ("<" + anything but ">" + ">") because attackers don't
# write well-formed HTML — we want to catch <script>, </script>,
# <img ... onerror=...> etc, not just "clean" tags.
HTML_TAG_RE = re.compile(r'<[^>]+>')

# --- Hashtags ------------------------------------------------------------
# A bare "#" followed by digits only (e.g. "ticket #4471") is a reference
# number, not a hashtag — require at least one letter so we don't confuse
# the two. This is a real edge case that shows up constantly in support-
# ticket-style text.
HASHTAG_RE = re.compile(r'#(?=\w*[A-Za-z])\w[\w-]*')

# --- Currency amounts ------------------------------------------------------
CURRENCY_RE = re.compile(
    r'(?:[$€£]\s?\d[\d,]*(?:\.\d+)?)|(?:\b(?:USD|EUR|GBP)\s?\d[\d,]*(?:\.\d+)?)'
)

# ---------------------------------------------------------------------------
# 2. SECURITY / THREAT-DETECTION PATTERNS
# ---------------------------------------------------------------------------
# These exist to prove the program does NOT blindly trust incoming text.
# We are not building a production WAF — the point is to demonstrate
# defensive *awareness*: detect the obvious attack shapes, log them safely
# (never echo raw hostile payloads to output), and make sure sensitive-data
# extraction doesn't get fooled by data hidden inside them.

# Script tags and inline event-handler attributes (onerror=, onload=, etc.)
# are the classic vector for smuggling extra "data" into a text blob.
HOSTILE_ZONE_RE = re.compile(
    r'<script\b[^>]*>.*?</script\s*>|on\w+\s*=\s*(["\']).*?\1',
    re.IGNORECASE | re.DOTALL,
)

SQL_INJECTION_RE = re.compile(
    r"(;\s*DROP\s+TABLE|--\s*$|\bUNION\s+SELECT\b|'\s*OR\s*'1'\s*=\s*'1)",
    re.IGNORECASE,
)

PATH_TRAVERSAL_RE = re.compile(r'(?:\.\./|\.\.\\){2,}')

# CRLF / URL-encoded newline followed by an email-header keyword — a classic
# email-header-injection attempt (trying to sneak in an extra Bcc:, etc.)
HEADER_INJECTION_RE = re.compile(
    r'(?:%0A|%0D|\r|\n)\s*(?:Bcc|Cc|To|Subject)\s*:', re.IGNORECASE
)

# A long run of characters with no whitespace/punctuation is a common shape
# for buffer-stuffing / fuzzing junk. Real tokens (emails, URLs, cards) are
# excluded from this check by using a boundary of length > 50 with no
# structure at all (no @, no dots, no digits pattern).
OVERSIZED_TOKEN_RE = re.compile(r'\b[A-Za-z]{50,}\b')


def find_hostile_zones(text):
    """Return a list of (start, end) spans that contain script tags or
    inline event-handler attributes. Any data extracted from inside one of
    these spans is treated as untrustworthy and excluded from results,
    even if it happens to look like a well-formed email/card/etc."""
    return [(m.start(), m.end()) for m in HOSTILE_ZONE_RE.finditer(text)]


def overlaps_hostile_zone(start, end, zones):
    return any(start < z_end and end > z_start for z_start, z_end in zones)


def scan_security_flags(text):
    """Independent pass over the raw text for known attack shapes. Snippets
    are truncated and HTML-escaped before being stored — we never echo a
    raw, "live" hostile payload back out in logs or output files."""
    flags = []

    for m in HOSTILE_ZONE_RE.finditer(text):
        flags.append({
            "type": "script_or_event_handler",
            "note": "Embedded script tag or inline event-handler attribute "
                    "detected; any data inside it was excluded from results.",
            "snippet": html_lib.escape(text[m.start():m.start() + 40]) + "...",
        })

    for m in SQL_INJECTION_RE.finditer(text):
        flags.append({
            "type": "sql_injection_pattern",
            "note": "Text resembling a SQL injection payload detected.",
            "snippet": html_lib.escape(text[m.start():m.start() + 40]) + "...",
        })

    for m in PATH_TRAVERSAL_RE.finditer(text):
        flags.append({
            "type": "path_traversal_pattern",
            "note": "Directory traversal sequence detected.",
            "snippet": html_lib.escape(text[m.start():m.start() + 40]) + "...",
        })

    for m in HEADER_INJECTION_RE.finditer(text):
        flags.append({
            "type": "header_injection_attempt",
            "note": "CRLF/encoded-newline followed by an email header "
                    "keyword — classic header injection attempt.",
            "snippet": html_lib.escape(text[max(0, m.start() - 20):m.start() + 20]),
        })

    for m in OVERSIZED_TOKEN_RE.finditer(text):
        flags.append({
            "type": "oversized_anomalous_token",
            "note": "Unusually long unstructured token — possible "
                    "buffer-stuffing / fuzzing junk.",
            "snippet": html_lib.escape(text[m.start():m.start() + 20]) + "...",
        })

    return flags


# ---------------------------------------------------------------------------
# 3. VALIDATION HELPERS
# ---------------------------------------------------------------------------

def luhn_check(digits):
    """Standard Luhn checksum. A regex can tell you a string is
    'card-shaped'; Luhn is what actually tells you the number could be
    real. This is the difference between pattern-matching and validation."""
    total = 0
    reversed_digits = digits[::-1]
    for i, d in enumerate(reversed_digits):
        d = int(d)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def classify_email_domain(email):
    domain = email.split("@")[-1].lower()
    for alu_domain, label in ALU_DOMAINS_IN_PRIORITY_ORDER:
        if domain == alu_domain:
            return label
    return "External"


def mask_email(email):
    """Show just enough to verify extraction worked without exposing the
    full address in output/logs (data-minimization principle)."""
    local, _, domain = email.partition("@")
    visible = local[0] if local else "*"
    return f"{visible}***@{domain}"


def mask_card(digits_only):
    return f"**** **** **** {digits_only[-4:]}"


def is_valid_url(candidate):
    """Strip common trailing punctuation a sentence might leave attached,
    then confirm the URL actually has a network location (host). This
    rejects malformed cases like 'https:///broken-link' which regex alone
    would happily match."""
    cleaned = candidate.rstrip('.,);\'"')
    parsed = urlparse(cleaned if "//" in cleaned else "http://" + cleaned)
    return bool(parsed.netloc), cleaned


# ---------------------------------------------------------------------------
# 4. EXTRACTION PIPELINE
# ---------------------------------------------------------------------------

def extract_emails(text, hostile_zones):
    valid, rejected = [], []
    for m in EMAIL_RE.finditer(text):
        if overlaps_hostile_zone(m.start(), m.end(), hostile_zones):
            rejected.append({"masked": mask_email(m.group()),
                              "reason": "found inside suspicious/script context"})
            continue
        valid.append({
            "masked": mask_email(m.group()),
            "category": classify_email_domain(m.group()),
        })
    return valid, rejected


def extract_credit_cards(text, hostile_zones):
    valid, rejected = [], []
    for m in CREDIT_CARD_RE.finditer(text):
        digits_only = re.sub(r'[ -]', '', m.group())
        if not (13 <= len(digits_only) <= 19):
            continue
        if overlaps_hostile_zone(m.start(), m.end(), hostile_zones):
            rejected.append({"masked": mask_card(digits_only),
                              "reason": "found inside suspicious/script context"})
            continue
        if luhn_check(digits_only):
            valid.append({"masked": mask_card(digits_only)})
        else:
            rejected.append({"masked": mask_card(digits_only),
                              "reason": "failed Luhn checksum"})
    return valid, rejected


def extract_phone_numbers(text):
    valid, rejected = [], []
    for m in PHONE_RE.finditer(text):
        digits_only = re.sub(r'\D', '', m.group())
        if 9 <= len(digits_only) <= 13:
            valid.append(m.group().strip())
        else:
            rejected.append({"raw": m.group().strip(), "reason": "implausible digit count"})
    return valid, rejected


def extract_urls(text):
    valid, rejected = [], []
    for m in URL_RE.finditer(text):
        ok, cleaned = is_valid_url(m.group())
        if ok:
            valid.append(cleaned)
        else:
            rejected.append({"raw": cleaned, "reason": "missing/empty host"})
    return valid, rejected


def extract_simple(pattern, text):
    return [m.group().strip() for m in pattern.finditer(text)]


# ---------------------------------------------------------------------------
# 5. MAIN
# ---------------------------------------------------------------------------

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(here, "..", "input", "raw-text.txt")
    output_path = os.path.join(here, "..", "output", "sample-output.json")

    with open(input_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    # Security pass FIRST — establishes hostile zones before we trust
    # anything else we find in the text.
    security_flags = scan_security_flags(raw_text)
    hostile_zones = find_hostile_zones(raw_text)

    emails_valid, emails_rejected = extract_emails(raw_text, hostile_zones)
    cards_valid, cards_rejected = extract_credit_cards(raw_text, hostile_zones)
    phones_valid, phones_rejected = extract_phone_numbers(raw_text)
    urls_valid, urls_rejected = extract_urls(raw_text)
    times_found = extract_simple(TIME_RE, raw_text)
    html_tags_found = [html_lib.escape(t) for t in extract_simple(HTML_TAG_RE, raw_text)]
    hashtags_found = extract_simple(HASHTAG_RE, raw_text)
    currency_found = extract_simple(CURRENCY_RE, raw_text)

    alu_breakdown = {"ALU Official": 0, "ALU Alumni": 0, "ALU SI": 0, "External": 0}
    for e in emails_valid:
        alu_breakdown[e["category"]] += 1

    results = {
        "emails": {"valid": emails_valid, "rejected": emails_rejected,
                   "alu_domain_breakdown": alu_breakdown},
        "credit_cards": {"valid": cards_valid, "rejected": cards_rejected},
        "phone_numbers": {"valid": phones_valid, "rejected": phones_rejected},
        "urls": {"valid": urls_valid, "rejected": urls_rejected},
        "times": times_found,
        "html_tags_detected": html_tags_found,
        "hashtags": hashtags_found,
        "currency_amounts": currency_found,
        "security_flags": security_flags,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # ---- Console summary (safe to print — everything sensitive is masked)
    print("=" * 60)
    print("DATA EXTRACTION & SECURE VALIDATION — SUMMARY")
    print("=" * 60)
    print(f"Emails found:        {len(emails_valid)} valid, {len(emails_rejected)} rejected")
    print(f"  ALU breakdown:     {alu_breakdown}")
    print(f"Credit cards found:  {len(cards_valid)} valid, {len(cards_rejected)} rejected")
    print(f"Phone numbers found: {len(phones_valid)} valid, {len(phones_rejected)} rejected")
    print(f"URLs found:          {len(urls_valid)} valid, {len(urls_rejected)} rejected")
    print(f"Time values found:   {len(times_found)}")
    print(f"HTML tags detected:  {len(html_tags_found)}")
    print(f"Hashtags found:      {len(hashtags_found)}")
    print(f"Currency amounts:    {len(currency_found)}")
    print(f"Security flags raised: {len(security_flags)}")
    for flag in security_flags:
        print(f"  - [{flag['type']}] {flag['note']}")
    print("-" * 60)
    print(f"Full results written to: {output_path}")
    print("Note: input text is NOT automatically trusted — see 'rejected' "
          "lists and 'security_flags' above for what was filtered out.")


if __name__ == "__main__":
    main()

