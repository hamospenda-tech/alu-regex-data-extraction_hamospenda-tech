Data Extraction & Secure Validation
A regex-based Python program that extracts structured data from realistic, messy raw text (modeled on a support-ticket export from an external API), validates that the data is genuinely well-formed, and treats the input as untrusted by default.

HOW TO RUN IT

Requires Python 3.7+ (standard library only — no dependencies to install).

cd src

python3 main.py

WHATS IN THE INPUT FILE

input/raw-text.txt is a fictional support-ticket thread combining:

- A realistic mix of email formats (personal, ALU official/alumni/SI domains, mixed casing, a few genuinely malformed addresses)
- Multiple phone number formats (international, dashed, dotted, bracketed)
- Credit card numbers in different separator styles
- A pasted chat log with 12h and 24h time values
- URLs with and without protocol, plus one deliberately broken URL
- Currency amounts in different notations
- Hashtags, alongside a "#4471" ticket reference that looks like a hashtag but isn't
- A block of hostile/malformed content (script tags, a SQL injection string, a path traversal string, an email header injection attempt, and an oversized junk token) mixed in the way it might arrive from an untrusted external API or form submission

Data types extracted (8 of 8)
Type
Notes
Emails
Classified into ALU Official / ALU Alumni / ALU SI / External
Credit cards
Checksum-validated (Luhn), not just pattern-matched
Phone numbers
Handles spaced, dashed, dotted, bracketed, +country-code formats
URLs
Both https:// and bare www. forms; validated for a real host
Time (12h/24h)
14:32, 9:15am, 08:00, 23:45, etc.
HTML tags
Escaped before being stored/printed
Hashtags
Excludes pure-digit #1234-style references
Currency amounts
$, €, £, and USD/EUR/GBP prefixed

Why some things are "extracted" but still rejected
The program separates pattern match from validity. A string can look like a credit card and still not be trusted. Every extractor returns a valid list and a rejected list with a reason:

Credit cards: matched candidates are run through the Luhn algorithm. A regex can only tell you a string is "16 digits, maybe grouped" — Luhn is the actual checksum real card numbers satisfy. Interestingly, all four card-shaped numbers in the sample input pass Luhn (they're well-known dummy test numbers used for exactly this reason) — which is why the context check below still matters even when the checksum passes.
Emails: the regex's own structure (a required . + 2+ letter TLD, a required non-empty local part) rejects malformed junk like alsoNotReal@nodot or @missingusername.com with no extra code needed.
URLs: matched candidates are parsed with urllib.parse to confirm they actually have a host. https:///broken-link matches the basic URL shape but has an empty host, so it's rejected.
Phone numbers: the digit count after stripping separators must fall in a plausible range (9–13 digits), which naturally excludes short fragments like 123-45.
Security handling
The brief requires the program to demonstrate that "not all input is trustworthy." Concretely:

Hostile-zone detection. Before any data extraction runs, the text is scanned for <script> tags and inline event-handler attributes (onerror=, onload=, etc.) — the classic vectors for smuggling extra "data" into a text blob. Any email or credit card number whose match falls inside one of these zones is excluded from the valid results and logged as rejected, even if it would otherwise look completely legitimate (e.g. a Luhn-valid card number hidden inside an onerror="steal(...)" attribute is correctly rejected in the sample output, while the same-shaped number sitting in plain text is accepted).

Design note: an email address immediately followed by injected script (rather than embedded inside it) is still counted as a syntactically valid email, and the attached script is flagged separately as its own security event. The reasoning is that rejecting all data merely adjacent to something suspicious would cause far too many false negatives on real text — the point is contextual awareness, not blanket paranoia.

Independent threat scan. Separately from extraction, the raw text is scanned for SQL-injection keywords, path-traversal sequences (../../), email header injection (%0A/CRLF followed by Bcc:/To:), and abnormally long unstructured tokens. These are reported in security_flags in the output — none of this content is used as "extracted data."

No raw sensitive data in output or logs. Emails are masked to j***@gmail.com and card numbers to **** **** **** 6467 before anything is printed to console or written to the JSON file. Any hostile snippet included in security_flags is truncated and HTML-escaped before storage, so a stored "flag" can never itself execute as script if the JSON were later rendered somewhere.

This isn't a claim to have built a production security system — it's a demonstration that the extraction logic doesn't naively trust its input, per the assignment's stated expectations.

