#!/usr/bin/env python3
"""tools/smoke.py — lightweight auto-discovering smoke harness.

Run from the repository root:

    python tools/smoke.py

This is a regression tripwire, not a per-case test suite. It auto-discovers
every mutation operator, WAF fingerprint and validation signature currently
defined in the package, so a new entry added to any of those lists is picked
up on the next run with no edits to this file. It exits non-zero if anything
is dead, broken or internally inconsistent:

  * a mutation operator raises or returns a non-str on a realistic sample;
  * a WAF fingerprint cannot be re-detected from a response that carries its
    own signature, or an operator-prior references an unknown product/operator;
  * a SQL-error or LFI-file signature matches nothing in the realistic corpus
    (i.e. it is dead or typo'd);
  * the static XSS validator neither accepts a known-good reflection nor
    rejects known-harmless text.

On success it prints "SMOKE OK (...)" and exits 0.
"""
import os
import sys

# Make the repo root importable regardless of the current working directory,
# so `python tools/smoke.py` works from anywhere (CI checks out fresh).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from waf_evolve.fingerprint import (
    WAF_OPERATOR_PRIORS,
    WAF_SIGNATURES,
    fingerprint_waf,
)
from waf_evolve.mutations import (
    _XSS_VECTOR_TEMPLATES,
    ALL_MUTATIONS,
    OPERATORS_BY_CATEGORY,
    backslash_insert_sql,
    crossover,
    gbk_overlong,
    operators_for,
    overlong_utf8,
    sql_hex_string_literal,
    uri_case_fold,
    xss_js_char_escape,
    xss_polyglot,
)
from waf_evolve.validators import (
    KNOWN_FILE_SIGNATURES,
    SQL_ERROR_SIGNATURES,
    validate_lfi,
    validate_sqli,
    validate_xss_static,
)

# Representative payload per category (deterministic inputs for the sweep).
SAMPLE_PAYLOAD = {
    "xss": "<script>alert(1)</script>",
    "sqli": "1' OR 1=1--",
    "lfi": "../../etc/passwd",
    "generic": "<img src=x onerror=alert(1)> 1' UNION SELECT 1,2--",
}

# Realistic sample corpora. Every SQL-error / LFI-file signature must match at
# least one line, which keeps a newly-added signature grounded in a real
# example (and catches typo'd patterns that would never fire).
SQL_ERROR_CORPUS = [
    "You have an error in your SQL syntax; check the manual for the right syntax",
    "Warning: mysql_fetch_array() expects parameter 1 to be resource",
    "ORA-00936: missing expression",
    "psycopg2.errors.SyntaxError: PostgreSQL ERROR 42601: syntax error",
    'SQLite3::OperationalError: near "SELECT": syntax error',
    "SQLITE_ERROR: database is locked",
    "sqlite3.OperationalError: no such table: users",
    'An exception occurred: near "WHERE": syntax error',
    "Unclosed quotation mark after the expression 'admin'.",
    "quoted string not properly terminated",
]

LFI_CORPUS = {
    "/etc/passwd": ["root:x:0:0:root:/root:/bin/bash", "www-data:x:33:33::/var/www:/bin/sh"],
    "/etc/shadow": ["root:$6$xyz$abcdefghijklmnop"],
    "win.ini": ["[fonts]", "[extensions]"],
    "php_source": ["<?php echo 1;", "<?= date('Y')"],
}

# Deterministic operators pinned to exact input -> output so a behavior change
# is caught immediately. Stochastic operators are covered by the sweep above.
# New deterministic operators MUST add a pin here when they are introduced.
DETERMINISTIC_PINS = {
    "add_null_byte": ("x", "x%00"),
    "double_url_encode": ("a b", "a%2520b"),
    "lfi_nested_traversal": ("../../etc/passwd", "....//....//etc/passwd"),
    "lfi_encode_traversal": ("../../etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    "lfi_double_encode_traversal": ("../../etc/passwd", "%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
}

# Static XSS reflection the validator must accept / reject.
XSS_GOOD = ("User: <script>alert(1)</script> done", "<script>alert(1)</script>")
XSS_BAD = ("User: <b>bold</b> done", "<script>alert(1)</script>")


class _FakeResponse:
    """Minimal stand-in for requests.Response (headers dict, text, status)."""

    def __init__(self, headers, text="", status=200):
        self.headers = headers
        self.text = text
        self.status_code = status


def _header_for_pattern(pat):
    """Build a concrete (name, value) header that satisfies a signature pattern."""
    if ":" in pat:
        name, _, val = pat.partition(":")
        value = val.split(r"\s*")[-1] or "x"
        return name, value
    return pat, "x"


def _craft_response(sig):
    headers, text = {}, ""
    if sig.get("headers"):
        name, value = _header_for_pattern(sig["headers"][0])
        headers[name] = value
    elif sig.get("body"):
        text = sig["body"][0]
    return _FakeResponse(headers, text=text)


# Real-world single-signature responses for the products whose secondary
# signals the craft-based check (which only exercises sig["headers"][0]) does
# not cover: multi-word `server:` values (GCP "Google Frontend"), `via:` hop
# strings (Varnish, KeyCDN), and block cookies (PerimeterX pxhid, DataDome).
# Making fingerprint_waf re-detect each from its real signal is a permanent
# tripwire on the real detection path, not just the crafted one.
REALISTIC_WAF_RESPONSES = {
    "Bunny.net": {"server": "BunnyCDN"},
    "Fastly": {"x-fastly-request-id": "d41d8cd9"},
    "Varnish": {"via": "1.1 varnish"},
    "PerimeterX/HUMAN": {"set-cookie": "pxhid=abc123; Path=/; HttpOnly"},
    "DataDome": {"set-cookie": "datadome=abc123; Path=/"},
    "Wallarm": {"x-wallarm": "1"},
    "GCP/Cloud Armor": {"server": "Google Frontend"},
    "KeyCDN": {"via": "1.1 keycdn"},
    "Radware/LinkDDoS": {"server": "Radware"},
}


def check_operators():
    all_names = {op.__name__ for op in ALL_MUTATIONS}
    for category, payload in SAMPLE_PAYLOAD.items():
        for op in operators_for(category):
            out = op(payload)
            assert isinstance(out, str), f"{op.__name__} returned {type(out)} for {category}"
    # every category operator must exist in ALL_MUTATIONS
    for cat, ops in OPERATORS_BY_CATEGORY.items():
        for op in ops:
            assert op.__name__ in all_names, f"{op.__name__} in {cat} but not ALL_MUTATIONS"
    # deterministic operators are pinned to exact output
    for name, (inp, expected) in DETERMINISTIC_PINS.items():
        fn = next((o for o in ALL_MUTATIONS if o.__name__ == name), None)
        assert fn is not None, f"pinned operator {name} missing from ALL_MUTATIONS"
        got = fn(inp)
        assert got == expected, f"{name}({inp!r}) = {got!r}, expected {expected!r}"
    # crossover stays a string
    assert isinstance(crossover("1' OR 1=1--", "2' AND 2=2--"), str)
    return len(all_names)


def check_evasion_pins():
    """Exact input->output pins for the deterministic evasion operators:
    SQLi/LFI (overlong UTF-8/GBK, backslash insertion, hex string literal,
    percent-encoding case fold) and the deterministic XSS evasion operators
    (cross-context polyglot, JS function-name unicode-escape)."""
    pins = [
        (overlong_utf8, "a b'c", "a%c0%a0b%c0%a7c"),
        (gbk_overlong, "a' b", "a%df%27%df%20b"),
        (backslash_insert_sql, "x = 1", "x\\ \\=\\ 1"),
        (sql_hex_string_literal, "'admin'", "0x61646d696e"),
        # degenerate inputs: only matched pairs rewrite, no corruption
        (sql_hex_string_literal, "'a'b'", "0x61b'"),
        (sql_hex_string_literal, "admin", "admin"),
        (sql_hex_string_literal, "''", "0x"),
        (uri_case_fold, "a%2Fb%3Dc", "a%2fb%3dc"),
        # deterministic XSS evasion operators (pure transforms -> exact output)
        (xss_polyglot, "alert(1)", '"><svg/onload=alert(1)>'),
        (xss_js_char_escape, "alert(1)", r"a\u006c\u0065\u0072\u0074(1)"),
        # proves it escapes the name INSIDE a vector, leaving the tag intact
        (xss_js_char_escape, "<svg onload=alert(1)>", r"<svg onload=a\u006c\u0065\u0072\u0074(1)>"),
    ]
    for fn, inp, expected in pins:
        got = fn(inp)
        assert got == expected, f"{fn.__name__}({inp!r}) = {got!r}, expected {expected!r}"
    return len(pins)


def check_fingerprints():
    all_op_names = {op.__name__ for op in ALL_MUTATIONS}
    for product, sig in WAF_SIGNATURES.items():
        resp = _craft_response(sig)
        detected, _detail = fingerprint_waf(lambda _p, _r=resp: _r)
        assert detected == product, (
            f"fingerprint: crafted {product} response detected as {detected!r}"
        )
    # real-world single-signature responses (secondary signals the craft check
    # does not exercise: multi-word server values, via hops, block cookies)
    for product, headers in REALISTIC_WAF_RESPONSES.items():
        assert product in WAF_SIGNATURES, f"realistic response for unknown {product!r}"
        resp = _FakeResponse(headers)
        detected, _detail = fingerprint_waf(lambda _p, _r=resp: _r)
        assert detected == product, (
            f"fingerprint: realistic {product} response detected as {detected!r}"
        )
    # operator-prior consistency: every prior product has a signature, and
    # every referenced operator is a real operator
    for product, ops in WAF_OPERATOR_PRIORS.items():
        assert product in WAF_SIGNATURES, f"prior product {product!r} has no signature"
        for name in ops:
            assert name in all_op_names, f"prior operator {name!r} (for {product}) is unknown"
    return len(WAF_SIGNATURES)


def check_sql_signatures():
    for pat in SQL_ERROR_SIGNATURES:
        hits = [c for c in SQL_ERROR_CORPUS if pat.search(c)]
        assert hits, f"SQL signature {pat.pattern!r} matches no corpus line (dead?)"
    ok, _reason = validate_sqli(SQL_ERROR_CORPUS[0])
    assert ok, "validate_sqli should accept a known SQL error"
    no, _reason = validate_sqli("all good, 200 ok")
    assert not no, "validate_sqli should reject harmless text"
    return len(SQL_ERROR_SIGNATURES)


def check_lfi_signatures():
    for file_hint, patterns in KNOWN_FILE_SIGNATURES.items():
        corpus = LFI_CORPUS.get(file_hint, [])
        for pat in patterns:
            hits = [c for c in corpus if pat.search(c)]
            assert hits, f"LFI signature [{file_hint}] {pat.pattern!r} matches no corpus line (dead?)"
    ok, _reason = validate_lfi("root:x:0:0:root:/root:/bin/bash")
    assert ok, "validate_lfi should accept /etc/passwd content"
    no, _reason = validate_lfi("nothing interesting here")
    assert not no, "validate_lfi should reject harmless text"
    return len(KNOWN_FILE_SIGNATURES)


def check_xss_static():
    good_text, payload = XSS_GOOD
    ok, _reason = validate_xss_static(good_text, payload)
    assert ok, "validate_xss_static should accept a reflected <script> payload"
    bad_text, payload2 = XSS_BAD
    no, _reason = validate_xss_static(bad_text, payload2)
    assert not no, "validate_xss_static should reject non-executable reflection"
    return 1


def check_xss_vector_coverage():
    """Every XSS delivery vector in _XSS_VECTOR_TEMPLATES (the single source
    of truth shared with xss_tag_vector_swap) and the two deterministic XSS
    evasion operators must be attributable by the static validator when
    reflected, so a regression that renders them 'invisible' to
    validate_xss_static is caught immediately."""
    vectors = [tmpl.format(call="alert(1)") for tmpl in _XSS_VECTOR_TEMPLATES]
    vectors.append(xss_polyglot("alert(1)"))
    vectors.append(xss_js_char_escape("<svg onload=alert(1)>"))
    for vec in vectors:
        reflected = f"<html><body> {vec} </body></html>"
        ok, reason = validate_xss_static(reflected, vec)
        assert ok, f"static XSS validator missed vector {vec!r} ({reason})"
    return len(vectors)


def main():
    n_ops = check_operators()
    check_evasion_pins()
    n_waf = check_fingerprints()
    n_sql = check_sql_signatures()
    n_lfi = check_lfi_signatures()
    n_xss = check_xss_static()
    n_xss_vec = check_xss_vector_coverage()
    print(
        f"SMOKE OK ({n_ops} operators, {n_waf} fingerprints, "
        f"{n_sql} sqli-signatures, {n_lfi} lfi-files, {n_xss} xss-check, "
        f"{n_xss_vec} xss-vectors-covered)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
