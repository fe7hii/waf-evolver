# WAF Evolver

An AI/RL-assisted, genetic-algorithm-based WAF/filter bypass fuzzer.
Instead of fixed payload lists, it learns from the target's **behavioral
signals** (status code, response size, block signatures, response time) and
mutates payloads across generations.

## ⚠️ ETHICAL & LEGAL NOTICE

This tool must be used **ONLY** against:
- Test/lab environments you set up yourself,
- Systems within a pentest/red-team scope for which you have **written,
  explicit authorization**,
- Targets within the **scope** of a bug bounty program that permits this
  kind of automated testing.

Using it against systems without permission is illegal and is entirely the
user's responsibility. The developer/provider accepts no liability.

## Why this, next to sqlmap / Burp

It is **not** a replacement - it is the adaptive WAF-evasion front-end they
lack, and it hands the result straight to them:

- **Learned, not static evasion.** sqlmap's tamper scripts are fixed
  transforms you pick by hand; this *discovers* which mutations actually get
  past the specific target's WAF from its response signals, and remembers them
  per target (the Q-table persists and reloads).
- **Feeds sqlmap directly.** `--export-tamper` turns the learned bypass into a
  ready-to-use sqlmap tamper script. Workflow: WAF blocks sqlmap → run this →
  drop the generated tamper into sqlmap → continue.
- **WAF fingerprinting + priors.** It identifies the WAF product (where it
  leaks) and starts from operator priors known to help against it.
- **Low false positives across categories.** SQLi + XSS + LFI in one loop,
  each with a real oracle (active boolean/time for SQLi, live-browser dialog
  for XSS), so a "success" is proven, not guessed.

(The RL is a simple tabular Q-learning, not deep RL - the value is the
adaptive/evolutionary loop and the oracle-backed validation, not magic.)

## Architecture

```
seed payloads → [Genetic Algorithm Loop] → best bypass candidates
                        │
                ├─ mutations.py   (mutation operators)
                ├─ fitness.py     (response analysis + scoring)
                ├─ agent.py       (Q-learning: learns which mutation works)
                └─ engine.py      (main loop, selection, crossover)
```

### How does it work?

1. **Baseline**: a harmless request is sent and the "normal" response is recorded.
2. **Population**: an initial population is built from the seed payloads.
3. **Evaluation**: each payload is sent to the target and a fitness score is
   derived from the response (status code, size difference, WAF signatures,
   response-time anomaly, payload reflection, and - most importantly -
   category-specific validation).
4. **Selection**: the highest-scoring payloads survive.
5. **Reproduction**: survivors produce the next generation via crossover +
   mutation, drawn from the category's operator set (and, against a
   fingerprinted WAF, weighted toward operators known to help). An optional
   RL agent (`--rl`) can bias operator choice; it is off by default (see
   Benchmark).
6. **Repeat**: continues until the success threshold is reached or the
   generation limit is hit.

## Installation

```bash
pip install -r requirements.txt --break-system-packages
```

## Usage

```bash
python3 cli.py \
  --url http://target.com/search \
  --param q \
  --seeds seeds/sqli_seeds.txt \
  --category sqli \
  --generations 30 \
  --population 40 \
  --delay 1.0 \
  --threshold 70
```

### Parameters

| Parameter | Description | Default |
|---|---|---|
| `--url` | Target URL (required) | - |
| `--param` | Name of the parameter to inject into | `q` |
| `--method` | GET or POST | `GET` |
| `--seeds` | Initial payload file | required |
| `--category` | Payload category: `sqli`, `xss`, `lfi`, `generic` | `generic` |
| `--generations` | Maximum number of generations | 30 |
| `--population` | Payloads per generation | 40 |
| `--delay` | Delay between requests (seconds) | 1.0 |
| `--threshold` | Fitness score accepted as success | 60.0 |
| `--rl` | Enable the experimental RL agent (off by default; see Benchmark) | off |
| `--header` | Extra HTTP header (`'Key: Value'`), repeatable | - |
| `--dynamic-validation` | For XSS: prove JS execution in a real browser (Playwright) | off |
| `--xss-live` | With dynamic validation, drive the real browser to the live URL (real parsing/CSP) instead of rendering the captured body | off |
| `--no-require-validation` | Accept success on score alone (not recommended) | off |
| `--max-requests` | Hard cap on total HTTP requests (0 = unlimited; includes confirmation probes) | 0 |
| `--baseline-samples` | Number of baseline requests sampled (median reduces noise) | 3 |
| `--no-minimize` | Do not minimize the confirmed payload after success | off |
| `--inject` | Where to place the payload: `query`, `form`, `json`, `header`, `template` | `query` |
| `--body-template` | For `--inject template`: a body containing the marker `FUZZ`, replaced by the payload | - |
| `--content-type` | Override Content-Type (useful with `--inject json`/`template`) | - |
| `--verify-url` | Second-order/stored: URL where the effect surfaces; validation runs against this page | - |
| `--jitter` | Random 0..JITTER seconds added to each inter-request delay | 0 |
| `--user-agent` | Custom User-Agent (default: a common browser UA) | browser UA |
| `--random-ua` | Rotate the User-Agent per request | off |
| `--no-fingerprint` | Skip WAF fingerprinting / operator priors | off |
| `--export-tamper` | After success, write a sqlmap tamper script of the learned bypass to PATH | - |
| `--proxy` | Route all traffic through an upstream proxy (e.g. Burp `http://127.0.0.1:8080`) | - |
| `--insecure` | Disable TLS verification (useful with an intercepting proxy) | off |
| `--cookie` | Cookie header for authenticated testing (`k=v; k2=v2`) | - |
| `--find-all` | Do not stop at the first finding; collect all distinct validated bypasses | off |
| `--report` | Write a Markdown report of findings (repro + evidence + profile) to PATH | - |

### Example: XSS payloads

```bash
python3 cli.py --url http://target.com/comment --param text \
  --seeds seeds/xss_seeds.txt --method POST --category xss --generations 20
```

### Example: with an auth token

```bash
python3 cli.py --url http://target.com/api/search --param query \
  --seeds seeds/sqli_seeds.txt --category sqli \
  --header "Authorization: Bearer xxxxx" \
  --header "X-Custom-Header: test"
```

## Adding your own mutation operator

Add a function to `waf_evolve/mutations.py` and include it in `ALL_MUTATIONS`:

```python
def my_custom_mutation(payload: str) -> str:
    # your logic
    return modified_payload

ALL_MUTATIONS.append(my_custom_mutation)
```

## Scoring philosophy (fitness)

The core challenge: a payload that "bypasses the WAF" (is not blocked) is
**not** necessarily a working exploit. For example `<Sc>alerT(1)</scRipT>`
evades a `<script` regex but runs nothing in a browser; a payload encoded so
many times (`%2525...`) that the backend never decodes it will pass the
filter yet exploit nothing.

So, for a specific category (`sqli`/`xss`/`lfi`):

- Merely not being blocked earns only a **small** score (necessary, not sufficient).
- The dominant reward comes from **category-specific validation** (a real SQL
  error, a real executable XSS structure, real file contents).
- **Over-encoding is penalized** - the more times a payload is nested-encoded,
  the larger the penalty, because such payloads bypass the filter without
  reaching the backend as an attack. This is the single most important lever
  for finding *real* bypasses against a real WAF.

For `generic` (no validator), the classic heuristics (status 200, size near
baseline, reflection) still drive the score.

### Active SQLi confirmation (boolean / time-based)

For `sqli`, when a candidate is not blocked the tool runs an **active
differential confirmation** through extra probes - this proves *control*
over the query, not just that an error was triggered:

- **Boolean-based:** it builds a definitely-TRUE and a definitely-FALSE
  sibling of the payload (inheriting the same evasion encoding/comments/case),
  sends both, and confirms only if the two responses differ in a controlled,
  logic-dependent way. If the payload was not actually injected, both siblings
  return the same page, so it is correctly rejected (no false positive).
- **Time-based blind:** if the payload carries a time construct -
  `sleep()`/`pg_sleep()`, MSSQL `WAITFOR DELAY 'h:m:s'`, or MySQL
  `BENCHMARK(N, ...)` - it sends a matched fast/slow pair (e.g. `sleep(0)`
  vs `sleep(3)`, `WAITFOR DELAY '0:0:0'` vs `'0:0:3'`, or `BENCHMARK(1, ...)`
  vs `BENCHMARK(10000000, ...)`) and confirms only if the response time
  shifts by the expected margin.

If neither applies, it falls back to error-signature detection.

### Payload minimization

After a confirmed finding, the tool greedily drops tokens while re-confirming,
yielding the smallest still-working payload - a clean, reproducible result for
a report instead of a bloated mutant.

### Injection locations

The payload is not limited to a URL query parameter. `--inject` places it in:

```bash
# URL query (default):   ?q=PAYLOAD
python3 cli.py --url http://t/search --param q --inject query ...

# form body:             q=PAYLOAD  (POST)
python3 cli.py --url http://t/login --param q --inject form --method POST ...

# JSON body:             {"q": "PAYLOAD"}
python3 cli.py --url http://t/api/search --param q --inject json --method POST ...

# an HTTP header:        X-Search: PAYLOAD
python3 cli.py --url http://t/ --param X-Search --inject header ...

# free-form body with a FUZZ marker (any content type):
python3 cli.py --url http://t/graphql --inject template \
  --content-type application/json \
  --body-template '{"query":"{ search(q:\"FUZZ\") }"}' ...
```

### Second-order / stored findings

With `--verify-url`, the payload is sent to the injection point and the effect
is validated on a *different* page - the classic stored-XSS / second-order
pattern. For dynamic XSS the browser visits the verify URL to observe real
execution of the stored payload:

```bash
python3 cli.py --url http://t/comment --param q --method POST --inject form \
  --verify-url http://t/feed \
  --seeds seeds/xss_seeds.txt --category xss --dynamic-validation --xss-live
```

(Minimization is skipped in this mode, since a shared store makes per-step
re-confirmation unreliable.)

### Traffic shaping

`--jitter` randomizes the inter-request delay, `--user-agent` sets a custom UA
(default is a common browser UA), and `--random-ua` rotates it. These reduce
tripping naive rate-limits/heuristics; they do **not** defeat managed WAFs
(see limitations).

### WAF fingerprinting & operator priors

At startup the tool sends one probe and matches response headers / block-page
text against known products (Cloudflare, Akamai, Imperva/Incapsula, Sucuri,
AWS WAF, F5 BIG-IP, ModSecurity/CRS). When identified, it seeds the RL agent
with operator priors known to help against that WAF, so it starts smarter.
When the WAF does not leak its identity it honestly reports
"Unknown/Generic WAF" and starts from zero. Disable with `--no-fingerprint`.

### Export the learned bypass to sqlmap

```bash
python3 cli.py --url http://target/search --param q --category sqli \
  --seeds seeds/sqli_seeds.txt --export-tamper waf_bypass_tamper.py

cp waf_bypass_tamper.py <sqlmap>/tamper/
sqlmap -u "http://target/search?q=1" --tamper=waf_bypass_tamper
```

The generated tamper is a self-contained sqlmap module applying the
deterministic forms of the operators that were learned to work on this target.

### Evasion profile

After each run the tool prints and writes `logs/<target>_profile.json` - the
detected WAF, the best payload, and the ranked operators that worked against
this target. Reusable intelligence for the next engagement.

### Burp/ZAP integration, auth, and reporting

```bash
python3 cli.py --url https://target/search --param q --category sqli \
  --seeds seeds/sqli_seeds.txt \
  --proxy http://127.0.0.1:8080 --insecure \
  --cookie "session=abc; role=user" \
  --find-all --report finding.md
```

- `--proxy` routes every request (and the live browser) through Burp/ZAP, so
  you see and can replay everything.
- `--insecure` trusts the proxy's CA; `--cookie` carries an authenticated session.
- `--find-all` keeps going past the first hit and collects every distinct
  validated bypass; `--report` writes a Markdown report with a working `curl`
  reproduction, the evidence, the detected WAF and the evasion profile.

### Other engine features

- **Contextual RL:** the Q-table is keyed by state (category + current
  response bucket), so the agent learns rules like "when stuck at X, operator
  Y helps" rather than one global ranking.
- **De-duplication:** identical payloads are cached and never re-sent.
- **Request budget:** `--max-requests` caps total traffic (probes included).
- **Multi-sample baseline:** the baseline is sampled several times and the
  median used, so size/time signals are not fooled by noise.
- **Grammar-aware crossover:** payloads are spliced at token boundaries so
  offspring stay closer to valid syntax (weaponizable, not just error-prone).

## Category-specific validation layer (validators.py)

Use the `--category` flag to enable strict, category-specific validation:

| Category | Validation |
|---|---|
| `xss` | Checks for a **real, closing, valid** `<script>` tag, an `onXXX=` event handler, a `javascript:` URI, or `<svg onload>`. Appearing as text is not enough. |
| `lfi` | Checks for the **actual content signature** of known files (`/etc/passwd`, `/etc/shadow`, `/etc/os-release`, `win.ini`, `boot.ini`, WordPress `wp-config.php`, IIS `web.config`, PHP source). A reflected path (e.g. a "file not found: X" message) is not enough. |
| `sqli` | Looks for a real SQL error message / engine signature (MySQL, MariaDB, PostgreSQL, Oracle, SQLite, MSSQL, DB2). |
| `generic` (default) | No specific validation (score-based only). |

Use `--no-require-validation` to disable this requirement (not recommended -
it reintroduces false positives).

### Dynamic XSS validation (Playwright - strongest proof)

Install Playwright and a browser. Note: some distro packages of Playwright
(e.g. Kali's `python3-playwright`, `*+ds`) ship without the Node driver and
cannot launch a browser - use the pip wheel, ideally in a virtualenv:

```bash
python3 -m venv pwvenv
./pwvenv/bin/pip install playwright requests flask
./pwvenv/bin/python -m playwright install chromium

./pwvenv/bin/python cli.py --url http://target.com/comment --param q \
  --seeds seeds/xss_seeds.txt --method POST \
  --category xss --dynamic-validation

# strongest: navigate the real browser to the live target
./pwvenv/bin/python cli.py --url http://target.com/page --param q \
  --seeds seeds/xss_seeds.txt --category xss --dynamic-validation --xss-live
```

If no working browser is available the tool logs a warning and falls back to
the (weaker) static check instead of crashing.

This mode **renders each candidate payload in a real headless Chromium** and
directly observes whether a JS dialog (alert/confirm/prompt) **actually
fires** - the most precise distinction between "fooled the regex" and
"actually executed JavaScript". A single browser instance is kept open for
the whole run (reopening per payload would be far too slow).

When dynamic validation is available it is **authoritative**: if the browser
runs the payload and no dialog fires, that is a definitive negative - the
tool does not silently fall back to the weaker static check and call it a
pass (which would reintroduce false positives). Static is used only when
Playwright is unavailable.

Add `--xss-live` to make the browser **navigate to the live target URL** with
the payload (GET) or auto-submit a form (POST), so the server's real response
and any CSP apply - the strongest, context-true proof. Without it, the
captured response body is rendered instead.

The static XSS check is also **attributed**: it confirms only an executable
structure that contains a signature of *your* payload, so it no longer
matches the application's own legitimate `<script>` tags.

XSS also gets **category-specific mutation operators** (tag/vector swap,
event-handler swap, attribute breakout, entity obfuscation) and its own
operator set, so payloads are not shredded by SQL-oriented mutations. SQLi
likewise uses a SQL-oriented operator set.

## Test / validation

Point the tool only at a target you are authorized to test. For a realistic
local setup, run an intentionally-vulnerable app behind a real WAF, e.g.
OWASP Juice Shop behind ModSecurity + OWASP CRS (below), or any deliberately
vulnerable app (DVWA, bWAPP, WebGoat) you host yourself.

### Against a real WAF (OWASP CRS)

The meaningful test for a WAF-bypass tool is a real WAF. A local setup with
**ModSecurity + OWASP Core Rule Set** in front of OWASP Juice Shop:

```yaml
services:
  juiceshop:
    image: bkimminich/juice-shop:latest
    networks: [wsnet]
  waf:
    image: owasp/modsecurity-crs:nginx
    environment:
      BACKEND: "http://juiceshop:3000"
      PORT: "8080"
      MODSEC_RULE_ENGINE: "On"
      BLOCKING_PARANOIA: "1"
    ports: ["127.0.0.1:8085:8080"]
    networks: [wsnet]
networks:
  wsnet: { driver: bridge }
```

```bash
python3 cli.py --url http://127.0.0.1:8085/rest/products/search --param q \
  --seeds seeds/sqli_seeds.txt --category sqli \
  --generations 20 --population 30 --delay 0.1 --threshold 70
```

**Result (after the scoring revision):** classic payloads (`' UNION SELECT
NULL--`) are blocked by CRS (403). Within ~2 generations the tool mutated one
into `' OR sniON seLEcT nULL--`, which **bypasses CRS and triggers a genuine
backend error** (`SQLITE_ERROR: ... syntax error`, HTTP 500) - validated as a
real SQLi signal. The RL agent learned to **down-weight over-encoding**
(`double_url_encode` went negative) and favor structural bypasses
(`case_randomize`, `script_null_byte_split`).

Before the revision, the tool plateaued at a non-validated score on
over-encoded `%2525...` payloads that passed the filter but exploited
nothing - the scoring now correctly penalizes that.

## Fixed issues

1. **RL reward was assigned to the wrong operator (critical, fixed)** - each
   `Individual` now records the operator that produced it (`source_op`), so
   the reward goes to the correct operator with that payload's real fitness.
2. **Greedy tie-breaking bug (fixed)** - when Q-values were tied the agent
   always picked the first operator; it now picks randomly among ties.
3. **Adaptive rate-limit backoff** - on repeated 429s the delay grows
   exponentially (capped at 30s) and returns to normal afterwards.
4. **Dynamic-validation silent-fallback warning** - if Playwright/browser is
   unavailable, a clear WARNING is now logged.
5. **Over-encoding false positives (fixed in this revision)** - the fitness
   function now penalizes multiply-encoded payloads and makes validation the
   dominant signal, so "not blocked" alone no longer looks like success.

## Benchmark (honest)

Measured locally against OWASP CRS (in front of Juice Shop) and a normalizing
regex-WAF lab. All attack types reach a **validated** finding:

| Scenario | Validated | Requests |
|---|---|---|
| SQLi (query, CRS) | yes | ~30 |
| SQLi (JSON body) | yes | ~42 |
| LFI (normalizing WAF) | yes | ~12 |
| XSS reflected (live browser) | yes | ~40-80 |
| XSS stored / second-order | yes (higher variance) | ~30-90 |

What actually drives results: the **fitness redesign** (over-encoding penalty
+ validation-dominant scoring) and the **category-specific operator sets** -
e.g. on CRS this took a non-validated plateau at ~45 down to a validated
finding in ~2 generations.

The **RL agent is off by default** because in these benchmarks it was neutral:
on easy targets success arrives in 1-2 generations before the learn→exploit
loop can close, and on harder targets many operators work so per-operator
selection doesn't matter. It is kept as `--rl` for experimentation. The
genetic search + operator sets + fitness + oracle validation are the engine.

## Scope & limitations (what this is / is not)

This is a focused **WAF-bypass payload fuzzer** with honest validation. It is
good at mutating past signature/rule-based filters (including OWASP CRS) and
proving a finding is real (active SQLi confirmation, live-browser XSS). It is
**not**:

- a replacement for sqlmap/Burp - far narrower technique coverage, no DB
  dumping, no broad crawl;
- effective against **managed WAFs** (Cloudflare/Akamai/Imperva) that use ML,
  bot/TLS fingerprinting, IP reputation and rate control - jitter/UA options
  do not defeat those;
- a fully general exploit finder - findings are heuristically scored and,
  despite the validators, **must be manually verified**.

Use it where it is strong: authorized testing of endpoints behind rule-based
WAFs, lab/CTF, and learning.

## Limitations / future work

- The fitness function is heuristic; findings **must be manually verified**.
- The RL agent is a simple tabular Q-table; deep RL (DQN) could learn richer
  state spaces (e.g. which mutation combination suits which WAF type).
- WAF fingerprinting could prioritize known bypasses for a detected product.
- Multiple parameters / injection points could be fuzzed at once.
- Requests are intentionally serial/slow to avoid tripping WAF/rate limits.

## Logs

Each run appends every tried payload, its score, and reason to
`logs/evolve_log.jsonl` (JSON Lines). The learned Q-table is stored as
`logs/<target>_qtable.json` and auto-loaded on the next run (memory
accumulates against the same target).
