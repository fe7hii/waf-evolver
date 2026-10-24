"""
cli.py
Command-line interface for running WAF Evolver.

USAGE:
    python3 cli.py --url http://localhost:8080/search --param q \
        --seeds seeds/sqli_seeds.txt --generations 30

IMPORTANT: Only use against targets you are authorized to test.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from waf_evolve import EvolveConfig, WAFEvolver


def load_seeds(path: str):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def main():
    parser = argparse.ArgumentParser(
        description="AI-assisted WAF bypass fuzzer (genetic algorithm + RL)"
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", default="q", help="Name of the parameter to inject into")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--seeds", required=True, help="Initial payload file (one payload per line)")
    parser.add_argument("--generations", type=int, default=30)
    parser.add_argument("--population", type=int, default=40)
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests (seconds)")
    parser.add_argument("--threshold", type=float, default=60.0, help="Fitness score accepted as success")
    parser.add_argument("--rl", action="store_true", help="Enable the experimental RL agent (off by default; neutral in our benchmarks)")
    parser.add_argument("--no-rl", action="store_true", help="(Deprecated, kept for compatibility; RL is off by default)")
    parser.add_argument("--header", action="append", default=[], help="Extra header, 'Key: Value' format, can be used multiple times")
    parser.add_argument("--category", default="generic", choices=["generic", "sqli", "xss", "lfi"],
                         help="Payload category - important for selecting the right validation logic")
    parser.add_argument("--dynamic-validation", action="store_true",
                         help="For XSS: look for real JS-execution proof in a real browser via Playwright (slow but definitive; Playwright must be installed)")
    parser.add_argument("--xss-live", action="store_true",
                         help="For XSS dynamic validation: drive the real browser to the live target URL (applies real parsing/CSP) instead of rendering the captured response body")
    parser.add_argument("--no-require-validation", action="store_true",
                         help="Accept success on fitness score alone, do not require category-specific validation (legacy behavior)")
    parser.add_argument("--max-requests", type=int, default=0,
                         help="Hard cap on total HTTP requests (0 = unlimited). Includes active confirmation probes.")
    parser.add_argument("--baseline-samples", type=int, default=3,
                         help="Number of baseline requests to sample (median used to reduce noise)")
    parser.add_argument("--no-minimize", action="store_true",
                         help="Do not minimize the confirmed payload after success")
    parser.add_argument("--inject", default="query",
                         choices=["query", "form", "json", "header", "template"],
                         help="Where to place the payload: URL query, form body, JSON body, an HTTP header, or a free-form body template")
    parser.add_argument("--body-template", default=None,
                         help="For --inject template: request body containing the marker FUZZ, replaced by the payload")
    parser.add_argument("--content-type", default=None,
                         help="Override Content-Type (useful with --inject json/template)")
    parser.add_argument("--verify-url", default=None,
                         help="Second-order/stored: URL where the effect surfaces; validation runs against this page")
    parser.add_argument("--jitter", type=float, default=0.0,
                         help="Random 0..JITTER seconds added to each inter-request delay")
    parser.add_argument("--user-agent", default=None, help="Custom User-Agent (default: a common browser UA)")
    parser.add_argument("--random-ua", action="store_true", help="Rotate the User-Agent per request")
    parser.add_argument("--no-fingerprint", action="store_true", help="Skip WAF fingerprinting / operator priors")
    parser.add_argument("--export-tamper", default=None, metavar="PATH",
                         help="After success, write a sqlmap tamper script of the learned bypass to PATH")
    parser.add_argument("--proxy", default=None, help="Route all traffic through an upstream proxy (e.g. Burp: http://127.0.0.1:8080)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification (useful with an intercepting proxy)")
    parser.add_argument("--cookie", default=None, help="Cookie header for authenticated testing ('k=v; k2=v2')")
    parser.add_argument("--find-all", action="store_true", help="Do not stop at the first finding; collect all distinct validated bypasses")
    parser.add_argument("--report", default=None, metavar="PATH", help="Write a Markdown report of findings to PATH")

    args = parser.parse_args()

    extra_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    try:
        seeds = load_seeds(args.seeds)
    except OSError as e:
        print(f"[x] Could not read seeds file: {e}")
        sys.exit(2)
    if not seeds:
        print("[x] Seeds file is empty - provide at least one payload.")
        sys.exit(2)
    print(f"[*] Loaded {len(seeds)} seed payload(s).")
    print(f"[*] Target: {args.url} (param={args.param}, method={args.method})")
    print(f"[*] {args.generations} generations, population={args.population}, RL={'on (experimental)' if args.rl else 'off'}")
    print("[!] Only use against targets you are authorized to test.\n")

    config = EvolveConfig(
        target_url=args.url,
        param_name=args.param,
        method=args.method,
        generations=args.generations,
        population_size=args.population,
        request_delay=args.delay,
        success_threshold=args.threshold,
        use_rl_agent=args.rl,
        extra_headers=extra_headers,
        category=args.category,
        use_dynamic_validation=args.dynamic_validation,
        require_validation=not args.no_require_validation,
        max_requests=args.max_requests,
        baseline_samples=args.baseline_samples,
        minimize=not args.no_minimize,
        xss_live=args.xss_live,
        inject_mode=args.inject,
        body_template=args.body_template,
        content_type=args.content_type,
        verify_url=args.verify_url,
        jitter=args.jitter,
        user_agent=args.user_agent,
        random_ua=args.random_ua,
        fingerprint=not args.no_fingerprint,
        export_tamper=args.export_tamper,
        proxy=args.proxy,
        verify_tls=not args.insecure,
        cookies=args.cookie,
        find_all=args.find_all,
        report=args.report,
    )

    evolver = WAFEvolver(config, seeds)
    try:
        best = evolver.run()
    except RuntimeError as e:
        print(f"[x] {e}")
        sys.exit(2)

    print("\n" + "=" * 60)
    print(f"BEST PAYLOAD FOUND: {best.payload}")
    print(f"SCORE: {best.fitness:.1f}")
    print(f"DETAIL: {best.reason}")
    print("=" * 60)


if __name__ == "__main__":
    main()
