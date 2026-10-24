"""
report.py
Generates a Markdown report of confirmed findings: reproduction command,
evidence, minimized payload, the learned evasion profile and the detected
WAF - something you can paste into a pentest/bug-bounty writeup.
"""
import shlex
from datetime import datetime
from pathlib import Path


def _curl_repro(cfg, payload: str) -> str:
    url = cfg.target_url
    mode = cfg.inject_mode
    ua = cfg.user_agent or "Mozilla/5.0"
    base = f"curl -s -A {shlex.quote(ua)}"
    if mode == "query":
        return f"{base} -G {shlex.quote(url)} --data-urlencode {shlex.quote(cfg.param_name + '=' + payload)}"
    if mode == "form":
        return f"{base} -X POST {shlex.quote(url)} --data-urlencode {shlex.quote(cfg.param_name + '=' + payload)}"
    if mode == "json":
        import json
        body = json.dumps({cfg.param_name: payload})
        return f"{base} -X POST -H 'Content-Type: application/json' -d {shlex.quote(body)} {shlex.quote(url)}"
    if mode == "header":
        return f"{base} -H {shlex.quote(cfg.param_name + ': ' + payload)} {shlex.quote(url)}"
    if mode == "template":
        body = (cfg.body_template or "FUZZ").replace("FUZZ", payload)
        ct = cfg.content_type or "application/x-www-form-urlencoded"
        return f"{base} -X POST -H {shlex.quote('Content-Type: ' + ct)} -d {shlex.quote(body)} {shlex.quote(url)}"
    return f"{base} {shlex.quote(url)}"


def write_report(path: str, cfg, detected_waf: str, findings: list, top_ops: list,
                 total_requests: int, max_items: int = 15) -> str:
    findings = sorted(findings, key=lambda f: f.get("fitness", 0), reverse=True)
    total_findings = len(findings)
    shown = findings[:max_items]
    lines = []
    lines.append("# WAF Evolver report")
    lines.append("")
    lines.append(f"- Date: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"- Target: `{cfg.target_url}`")
    if cfg.verify_url:
        lines.append(f"- Verify URL (second-order): `{cfg.verify_url}`")
    lines.append(f"- Category: `{cfg.category}`  |  Injection: `{cfg.inject_mode}`  |  "
                 f"Param/field: `{cfg.param_name}`  |  Method: `{cfg.method}`")
    lines.append(f"- Detected WAF: **{detected_waf}**")
    lines.append(f"- Total requests sent: {total_requests}")
    lines.append(f"- Confirmed findings: {total_findings}" +
                 (f" (showing top {len(shown)})" if total_findings > len(shown) else ""))
    lines.append("")
    lines.append("> Heuristic tool output - verify manually before reporting.")
    lines.append("")

    if not shown:
        lines.append("_No validated findings._")
    for i, f in enumerate(shown, 1):
        lines.append(f"## Finding {i}")
        lines.append("")
        lines.append(f"- Validated: **{f.get('validated')}**  |  HTTP status: {f.get('status_code')}  "
                     f"|  score: {f.get('fitness')}")
        lines.append("- Payload:")
        lines.append("")
        lines.append("```")
        lines.append(f.get("payload", ""))
        lines.append("```")
        lines.append(f"- Evidence: {f.get('reason', '')}")
        lines.append("- Reproduce:")
        lines.append("")
        lines.append("```bash")
        lines.append(_curl_repro(cfg, f.get("payload", "")))
        if cfg.verify_url:
            lines.append("# then observe the effect at:")
            lines.append(f"curl -s {cfg.verify_url}")
        lines.append("```")
        lines.append("")

    lines.append("## Learned evasion profile")
    lines.append("")
    lines.append(f"Operators that worked against this target (`{detected_waf}`):")
    lines.append("")
    for name, q in top_ops:
        lines.append(f"- `{name}`: {q:+.2f}")
    lines.append("")

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(lines))
    return path
