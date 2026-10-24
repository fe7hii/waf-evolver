"""
engine.py
The main evolutionary (genetic algorithm) loop. Mutates a population of
payloads across generations, keeps the fittest, and uses a contextual RL
agent to learn which mutations help.

Features: multiple injection locations (query/form/json/header/template),
second-order/stored verification via a separate URL, multi-sample baseline,
active SQLi confirmation via a prober, de-duplication, a request budget,
request jitter + browser-like User-Agent, and post-success minimization.

Use ONLY against targets you are authorized to test.
"""
import json
import logging
import random
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

from . import fingerprint as fp
from . import mutations, tamper_export
from .agent import MutationAgent
from .fitness import FitnessResult, calculate_fitness
from .validators import BrowserSession

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("waf_evolve")

DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

UA_POOL = [
    DEFAULT_UA,
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
     "(KHTML, like Gecko) Version/17.4 Safari/605.1.15"),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"),
]

FUZZ_MARKER = "FUZZ"


@dataclass
class Individual:
    payload: str
    fitness: float = 0.0
    reason: str = ""
    status_code: int | None = None
    validated: bool | None = None
    source_op: str | None = None


@dataclass
class EvolveConfig:
    target_url: str
    param_name: str = "q"
    method: str = "GET"
    generations: int = 30
    population_size: int = 40
    survival_ratio: float = 0.3
    request_delay: float = 1.0
    success_threshold: float = 60.0
    use_rl_agent: bool = False
    extra_headers: dict = field(default_factory=dict)
    log_file: str | None = "logs/evolve_log.jsonl"
    category: str = "generic"
    use_dynamic_validation: bool = False
    require_validation: bool = True
    max_requests: int = 0
    baseline_samples: int = 3
    minimize: bool = True
    xss_live: bool = False
    inject_mode: str = "query"
    body_template: str | None = None
    content_type: str | None = None
    verify_url: str | None = None
    jitter: float = 0.0
    user_agent: str | None = None
    random_ua: bool = False
    fingerprint: bool = True
    export_tamper: str | None = None
    proxy: str | None = None
    verify_tls: bool = True
    cookies: str | None = None
    find_all: bool = False
    report: str | None = None


def _bucket(status: int | None) -> str:
    if status is None:
        return "none"
    if status in (403, 406):
        return "blocked"
    if status == 429:
        return "ratelimited"
    if status >= 500:
        return "error"
    if status == 200:
        return "ok"
    return "other"


class WAFEvolver:
    def __init__(self, config: EvolveConfig, seed_payloads: list[str]):
        self.cfg = config
        self.seed_payloads = seed_payloads
        self.session = requests.Session()
        self.session.headers["User-Agent"] = config.user_agent or DEFAULT_UA
        if config.extra_headers:
            self.session.headers.update(config.extra_headers)
        if config.proxy:
            self.session.proxies.update({"http": config.proxy, "https": config.proxy})
        if not config.verify_tls:
            self.session.verify = False
            try:
                import urllib3
                urllib3.disable_warnings()
            except Exception:
                pass
        if config.cookies:
            for part in config.cookies.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())

        self._ops = mutations.operators_for(config.category)
        self.agent = MutationAgent(
            self._ops,
            save_path=f"logs/{self._safe_name()}_qtable.json" if config.use_rl_agent else None,
        ) if config.use_rl_agent else None

        self.baseline_response = None
        self.baseline_stats: dict = {}
        self.detected_waf = "unknown"
        self._op_weights = None
        self.findings: list[dict] = []
        self._finding_payloads: set = set()
        self.best_individual: Individual | None = None
        self._browser_session: BrowserSession | None = None
        self._consecutive_429 = 0
        self._requests_made = 0
        self._budget_exhausted = False
        self._cache: dict = {}
        self.log_path = Path(config.log_file) if config.log_file else None
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _safe_name(self):
        return "".join(c if c.isalnum() else "_" for c in self.cfg.target_url)[:50]

    def _budget_left(self) -> bool:
        if self.cfg.max_requests <= 0:
            return True
        return self._requests_made < self.cfg.max_requests

    def _sleep_after(self):
        extra = random.uniform(0, self.cfg.jitter) if self.cfg.jitter > 0 else 0.0
        time.sleep(self.cfg.request_delay + extra)

    def _build_request(self, payload: str):
        """Return (method, url, kwargs) placing the payload per inject_mode."""
        mode = self.cfg.inject_mode
        method = self.cfg.method.upper()
        url = self.cfg.target_url
        kwargs: dict = {}
        if mode == "query":
            kwargs["params"] = {self.cfg.param_name: payload}
        elif mode == "form":
            method = "POST" if method == "GET" else method
            kwargs["data"] = {self.cfg.param_name: payload}
        elif mode == "json":
            method = "POST" if method == "GET" else method
            kwargs["json"] = {self.cfg.param_name: payload}
        elif mode == "header":
            kwargs["headers"] = {self.cfg.param_name: payload}
        elif mode == "template":
            tmpl = self.cfg.body_template or (FUZZ_MARKER)
            body = tmpl.replace(FUZZ_MARKER, payload)
            method = "POST" if method == "GET" else method
            kwargs["data"] = body.encode()
            ct = self.cfg.content_type or "application/x-www-form-urlencoded"
            kwargs["headers"] = {"Content-Type": ct}
        else:
            kwargs["params"] = {self.cfg.param_name: payload}
        if self.cfg.content_type and mode in ("json",):
            kwargs.setdefault("headers", {})["Content-Type"] = self.cfg.content_type
        return method, url, kwargs

    def _raw_send(self, payload: str):
        """Low-level send honoring injection mode, budget, UA rotation,
        delay+jitter and adaptive 429 backoff. Also used as the active-
        confirmation prober."""
        if not self._budget_left():
            self._budget_exhausted = True
            return None
        method, url, kwargs = self._build_request(payload)
        if self.cfg.random_ua:
            kwargs.setdefault("headers", {})["User-Agent"] = random.choice(UA_POOL)
        try:
            resp = self.session.request(method, url, timeout=15, **kwargs)
        except requests.RequestException as e:
            logger.warning(f"Request error: {e}")
            return None
        self._requests_made += 1
        self._handle_backoff(resp)
        return resp

    def _get_url(self, url: str):
        """Plain GET of a URL (used to read the second-order/verify page)."""
        if not self._budget_left():
            self._budget_exhausted = True
            return None
        headers = {}
        if self.cfg.random_ua:
            headers["User-Agent"] = random.choice(UA_POOL)
        try:
            resp = self.session.get(url, timeout=15, headers=headers or None)
        except requests.RequestException as e:
            logger.warning(f"Verify request error: {e}")
            return None
        self._requests_made += 1
        self._handle_backoff(resp)
        return resp

    def _handle_backoff(self, resp):
        if resp.status_code == 429:
            self._consecutive_429 += 1
            backoff = min(self.cfg.request_delay * (2 ** self._consecutive_429), 30.0)
            logger.warning(f"  got 429 ({self._consecutive_429} in a row), waiting {backoff:.1f}s (adaptive backoff)...")
            time.sleep(backoff)
        else:
            self._consecutive_429 = 0
            self._sleep_after()

    def _get_baseline(self):
        logger.info(f"Sending {self.cfg.baseline_samples} baseline (reference) request(s)...")
        samples = []
        for _ in range(max(1, self.cfg.baseline_samples)):
            payload = f"harmless_test_value_{random.randint(1000,9999)}"
            inj = self._raw_send(payload)
            r = self._get_url(self.cfg.verify_url) if self.cfg.verify_url else inj
            if r is not None:
                samples.append(r)
        if not samples:
            raise RuntimeError("Baseline request failed; the target appears unreachable.")
        self.baseline_response = samples[-1]
        self.baseline_stats = {
            "text": samples[-1].text,
            "median_len": statistics.median(len(s.text) for s in samples),
            "median_elapsed": statistics.median(s.elapsed.total_seconds() for s in samples),
        }
        logger.info(
            f"Baseline: status={self.baseline_response.status_code}, "
            f"median_len={self.baseline_stats['median_len']:.0f}, "
            f"median_time={self.baseline_stats['median_elapsed']:.3f}s"
        )

    def _log_entry(self, generation: int, individual: Individual):
        if not self.log_path:
            return
        entry = {
            "generation": generation,
            "payload": individual.payload,
            "fitness": individual.fitness,
            "status_code": individual.status_code,
            "validated": individual.validated,
            "reason": individual.reason,
            "timestamp": time.time(),
        }
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def _init_population(self) -> list[tuple]:
        pop = []
        while len(pop) < self.cfg.population_size:
            pop.extend(self.seed_payloads)
        return [(p, None) for p in pop[: self.cfg.population_size]]

    def _xss_target(self):
        stored = self.cfg.verify_url is not None
        nav_url = self.cfg.verify_url or self.cfg.target_url
        live_ok = self.cfg.xss_live and (stored or self.cfg.inject_mode == "query")
        return {
            "live": live_ok,
            "stored": stored,
            "url": nav_url,
            "method": self.cfg.method,
            "param": self.cfg.param_name,
            "headers": dict(self.session.headers),
        }

    def _evaluate(self, payload: str, source_op: str | None = None) -> Individual:
        if payload in self._cache:
            c = self._cache[payload]
            return Individual(payload, c.fitness, c.reason, c.status_code, c.validated, source_op)

        injection = self._raw_send(payload)
        if injection is None:
            return Individual(payload=payload, fitness=-999, reason="request failed or budget exhausted", source_op=source_op)

        if injection.status_code in (403, 406):
            analyze = injection
        elif self.cfg.verify_url:
            ver = self._get_url(self.cfg.verify_url)
            analyze = ver if ver is not None else injection
        else:
            analyze = injection

        if self.cfg.use_dynamic_validation and self.cfg.category == "xss" and \
                (self._browser_session is None or not getattr(self._browser_session, "available", False)):
            logger.warning("  dynamic XSS validation requested but no working browser - using STATIC validation.")

        result: FitnessResult = calculate_fitness(
            analyze,
            self.baseline_response,
            payload,
            category=self.cfg.category,
            use_dynamic_validation=self.cfg.use_dynamic_validation,
            browser_session=self._browser_session,
            prober=(None if self.cfg.verify_url else self._raw_send),
            baseline_stats=self.baseline_stats,
            xss_target=self._xss_target(),
        )
        ind = Individual(
            payload=payload,
            fitness=result.score,
            reason=result.reason,
            status_code=result.status_code,
            validated=result.validated,
            source_op=source_op,
        )
        self._cache[payload] = ind
        return ind

    def _select_survivors(self, evaluated: list[Individual]) -> list[Individual]:
        sorted_pop = sorted(evaluated, key=lambda ind: ind.fitness, reverse=True)
        n = max(2, int(len(evaluated) * self.cfg.survival_ratio))
        return sorted_pop[:n]

    def _breed_next_generation(self, survivors: list[Individual], state: str) -> list[tuple]:
        next_gen = [(s.payload, None) for s in survivors]
        while len(next_gen) < self.cfg.population_size:
            p1, p2 = random.sample(survivors, min(2, len(survivors)))
            child = mutations.crossover(p1.payload, p2.payload)
            if self.agent:
                op = self.agent.choose_mutation(state)
                child = mutations.mutate(child, operators=[op])
                op_name = op.__name__
            else:
                child = mutations.mutate(child, operators=self._ops, weights=self._op_weights)
                op_name = None
            next_gen.append((child, op_name))
        return next_gen

    def _minimize(self, ind: Individual) -> Individual:
        if ind.validated is not True:
            return ind
        logger.info("Minimizing the confirmed payload...")
        current = ind
        improved = True
        passes = 0
        while improved and passes < 3 and self._budget_left():
            improved = False
            passes += 1
            bounds = mutations._token_boundaries(current.payload)
            for i in range(len(bounds) - 1):
                if not self._budget_left():
                    break
                cand = current.payload[:bounds[i]] + current.payload[bounds[i + 1]:]
                if not cand or cand == current.payload:
                    continue
                self._cache.pop(cand, None)
                trial = self._evaluate(cand)
                if trial.validated is True and len(cand) < len(current.payload):
                    current = trial
                    improved = True
                    break
        if current.payload != ind.payload:
            logger.info(f"Minimized: {ind.payload!r} -> {current.payload!r}")
        return current

    def run(self) -> Individual:
        if self.cfg.category == "xss" and self.cfg.use_dynamic_validation:
            logger.info("Starting a single Chromium instance for dynamic XSS validation...")
            self._browser_session = BrowserSession(
                proxy=self.cfg.proxy,
                ignore_https_errors=not self.cfg.verify_tls,
            ).__enter__()
        try:
            return self._run_inner()
        finally:
            if self._browser_session:
                self._browser_session.__exit__(None, None, None)
                logger.info("Chromium instance closed.")

    def _run_inner(self) -> Individual:
        self._get_baseline()

        if self.cfg.fingerprint:
            product, detail = fp.fingerprint_waf(self._raw_send)
            self.detected_waf = product or "none"
            logger.info(f"WAF fingerprint: {self.detected_waf} ({detail})")
            if product in fp.WAF_OPERATOR_PRIORS:
                names = [o.__name__ for o in self._ops]
                priors = [o for o in fp.WAF_OPERATOR_PRIORS[product] if o in names]
                if self.agent:
                    self.agent.seed_priors(priors)
                    logger.info(f"Seeded agent priors for {self.detected_waf}: {priors}")
                elif priors:
                    self._op_weights = {o: 3.0 for o in priors}
                    logger.info(f"Weighted operators for {self.detected_waf}: {priors}")

        population = self._init_population()
        state = f"{self.cfg.category}|none"

        for gen in range(1, self.cfg.generations + 1):
            if self._budget_exhausted or not self._budget_left():
                logger.info(f"Request budget ({self.cfg.max_requests}) reached. Stopping.")
                break
            logger.info(f"--- Generation {gen}/{self.cfg.generations} ---")
            evaluated = []

            for payload, source_op in population:
                ind = self._evaluate(payload, source_op=source_op)
                evaluated.append(ind)
                self._log_entry(gen, ind)

                if self.agent and ind.source_op:
                    self.agent.update(ind.source_op, ind.fitness, state=state)

                if ind.validated is True and ind.payload not in self._finding_payloads:
                    self._finding_payloads.add(ind.payload)
                    self.findings.append({
                        "payload": ind.payload, "reason": ind.reason,
                        "status_code": ind.status_code, "fitness": round(ind.fitness, 1),
                        "validated": ind.validated,
                    })
                    logger.info(f"  CONFIRMED FINDING #{len(self.findings)}: {ind.payload!r}")

                if self.best_individual is None or ind.fitness > self.best_individual.fitness:
                    self.best_individual = ind
                    logger.info(f"  NEW BEST (score={ind.fitness:.1f}, status={ind.status_code}, "
                                f"validated={ind.validated}, op={ind.source_op}): {ind.payload!r}")

                if self._budget_exhausted:
                    break

            success = self.best_individual.fitness >= self.cfg.success_threshold
            if success and self.cfg.require_validation and self.cfg.category != "generic":
                success = self.best_individual.validated is True

            if success and not self.cfg.find_all:
                logger.info(f"SUCCESS (score={self.best_individual.fitness:.1f} >= "
                            f"{self.cfg.success_threshold}, validated={self.best_individual.validated}). Stopping.")
                break
            if success and self.cfg.find_all:
                logger.info(f"  (find-all mode: {len(self.findings)} finding(s) so far, continuing)")

            survivors = self._select_survivors(evaluated)
            state = f"{self.cfg.category}|{_bucket(survivors[0].status_code)}"
            logger.info(f"  Gen avg score: {sum(i.fitness for i in evaluated) / len(evaluated):.1f}, "
                        f"best survivor: {survivors[0].fitness:.1f}, state='{state}', "
                        f"requests={self._requests_made}")

            population = self._breed_next_generation(survivors, state)
            if self.agent:
                self.agent.decay_epsilon()

        if self.cfg.minimize and not self.cfg.verify_url and not self.cfg.find_all and \
                self.best_individual and self.best_individual.validated is True:
            minimized = self._minimize(self.best_individual)
            if minimized.payload != self.best_individual.payload and minimized.payload not in self._finding_payloads:
                self._finding_payloads.add(minimized.payload)
                self.findings.insert(0, {
                    "payload": minimized.payload, "reason": minimized.reason,
                    "status_code": minimized.status_code, "fitness": round(minimized.fitness, 1),
                    "validated": minimized.validated,
                })
            self.best_individual = minimized
        elif self.best_individual and self.best_individual.validated is True and \
                (self.cfg.verify_url or self.cfg.find_all):
            logger.info("Skipping minimization (second-order/stored or find-all mode).")

        if self.agent:
            self.agent.save()
            logger.info("\n" + self.agent.report())
            top = self.agent.top_operators(5)
            logger.info("Evasion profile (top operators vs this target): "
                        + ", ".join(f"{n} {q:+.1f}" for n, q in top))
            self._write_profile(top)

        if self.cfg.export_tamper and self.agent:
            path = tamper_export.export_sqlmap_tamper(self.agent, self.cfg.export_tamper, self.detected_waf)
            if path:
                logger.info(f"sqlmap tamper written: {path} (use: sqlmap --tamper={Path(path).stem})")
            else:
                logger.info("No deterministic SQL operators learned; sqlmap tamper not exported.")

        if self.cfg.report:
            try:
                top = self.agent.top_operators(10) if self.agent else []
                from . import report as _report
                path = _report.write_report(self.cfg.report, self.cfg, self.detected_waf,
                                            self.findings, top, self._requests_made)
                logger.info(f"Report written: {path}")
            except Exception as e:
                logger.warning(f"Could not write report: {e}")

        logger.info(
            f"\n=== RESULT ===\nBest payload: {self.best_individual.payload!r}\n"
            f"Score: {self.best_individual.fitness:.1f}\n"
            f"Validated: {self.best_individual.validated}\n"
            f"Confirmed findings: {len(self.findings)}\n"
            f"Detected WAF: {self.detected_waf}\n"
            f"Total requests sent: {self._requests_made}\n"
            f"Reason: {self.best_individual.reason}"
        )
        return self.best_individual

    def _write_profile(self, top):
        if not self.log_path:
            return
        profile = {
            "target": self.cfg.target_url,
            "category": self.cfg.category,
            "detected_waf": self.detected_waf,
            "best_payload": self.best_individual.payload if self.best_individual else None,
            "validated": self.best_individual.validated if self.best_individual else None,
            "top_operators": [{"operator": n, "value": round(q, 2)} for n, q in top],
            "total_requests": self._requests_made,
        }
        path = self.log_path.parent / f"{self._safe_name()}_profile.json"
        try:
            path.write_text(json.dumps(profile, indent=2))
            logger.info(f"Evasion profile written: {path}")
        except Exception as e:
            logger.warning(f"Could not write profile: {e}")
