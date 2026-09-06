"""
Bounded HTTP request-rate test.

Registry function:
    http_rate_test

Use only against HTTP/HTTPS services you own or are explicitly
authorized to test.

This module intentionally limits concurrency and request count to
avoid turning the tool into an unrestricted traffic generator.
"""

from __future__ import annotations
from ..core.colors import module_banner
WEBTESTER_BANNER = r"""
__        __      _       _
\ \      / /__  | |__   | |_ ___  ___| |_ ___ _ __
 \ \ /\ / / _ \ | '_ \  | __/ _ \/ __| __/ _ \ '__|
  \ V  V /  __/ | |_) | | ||  __/\__ \ ||  __/ |
   \_/\_/ \___| |_.__/   \__\___||___/\__\___|_|

                    WEB TESTER
           Coded by : argcyberskillhub
"""

def show_banner():
    print(module_banner(WEBTESTER_BANNER, "webtester"))


import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)

from ..core.ui import (
    section,
    ok,
    info,
    warn,
    err,
    get_str,
    get_int,
    spinner,
    wait_or_exit,
    print_two_col,
)
from ..core.export import prompt_export


UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36"
)

MAX_REQUESTS = 20000
MAX_WORKERS = 100
DEFAULT_REQUESTS = 200
DEFAULT_WORKERS = 20
DEFAULT_TIMEOUT = 100


def _normalize_url(url: str) -> str:
    """Normalize a user supplied HTTP URL."""

    url = (url or "").strip()

    if not url:
        return ""

    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Invalid URL: hostname is missing.")

    return url


def _single_request(
    url: str,
    timeout: int,
) -> dict:
    """
    Execute one bounded GET request.

    Only a small response prefix is read so that a large response
    does not unnecessarily consume bandwidth.
    """

    started = time.perf_counter()

    result = {
        "status": None,
        "latency_ms": None,
        "ok": False,
        "error": None,
    }

    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": UA,
                "Accept": "*/*",
                "Connection": "close",
            },
            method="GET",
        )

        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:
            # Read only a small prefix.
            response.read(1024)

            result["status"] = response.status
            result["ok"] = 200 <= response.status < 500

    except urllib.error.HTTPError as exc:
        # An HTTP response, even an error response, proves that the
        # endpoint responded.
        result["status"] = exc.code
        result["ok"] = True
        result["error"] = str(exc)

    except urllib.error.URLError as exc:
        result["error"] = str(exc.reason)

    except TimeoutError:
        result["error"] = "timeout"

    except Exception as exc:
        result["error"] = str(exc)

    result["latency_ms"] = round(
        (time.perf_counter() - started) * 1000,
        2,
    )

    return result


def _summarize(results: list[dict]) -> dict:
    """Create aggregate request statistics."""

    total = len(results)

    successful = [
        item for item in results
        if item["ok"]
    ]

    statuses: dict[str, int] = {}

    for item in results:
        status = item.get("status")

        if status is not None:
            key = str(status)
            statuses[key] = statuses.get(key, 0) + 1

    latencies = [
        item["latency_ms"]
        for item in results
        if item.get("latency_ms") is not None
    ]

    elapsed_values = latencies

    if latencies:
        average_latency = round(
            sum(latencies) / len(latencies),
            2,
        )
        minimum_latency = min(latencies)
        maximum_latency = max(latencies)

        ordered = sorted(latencies)
        p95_index = min(
            len(ordered) - 1,
            max(0, int(len(ordered) * 0.95) - 1),
        )
        p95_latency = ordered[p95_index]

    else:
        average_latency = None
        minimum_latency = None
        maximum_latency = None
        p95_latency = None

    return {
        "total_requests": total,
        "responses": len(successful),
        "failed_requests": total - len(successful),
        "status_counts": statuses,
        "average_latency_ms": average_latency,
        "minimum_latency_ms": minimum_latency,
        "maximum_latency_ms": maximum_latency,
        "p95_latency_ms": p95_latency,
    }


def http_rate_test():
    section("HTTP request-rate test (authorized)")

    url = get_str(
        "Target URL"
    ) or ""

    if not url:
        return

    try:
        url = _normalize_url(url)
    except ValueError as exc:
        err(str(exc))
        wait_or_exit()
        return

    # Keep the test deliberately bounded.
    requests = get_int(
        "Number of requests",
        DEFAULT_REQUESTS,
    )

    workers = get_int(
        "Concurrent workers",
        DEFAULT_WORKERS,
    )

    timeout = get_int(
        "Per-request timeout (seconds)",
        DEFAULT_TIMEOUT,
    )

    if requests < 1:
        err("Request count must be at least 1.")
        wait_or_exit()
        return

    if requests > MAX_REQUESTS:
        warn(
            f"Request count capped at {MAX_REQUESTS}."
        )
        requests = MAX_REQUESTS

    if workers < 1:
        err("Worker count must be at least 1.")
        wait_or_exit()
        return

    if workers > MAX_WORKERS:
        warn(
            f"Concurrency capped at {MAX_WORKERS} workers."
        )
        workers = MAX_WORKERS

    if timeout < 1:
        err("Timeout must be at least 1 second.")
        wait_or_exit()
        return

    info(f"Target      : {url}")
    info(f"Requests    : {requests}")
    info(f"Concurrency : {workers}")
    info(f"Timeout     : {timeout}s")

    warn(
        "Run this only against a system you own or are "
        "explicitly authorized to test."
    )

    results: list[dict] = []

    started = time.perf_counter()

    try:
        with ThreadPoolExecutor(
            max_workers=workers
        ) as executor:

            futures = [
                executor.submit(
                    _single_request,
                    url,
                    timeout,
                )
                for _ in range(requests)
            ]

            with spinner():
                for future in as_completed(futures):
                    try:
                        results.append(
                            future.result()
                        )
                    except Exception as exc:
                        results.append(
                            {
                                "status": None,
                                "latency_ms": None,
                                "ok": False,
                                "error": str(exc),
                            }
                        )

    except KeyboardInterrupt:
        warn("Test interrupted by user.")

    elapsed = time.perf_counter() - started

    summary = _summarize(results)

    if elapsed > 0:
        achieved_rate = round(
            len(results) / elapsed,
            2,
        )
    else:
        achieved_rate = None

    summary["elapsed_seconds"] = round(
        elapsed,
        3,
    )

    summary["achieved_requests_per_second"] = (
        achieved_rate
    )

    summary["target"] = url
    summary["configured_requests"] = requests
    summary["configured_workers"] = workers
    summary["timeout_seconds"] = timeout

    print_two_col(
        ["Metric", "Value"],
        [
            [
                "Requests completed",
                summary["total_requests"],
            ],
            [
                "Responses",
                summary["responses"],
            ],
            [
                "Failed requests",
                summary["failed_requests"],
            ],
            [
                "Elapsed",
                f"{summary['elapsed_seconds']} s",
            ],
            [
                "Observed rate",
                (
                    f"{achieved_rate} req/s"
                    if achieved_rate is not None
                    else "n/a"
                ),
            ],
            [
                "Average latency",
                (
                    f"{summary['average_latency_ms']} ms"
                    if summary["average_latency_ms"] is not None
                    else "n/a"
                ),
            ],
            [
                "Minimum latency",
                (
                    f"{summary['minimum_latency_ms']} ms"
                    if summary["minimum_latency_ms"] is not None
                    else "n/a"
                ),
            ],
            [
                "Maximum latency",
                (
                    f"{summary['maximum_latency_ms']} ms"
                    if summary["maximum_latency_ms"] is not None
                    else "n/a"
                ),
            ],
            [
                "P95 latency",
                (
                    f"{summary['p95_latency_ms']} ms"
                    if summary["p95_latency_ms"] is not None
                    else "n/a"
                ),
            ],
            [
                "HTTP statuses",
                (
                    ", ".join(
                        f"{k}: {v}"
                        for k, v in sorted(
                            summary["status_counts"].items()
                        )
                    )
                    or "none"
                ),
            ],
        ],
    )

    if summary["failed_requests"] == 0:
        ok("All test requests received a response.")
    else:
        warn(
            f"{summary['failed_requests']} request(s) "
            "failed or timed out."
        )

    prompt_export(
        summary,
        "http_rate_test",
    )

    wait_or_exit()
