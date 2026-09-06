"""
Social / public-profile information module.

Registry functions:
    username_availability
    profile_discovery
    platform_search
    email_domain_corr
    website_lookup
    full_enum

Only public, unauthenticated information is queried.
Use responsibly and only for accounts/domains you are authorized
to investigate.
"""
from __future__ import annotations
from ..core.colors import module_banner
SOCIAL_BANNER = r"""
   ____             _       _   _        __
  / ___|  ___   ___(_) __ _| | (_)_ __  / _| ___
  \___ \ / _ \ / __| |/ _` | | | | '_ \| |_ / _ \
   ___) | (_) | (__| | (_| | | | | | | |  _| (_) |
  |____/ \___/ \___|_|\__,_|_| |_|_| |_|_|  \___/

       SOCIAL / OSINT UTILITIES
       Coded by : argcyberskillhub
"""


def show_banner():
    print(module_banner(SOCIAL_BANNER, "social"))


import json
import re
import urllib.error
import urllib.parse
import urllib.request

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

HTTP_TIMEOUT = 10




# --------------------------------------------------------------------------
# Supported public platforms
# --------------------------------------------------------------------------

PLATFORMS = {
    "github": "https://github.com/{username}",
    "gitlab": "https://gitlab.com/{username}",
    "reddit": "https://www.reddit.com/user/{username}/",
    "x": "https://x.com/{username}",
    "instagram": "https://www.instagram.com/{username}/",
    "facebook": "https://www.facebook.com/{username}/",
    "linkedin": "https://www.linkedin.com/in/{username}/",
    "medium": "https://medium.com/@{username}",
    "devto": "https://dev.to/{username}",
    "twitch": "https://www.twitch.tv/{username}",
    "youtube": "https://www.youtube.com/@{username}",
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _valid_username(username: str) -> bool:
    """
    Conservative username validation.

    Allows common usernames without accepting arbitrary URLs.
    """
    return bool(
        re.fullmatch(
            r"[A-Za-z0-9._-]{1,80}",
            username or "",
        )
    )


def _request(
    url: str,
    method: str = "GET",
    timeout: int = HTTP_TIMEOUT,
):
    """Perform a public HTTP request."""

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/json;q=0.9,*/*;q=0.8"
            ),
        },
        method=method,
    )

    return urllib.request.urlopen(
        req,
        timeout=timeout,
    )


def _check_url(url: str) -> dict:
    """Check a public URL without submitting credentials."""

    result = {
        "url": url,
        "status": None,
        "final_url": None,
        "exists": False,
        "error": None,
    }

    try:
        with _request(url, method="HEAD") as response:
            result["status"] = response.status
            result["final_url"] = response.geturl()
            result["exists"] = 200 <= response.status < 400
            return result

    except urllib.error.HTTPError as exc:
        result["status"] = exc.code
        result["final_url"] = exc.geturl()

        # 401/403 can mean the profile exists but is restricted.
        result["exists"] = exc.code in (401, 403)

        result["error"] = exc.reason
        return result

    except Exception as exc:
        result["error"] = str(exc)
        return result


def _get_html(url: str, limit: int = 200_000):
    """Fetch a limited amount of public HTML."""

    try:
        with _request(url) as response:
            body = response.read(limit).decode(
                "utf-8",
                "replace",
            )

            return {
                "status": response.status,
                "final_url": response.geturl(),
                "headers": dict(response.headers.items()),
                "body": body,
            }

    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(limit).decode(
                "utf-8",
                "replace",
            )
        except Exception:
            body = ""

        return {
            "status": exc.code,
            "final_url": exc.geturl(),
            "headers": dict(exc.headers.items()),
            "body": body,
        }

    except Exception as exc:
        return {
            "status": None,
            "final_url": url,
            "headers": {},
            "body": "",
            "error": str(exc),
        }


def _extract_title(html: str) -> str | None:
    """Extract the HTML title."""

    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html or "",
        re.I | re.S,
    )

    if not match:
        return None

    title = re.sub(
        r"\s+",
        " ",
        match.group(1),
    ).strip()

    return title[:200] if title else None


def _platform_from_name(value: str) -> str:
    """Normalize a platform name."""

    value = (value or "").strip().lower()

    aliases = {
        "twitter": "x",
        "x.com": "x",
        "github.com": "github",
        "gitlab.com": "gitlab",
        "reddit.com": "reddit",
        "instagram.com": "instagram",
        "linkedin.com": "linkedin",
        "medium.com": "medium",
        "dev.to": "devto",
        "twitch.tv": "twitch",
        "youtube.com": "youtube",
    }

    return aliases.get(value, value)


# --------------------------------------------------------------------------
# 1. Username availability
# --------------------------------------------------------------------------

def username_availability():
    section("Username availability checker")

    username = get_str("Username") or ""

    if not username:
        return

    if not _valid_username(username):
        err(
            "Invalid username. Use letters, numbers, '.', '_' or '-'."
        )
        wait_or_exit()
        return

    selected = get_str(
        "Platform (or 'all')",
        default="all",
    )

    selected = selected.strip().lower()

    if selected == "all":
        platforms = list(PLATFORMS.keys())
    else:
        platform = _platform_from_name(selected)

        if platform not in PLATFORMS:
            err(
                "Unsupported platform. "
                f"Available: {', '.join(PLATFORMS)}"
            )
            wait_or_exit()
            return

        platforms = [platform]

    results = []

    info(
        f"Checking public profile URLs for '{username}'."
    )

    with spinner():
        for platform in platforms:
            url = PLATFORMS[platform].format(
                username=urllib.parse.quote(
                    username,
                    safe="._-",
                )
            )

            result = _check_url(url)

            result["platform"] = platform
            result["username"] = username

            results.append(result)

    found = [
        item for item in results
        if item["exists"]
    ]

    if found:
        ok(f"Found {len(found)} accessible/likely-existing profile(s).")

        print_two_col(
            ["Platform", "Status", "URL"],
            [
                [
                    item["platform"],
                    item["status"],
                    item["final_url"] or item["url"],
                ]
                for item in found
            ],
        )
    else:
        info("No accessible public profiles were confirmed.")

    prompt_export(
        results,
        f"username_{username}",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 2. Public-profile discovery
# --------------------------------------------------------------------------

def profile_discovery():
    section("Public-profile discovery")

    username = get_str("Username") or ""

    if not username:
        return

    if not _valid_username(username):
        err("Invalid username.")
        wait_or_exit()
        return

    results = []

    info(
        "Checking supported public profile endpoints."
    )

    with spinner():
        for platform, template in PLATFORMS.items():
            url = template.format(
                username=urllib.parse.quote(
                    username,
                    safe="._-",
                )
            )

            result = _check_url(url)
            result["platform"] = platform
            result["username"] = username

            results.append(result)

    confirmed = [
        item for item in results
        if item["exists"]
    ]

    if confirmed:
        ok(f"{len(confirmed)} public profile(s) found.")

        for item in confirmed:
            print(
                f"   . {item['platform']:<12} "
                f"{item['final_url'] or item['url']}"
            )
    else:
        info("No public profile endpoints responded positively.")

    prompt_export(
        {
            "username": username,
            "profiles": results,
        },
        f"profiles_{username}",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 3. Social-platform search
# --------------------------------------------------------------------------

def platform_search():
    section("Social-platform search")

    platform = _platform_from_name(
        get_str("Platform") or ""
    )

    username = get_str("Username") or ""

    if not platform or not username:
        return

    if platform not in PLATFORMS:
        err(
            "Unsupported platform. "
            f"Available: {', '.join(PLATFORMS)}"
        )
        wait_or_exit()
        return

    if not _valid_username(username):
        err("Invalid username.")
        wait_or_exit()
        return

    url = PLATFORMS[platform].format(
        username=urllib.parse.quote(
            username,
            safe="._-",
        )
    )

    result = _check_url(url)

    result.update(
        {
            "platform": platform,
            "username": username,
        }
    )

    if result["exists"]:
        ok(
            f"Public profile appears accessible: "
            f"{result['final_url'] or url}"
        )
    elif result["status"] in (401, 403):
        warn(
            f"Server returned HTTP {result['status']}; "
            "the profile may be restricted."
        )
    elif result["status"]:
        info(
            f"HTTP {result['status']}; "
            "profile was not confirmed."
        )
    else:
        err(
            result.get("error")
            or "Request failed."
        )

    prompt_export(
        result,
        f"profile_{platform}_{username}",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 4. Public email/domain correlation
# --------------------------------------------------------------------------

def email_domain_corr():
    section("Public email/domain correlation")

    email = get_str(
        "Public email address"
    ) or ""

    if not email:
        return

    email = email.strip().lower()

    # Do not attempt password/account recovery or private-data lookup.
    if not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email,
    ):
        err("Invalid email address.")
        wait_or_exit()
        return

    local, domain = email.rsplit("@", 1)

    result = {
        "email": email,
        "local_part": local,
        "domain": domain,
        "domain_addresses": [],
        "website": f"https://{domain}/",
        "website_status": None,
        "website_title": None,
    }

    # Resolve domain through the normal resolver.
    try:
        import socket

        addresses = []

        for item in socket.getaddrinfo(
            domain,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        ):
            address = item[4][0]

            if address not in addresses:
                addresses.append(address)

        result["domain_addresses"] = addresses

    except Exception as exc:
        result["dns_error"] = str(exc)

    # Check whether the public domain website responds.
    page = _get_html(
        result["website"],
        limit=100_000,
    )

    result["website_status"] = page.get("status")
    result["website_final_url"] = page.get("final_url")
    result["website_title"] = _extract_title(
        page.get("body", "")
    )

    info(f"Domain: {domain}")

    if result["domain_addresses"]:
        ok(
            "DNS addresses: "
            + ", ".join(result["domain_addresses"])
        )
    else:
        warn("No DNS address was resolved.")

    if result["website_status"]:
        info(
            f"Website HTTP status: "
            f"{result['website_status']}"
        )

    if result["website_title"]:
        info(
            f"Website title: "
            f"{result['website_title']}"
        )

    info(
        "This check only correlates publicly supplied "
        "email/domain information; it does not access private accounts."
    )

    prompt_export(
        result,
        f"email_domain_{domain}",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 5. Public website/profile lookup
# --------------------------------------------------------------------------

def website_lookup():
    section("Public website / profile lookup")

    url = get_str("URL") or ""

    if not url:
        return

    if not re.match(
        r"^https?://",
        url,
        re.I,
    ):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)

    if not parsed.hostname:
        err("Invalid URL.")
        wait_or_exit()
        return

    info(f"URL: {url}")

    page = _get_html(
        url,
        limit=200_000,
    )

    body = page.get("body", "")
    headers = page.get("headers", {})

    result = {
        "requested_url": url,
        "final_url": page.get("final_url"),
        "status": page.get("status"),
        "title": _extract_title(body),
        "server": headers.get("Server"),
        "content_type": headers.get("Content-Type"),
        "content_length": headers.get("Content-Length"),
        "error": page.get("error"),
    }

    if result["status"] and 200 <= result["status"] < 400:
        ok(
            f"HTTP {result['status']} "
            f"{result['final_url']}"
        )
    elif result["status"]:
        warn(
            f"HTTP {result['status']} "
            f"{result['final_url']}"
        )
    else:
        err(result["error"] or "Request failed.")

    if result["title"]:
        info(f"Title: {result['title']}")

    if result["server"]:
        info(f"Server: {result['server']}")

    prompt_export(
        result,
        f"website_{parsed.hostname}",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 6. Full username enumeration
# --------------------------------------------------------------------------

def full_enum():
    section("Username enumeration")

    username = get_str("Username") or ""

    if not username:
        return

    if not _valid_username(username):
        err("Invalid username.")
        wait_or_exit()
        return

    # Keep this enumeration bounded to the explicitly supported
    # public platforms.
    results = []

    info(
        f"Checking {len(PLATFORMS)} supported public platforms."
    )

    with spinner():
        for platform, template in PLATFORMS.items():
            url = template.format(
                username=urllib.parse.quote(
                    username,
                    safe="._-",
                )
            )

            result = _check_url(url)

            results.append(
                {
                    "username": username,
                    "platform": platform,
                    "status": result["status"],
                    "exists": result["exists"],
                    "url": result["final_url"] or url,
                    "error": result["error"],
                }
            )

    results.sort(
        key=lambda item: (
            not item["exists"],
            item["platform"],
        )
    )

    found = [
        item for item in results
        if item["exists"]
    ]

    if found:
        ok(
            f"Potentially matching public profiles: "
            f"{len(found)}"
        )

        print_two_col(
            ["Platform", "Status", "Profile"],
            [
                [
                    item["platform"],
                    item["status"],
                    item["url"],
                ]
                for item in found
            ],
        )
    else:
        info("No accessible profiles confirmed.")

    prompt_export(
        {
            "username": username,
            "checked_platforms": list(PLATFORMS.keys()),
            "results": results,
        },
        f"enum_{username}",
    )

    wait_or_exit()
