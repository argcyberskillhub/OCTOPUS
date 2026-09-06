"""
Passive IP tracer / network intelligence module.

Provides public information about an IP address using:
- Reverse DNS
- ASN / network information
- Public geolocation API
- Basic IP classification

No port scanning, packet injection, flooding, or intrusive probing.
Use only for legitimate information gathering.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.parse
import urllib.request

from ..core.colors import module_banner
from ..core.export import prompt_export
from ..core.ui import (
    section,
    ok,
    info,
    warn,
    err,
    get_str,
    print_two_col,
    wait_or_exit,
)


IPTRACE_BANNER = r"""
   ___  ____    _____
   |_| |  _ \  |_   _| __ __ _  ___   ___     __
   | | | |_) |   | || '__/ _` |/ __/ / _ \ | '__/
   |_| |  __/    | || | | (_| | (__ | |__/ | |
   |_|_|_|       |_||_|  \__,_|\___\ \___| |_|

          IP TRACER / NETWORK INTELLIGENCE
           Coded by : argcyberskillhub
"""


def show_banner() -> None:
    """Display the IP tracer banner."""
    print(module_banner(IPTRACE_BANNER, "iptrace"))


UA = (
    "Mozilla/5.0 (compatible; Octopus-IPTrace/1.0; "
    "+https://example.invalid)"
)


def _get_public_ip_info(ip: str) -> dict:
    """
    Query public IP information.

    The service is used only for publicly available metadata.
    """

    encoded_ip = urllib.parse.quote(ip, safe="")
    url = f"https://ipwho.is/{encoded_ip}"

    request = urllib.request.Request(
        url,
        headers={"User-Agent": UA},
    )

    with urllib.request.urlopen(
        request,
        timeout=10,
    ) as response:
        raw = response.read(12000)

    data = json.loads(
        raw.decode(
            "utf-8",
            "replace",
        )
    )

    if not isinstance(data, dict):
        raise ValueError(
            "Unexpected response from geolocation service."
        )

    return data


def _reverse_dns(ip: str) -> dict:
    """Perform a passive reverse DNS lookup."""

    result = {
        "hostname": None,
        "aliases": [],
        "addresses": [],
    }

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        result["hostname"] = hostname
        result["aliases"] = aliases
        result["addresses"] = addresses

    except (socket.herror, socket.gaierror):
        pass

    except Exception as exc:
        result["error"] = str(exc)

    return result


def _ip_classification(
    ip_obj: ipaddress._BaseAddress,
) -> dict:
    """Return basic classification information for an IP."""

    return {
        "version": ip_obj.version,
        "private": ip_obj.is_private,
        "global": ip_obj.is_global,
        "loopback": ip_obj.is_loopback,
        "multicast": ip_obj.is_multicast,
        "reserved": ip_obj.is_reserved,
        "link_local": ip_obj.is_link_local,
        "unspecified": ip_obj.is_unspecified,
    }


def ip_trace() -> None:
    """Run passive IP intelligence collection."""

    section("IP Tracer / Network Intelligence")
    show_banner()

    value = get_str("IP address") or ""

    if not value:
        return

    value = value.strip()

    # ------------------------------------------------------------------
    # IP validation
    # ------------------------------------------------------------------

    try:
        ip_obj = ipaddress.ip_address(value)

    except ValueError:
        err(
            "Invalid IP address. Enter IPv4 or IPv6."
        )
        wait_or_exit()
        return

    ip = str(ip_obj)

    info(f"Target IP : {ip}")

    classification = _ip_classification(ip_obj)

    if classification["private"]:
        warn(
            "This is a private/non-public IP. "
            "Public geolocation data may not be available."
        )

    result = {
        "ip": ip,
        "classification": classification,
        "reverse_dns": {},
        "public_info": {},
    }

    # ------------------------------------------------------------------
    # Reverse DNS
    # ------------------------------------------------------------------

    info("Performing reverse DNS lookup...")

    rdns = _reverse_dns(ip)
    result["reverse_dns"] = rdns

    if rdns.get("hostname"):
        ok(
            f"PTR hostname: {rdns['hostname']}"
        )

    else:
        info(
            "No public PTR hostname returned."
        )

    if rdns.get("aliases"):
        info(
            "Aliases: "
            + ", ".join(rdns["aliases"])
        )

    # ------------------------------------------------------------------
    # Public IP intelligence
    # ------------------------------------------------------------------

    if classification["global"]:
        info(
            "Querying public IP intelligence..."
        )

        try:
            data = _get_public_ip_info(ip)

            if data.get("success") is False:
                raise ValueError(
                    data.get(
                        "message",
                        "Public lookup failed.",
                    )
                )

            result["public_info"] = data

        except Exception as exc:
            warn(
                f"Public IP lookup unavailable: {exc}"
            )

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    rows = [
        ["IP address", ip],
        ["Version", classification["version"]],
        ["Public/global", classification["global"]],
        ["Private", classification["private"]],
        ["Loopback", classification["loopback"]],
        ["Reserved", classification["reserved"]],
        ["Link-local", classification["link_local"]],
    ]

    public = result["public_info"]

    if public:
        rows.extend(
            [
                [
                    "Country",
                    public.get("country", "n/a"),
                ],
                [
                    "Region",
                    public.get("region", "n/a"),
                ],
                [
                    "City",
                    public.get("city", "n/a"),
                ],
                [
                    "Postal code",
                    public.get("postal", "n/a"),
                ],
                [
                    "Continent",
                    public.get("continent", "n/a"),
                ],
                [
                    "Timezone",
                    (
                        public.get("timezone", {})
                        or {}
                    ).get(
                        "id",
                        "n/a",
                    ),
                ],
                [
                    "Latitude",
                    public.get("latitude", "n/a"),
                ],
                [
                    "Longitude",
                    public.get("longitude", "n/a"),
                ],
            ]
        )

        connection = (
            public.get("connection", {})
            or {}
        )

        rows.extend(
            [
                [
                    "ASN",
                    connection.get(
                        "asn",
                        "n/a",
                    ),
                ],
                [
                    "Organization",
                    connection.get(
                        "org",
                        "n/a",
                    ),
                ],
                [
                    "ISP",
                    connection.get(
                        "isp",
                        "n/a",
                    ),
                ],
                [
                    "Domain",
                    connection.get(
                        "domain",
                        "n/a",
                    ),
                ],
            ]
        )

    if rdns.get("hostname"):
        rows.insert(
            1,
            [
                "Reverse DNS",
                rdns["hostname"],
            ],
        )

    print_two_col(
        ["Field", "Value"],
        rows,
    )

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    if public:
        ok(
            "Public IP intelligence collected."
        )
    else:
        info(
            "Only local classification/reverse-DNS "
            "information was available."
        )

    info(
        "Geolocation is approximate and may identify "
        "the ISP/network location rather than the "
        "physical location of a person or device."
    )

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    prompt_export(
        result,
        f"iptrace_{ip.replace(':', '_')}",
    )

    wait_or_exit()
