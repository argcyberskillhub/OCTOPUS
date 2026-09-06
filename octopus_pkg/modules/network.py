"""
Network information and authorized TCP scanning module.

Registry functions:
    tcp_port_scan
    host_discovery
    dns_lookup
    reverse_dns
    whois_lookup
    banner_grab
    local_netinfo
    common_port_scan
    custom_range_scan

Use scanning functions only against hosts/networks you own or are
explicitly authorized to inspect.
"""

from __future__ import annotations
from ..core.colors import module_banner
NETWORK_BANNER = r"""
 _   _      _                      _        _         __
| \ | | ___| |___      _____  _ __| | __   (_)_ __  / _| ___
|  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ /   | | '_ '| |_ / _ \
| |\  |  __/ |_ \ V  V / (_) | |  |   <    | | | | |  _| |_| |
|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\   |_|_| |_| |  \___/

                         network-info
                  Coded by : argcyberskillhub

"""


def show_banner():
    print(module_banner(NETWORK_BANNER, "network"))

import ipaddress
import os
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from ..core.ui import (
    section,
    ok,
    info,
    warn,
    err,
    get_str,
    get_int,
    yes_no,
    spinner,
    wait_or_exit,
    print_two_col,
)
from ..core.export import prompt_export


# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------

MAX_WORKERS = 50
MAX_CUSTOM_PORTS = 1000
DEFAULT_TIMEOUT = 1.5

COMMON_PORTS = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-server",
    68: "DHCP-client",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-submit",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    3000: "HTTP-alt",
    3306: "MySQL",
    3389: "RDP",
    5000: "HTTP-alt",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-alt",
    8080: "HTTP-proxy-alt",
    8443: "HTTPS-alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


# --------------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------------

def _resolve_host(host: str) -> str:
    """Resolve a hostname to an IPv4/IPv6 address."""

    host = (host or "").strip()

    if not host:
        raise ValueError("Hostname/IP is required.")

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(
            f"Could not resolve '{host}': {exc}"
        ) from exc


def _parse_port(value: str) -> int:
    """Validate a TCP port."""

    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("Port must be an integer.")

    if not 1 <= port <= 65535:
        raise ValueError(
            "Port must be between 1 and 65535."
        )

    return port


def _tcp_check(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Perform a TCP connect check."""

    result = {
        "host": host,
        "port": port,
        "open": False,
        "latency_ms": None,
        "error": None,
    }

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.settimeout(timeout)

    import time

    started = time.perf_counter()

    try:
        code = sock.connect_ex(
            (host, port)
        )

        result["open"] = code == 0

    except socket.timeout:
        result["error"] = "timeout"

    except OSError as exc:
        result["error"] = str(exc)

    finally:
        sock.close()

    result["latency_ms"] = round(
        (time.perf_counter() - started) * 1000,
        2,
    )

    return result


def _scan_ports(
    host: str,
    ports: list[int],
    timeout: float,
    workers: int,
) -> list[dict[str, Any]]:
    """Bounded concurrent TCP port scan."""

    workers = max(
        50,
        min(workers, MAX_WORKERS),
    )

    results: list[dict[str, Any]] = []

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = {
            executor.submit(
                _tcp_check,
                host,
                port,
                timeout,
            ): port
            for port in ports
        }

        for future in as_completed(futures):
            try:
                results.append(
                    future.result()
                )
            except Exception as exc:
                results.append(
                    {
                        "host": host,
                        "port": futures[future],
                        "open": False,
                        "latency_ms": None,
                        "error": str(exc),
                    }
                )

    results.sort(
        key=lambda item: item["port"]
    )

    return results


def _print_open_ports(results: list[dict[str, Any]]) -> None:
    """Print only open TCP ports."""

    opened = [
        item
        for item in results
        if item.get("open")
    ]

    if not opened:
        info("No open TCP ports found in the selected range.")
        return

    ok(
        f"Found {len(opened)} open TCP port(s)."
    )

    rows = []

    for item in opened:
        port = item["port"]

        rows.append(
            [
                port,
                COMMON_PORTS.get(
                    port,
                    "unknown",
                ),
                f"{item['latency_ms']} ms",
            ]
        )

    print_two_col(
        ["Port", "Likely service", "Latency"],
        rows,
    )


# --------------------------------------------------------------------------
# 1. TCP port scanner
# --------------------------------------------------------------------------

def tcp_port_scan():
    section("TCP port scanner")

    target = get_str(
        "Target hostname/IP"
    ) or ""

    if not target:
        return

    try:
        host = _resolve_host(target)

        start_port = _parse_port(
            get_str(
                "Start port",
                default="1",
            )
        )

        end_port = _parse_port(
            get_str(
                "End port",
                default="1024",
            )
        )

    except ValueError as exc:
        err(str(exc))
        wait_or_exit()
        return

    if start_port > end_port:
        err("Start port cannot be greater than end port.")
        wait_or_exit()
        return

    count = end_port - start_port + 1

    if count > MAX_CUSTOM_PORTS:
        err(
            f"Range is too large. Maximum is "
            f"{MAX_CUSTOM_PORTS} ports per scan."
        )
        wait_or_exit()
        return

    timeout = get_int(
        "Timeout (seconds)",
        2,
    )

    workers = get_int(
        "Concurrent workers",
        8,
    )

    if timeout < 1:
        timeout = 1

    workers = max(
        1,
        min(workers, MAX_WORKERS),
    )

    ports = list(
        range(
            start_port,
            end_port + 1,
        )
    )

    info(f"Target: {target} -> {host}")
    info(f"Ports : {start_port}-{end_port}")

    warn(
        "Only scan systems you own or are authorized to test."
    )

    with spinner():
        results = _scan_ports(
            host,
            ports,
            float(timeout),
            workers,
        )

    _print_open_ports(results)

    prompt_export(
        {
            "target": target,
            "resolved_ip": host,
            "start_port": start_port,
            "end_port": end_port,
            "results": results,
        },
        f"tcp_scan_{host}",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 2. Host discovery
# --------------------------------------------------------------------------

def host_discovery():
    section("Host discovery")

    target = get_str(
        "Network/CIDR or single host"
    ) or ""

    if not target:
        return

    try:
        network = ipaddress.ip_network(
            target,
            strict=False,
        )
    except ValueError:
        try:
            host = _resolve_host(target)

            result = {
                "target": target,
                "host": host,
                "reachable": False,
            }

            check = _tcp_check(
                host,
                80,
                1.0,
            )

            if check["open"]:
                result["reachable"] = True
                ok(
                    f"{target} responded on TCP/80."
                )
            else:
                check = _tcp_check(
                    host,
                    443,
                    1.0,
                )

                if check["open"]:
                    result["reachable"] = True
                    ok(
                        f"{target} responded on TCP/443."
                    )
                else:
                    info(
                        "No response on TCP/80 or TCP/443. "
                        "Host may still be reachable."
                    )

            prompt_export(
                result,
                f"host_{host}",
            )

        except ValueError as exc:
            err(str(exc))

        wait_or_exit()
        return

    # Keep network discovery bounded.
    hosts = list(network.hosts())

    if len(hosts) > 254:
        err(
            "Network is too large for this bounded discovery "
            "function. Use a /24 or smaller."
        )
        wait_or_exit()
        return

    workers = get_int(
        "Concurrent workers",
        16,
    )

    workers = max(
        1,
        min(workers, MAX_WORKERS),
    )

    results = []

    info(
        f"Checking {len(hosts)} host(s) in {network}."
    )

    def check_host(ip):
        ip_str = str(ip)

        for port in (80, 443, 22):
            result = _tcp_check(
                ip_str,
                port,
                0.8,
            )

            if result["open"]:
                return {
                    "ip": ip_str,
                    "reachable": True,
                    "port": port,
                }

        return {
            "ip": ip_str,
            "reachable": False,
            "port": None,
        }

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = [
            executor.submit(
                check_host,
                ip,
            )
            for ip in hosts
        ]

        with spinner():
            for future in as_completed(futures):
                try:
                    results.append(
                        future.result()
                    )
                except Exception:
                    pass

    results.sort(
        key=lambda item: ipaddress.ip_address(
            item["ip"]
        )
    )

    alive = [
        item
        for item in results
        if item["reachable"]
    ]

    if alive:
        ok(
            f"Found {len(alive)} responsive host(s)."
        )

        print_two_col(
            ["IP", "Observed TCP port"],
            [
                [
                    item["ip"],
                    item["port"],
                ]
                for item in alive
            ],
        )
    else:
        info(
            "No hosts responded on the tested TCP ports."
        )

    prompt_export(
        {
            "network": str(network),
            "results": results,
        },
        "host_discovery",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 3. DNS lookup
# --------------------------------------------------------------------------

def dns_lookup():
    section("DNS lookup")

    host = get_str(
        "Hostname/domain"
    ) or ""

    if not host:
        return

    host = host.strip().rstrip(".")

    record_types = [
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
    ]

    result: dict[str, Any] = {
        "hostname": host
    }

    # Use dnspython when installed.
    try:
        import dns.resolver

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(
                    host,
                    record_type,
                )

                values = [
                    str(answer)
                    for answer in answers
                ]

                result[record_type] = values

                if values:
                    ok(
                        f"{record_type:<5}: "
                        + ", ".join(values)
                    )
                else:
                    info(
                        f"{record_type:<5}: none"
                    )

            except Exception:
                result[record_type] = []

                info(
                    f"{record_type:<5}: none"
                )

    except ImportError:
        warn(
            "dnspython is not installed; using standard-library "
            "A/AAAA resolution."
        )

        addresses = set()

        try:
            for item in socket.getaddrinfo(
                host,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            ):
                addresses.add(
                    item[4][0]
                )
        except socket.gaierror as exc:
            err(
                f"DNS resolution failed: {exc}"
            )

        result["A/AAAA"] = sorted(
            addresses
        )

        for address in sorted(addresses):
            ok(address)

    prompt_export(
        result,
        f"dns_{host}",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 4. Reverse DNS
# --------------------------------------------------------------------------

def reverse_dns():
    section("Reverse DNS lookup")

    value = get_str(
        "IP address"
    ) or ""

    if not value:
        return

    try:
        ip = ipaddress.ip_address(
            value
        )
    except ValueError:
        err("Invalid IP address.")
        wait_or_exit()
        return

    result = {
        "ip": str(ip),
        "hostname": None,
        "aliases": [],
    }

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(
            str(ip)
        )

        result["hostname"] = hostname
        result["aliases"] = aliases
        result["addresses"] = addresses

        ok(
            f"PTR hostname: {hostname}"
        )

        if aliases:
            info(
                "Aliases: "
                + ", ".join(aliases)
            )

    except socket.herror:
        info(
            "No PTR hostname was returned."
        )

    except Exception as exc:
        err(
            f"Reverse lookup failed: {exc}"
        )

    prompt_export(
        result,
        f"reverse_dns_{ip}",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 5. WHOIS
# --------------------------------------------------------------------------

def whois_lookup():
    section("WHOIS lookup")

    target = get_str(
        "Domain/IP"
    ) or ""

    if not target:
        return

    # Prefer python-whois if available.
    try:
        import whois as whois_module

        info(
            "Querying public WHOIS data..."
        )

        data = whois_module.whois(
            target
        )

        if hasattr(data, "items"):
            result = dict(data)
        else:
            result = {
                "result": str(data)
            }

        displayed = []

        for key, value in result.items():
            if value in (None, "", [], {}):
                continue

            if isinstance(value, (list, tuple)):
                value = ", ".join(
                    str(item)
                    for item in value
                )

            displayed.append(
                [
                    str(key),
                    str(value),
                ]
            )

        if displayed:
            print_two_col(
                ["Field", "Value"],
                displayed,
            )

            ok(
                "WHOIS query completed."
            )
        else:
            info(
                "WHOIS returned no displayable fields."
            )

        prompt_export(
            result,
            f"whois_{target}",
        )

    except ImportError:
        warn(
            "python-whois is not installed."
        )
        info(
            "Install with: pip install python-whois"
        )

    except Exception as exc:
        err(
            f"WHOIS lookup failed: {exc}"
        )

    wait_or_exit()


# --------------------------------------------------------------------------
# 6. Banner grabbing
# --------------------------------------------------------------------------

def banner_grab():
    section("TCP banner grabbing")

    target = get_str(
        "Target hostname/IP"
    ) or ""

    if not target:
        return

    try:
        host = _resolve_host(target)

        port = _parse_port(
            get_str(
                "Port",
                default="80",
            )
        )

    except ValueError as exc:
        err(str(exc))
        wait_or_exit()
        return

    timeout = get_int(
        "Timeout (seconds)",
        5,
    )

    timeout = max(
        1,
        timeout,
    )

    result = {
        "target": target,
        "resolved_ip": host,
        "port": port,
        "connected": False,
        "banner": "",
        "error": None,
    }

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.settimeout(
        float(timeout)
    )

    try:
        sock.connect(
            (host, port)
        )

        result["connected"] = True

        # Send a minimal HTTP request for common HTTP ports.
        if port in (
            80,
            3000,
            5000,
            8000,
            8080,
            8888,
        ):
            payload = (
                f"HEAD / HTTP/1.0\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: Octopus/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode(
                "ascii",
                "ignore",
            )

            sock.sendall(payload)

        try:
            data = sock.recv(4096)

            banner = data.decode(
                "utf-8",
                "replace",
            ).strip()

            result["banner"] = banner[:4000]

        except socket.timeout:
            result["banner"] = ""

        if result["banner"]:
            ok("Received public service response:")
            print(result["banner"])

        else:
            info(
                "TCP connection succeeded, but no banner "
                "was returned."
            )

    except Exception as exc:
        result["error"] = str(exc)
        err(
            f"Connection failed: {exc}"
        )

    finally:
        sock.close()

    prompt_export(
        result,
        f"banner_{host}_{port}",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 7. Local network information
# --------------------------------------------------------------------------

def local_netinfo():
    section("Local network information")

    result: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "interfaces": [],
    }

    info(
        f"Hostname : {result['hostname']}"
    )
    info(
        f"FQDN     : {result['fqdn']}"
    )
    info(
        f"Platform : {result['platform']}"
    )

    # Preferred interface information.
    try:
        import psutil

        for interface, addresses in psutil.net_if_addrs().items():
            for address in addresses:
                family = str(address.family)

                if family not in (
                    "AddressFamily.AF_INET",
                    "AddressFamily.AF_INET6",
                ):
                    continue

                result["interfaces"].append(
                    {
                        "interface": interface,
                        "family": family,
                        "address": address.address,
                        "netmask": address.netmask,
                        "broadcast": address.broadcast,
                    }
                )

    except ImportError:
        warn(
            "psutil not installed; using standard-library "
            "interface information."
        )

        try:
            hostname = socket.gethostname()

            addresses = set()

            for item in socket.getaddrinfo(
                hostname,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            ):
                addresses.add(
                    item[4][0]
                )

            for address in sorted(addresses):
                result["interfaces"].append(
                    {
                        "interface": "default",
                        "family": "IP",
                        "address": address,
                        "netmask": None,
                        "broadcast": None,
                    }
                )

        except Exception as exc:
            result["error"] = str(exc)

    except Exception as exc:
        result["error"] = str(exc)

    if result["interfaces"]:
        print_two_col(
            ["Interface", "Family", "Address", "Netmask"],
            [
                [
                    item["interface"],
                    item["family"],
                    item["address"],
                    item["netmask"] or "n/a",
                ]
                for item in result["interfaces"]
            ],
        )
    else:
        info(
            "No interface addresses were discovered."
        )

    prompt_export(
        result,
        "local_netinfo",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 8. Common-port scan
# --------------------------------------------------------------------------

def common_port_scan():
    section("Common-port scan")

    target = get_str(
        "Target hostname/IP"
    ) or ""

    if not target:
        return

    try:
        host = _resolve_host(target)
    except ValueError as exc:
        err(str(exc))
        wait_or_exit()
        return

    timeout = get_int(
        "Timeout (seconds)",
        2,
    )

    workers = get_int(
        "Concurrent workers",
        16,
    )

    timeout = max(
        1,
        timeout,
    )

    workers = max(
        1,
        min(workers, MAX_WORKERS),
    )

    ports = sorted(
        COMMON_PORTS.keys()
    )

    info(
        f"Target: {target} -> {host}"
    )

    warn(
        "Only scan systems you own or are authorized to test."
    )

    with spinner():
        results = _scan_ports(
            host,
            ports,
            float(timeout),
            workers,
        )

    _print_open_ports(
        results
    )

    prompt_export(
        {
            "target": target,
            "resolved_ip": host,
            "ports": ports,
            "results": results,
        },
        f"common_ports_{host}",
    )

    wait_or_exit()


# --------------------------------------------------------------------------
# 9. Custom port range scan
# --------------------------------------------------------------------------

def custom_range_scan():
    section("Custom-port range scan")

    target = get_str(
        "Target hostname/IP"
    ) or ""

    if not target:
        return

    try:
        host = _resolve_host(target)

        start_port = _parse_port(
            get_str(
                "Start port"
            )
        )

        end_port = _parse_port(
            get_str(
                "End port"
            )
        )

    except ValueError as exc:
        err(str(exc))
        wait_or_exit()
        return

    if start_port > end_port:
        err(
            "Start port cannot be greater than end port."
        )
        wait_or_exit()
        return

    count = end_port - start_port + 1

    if count > MAX_CUSTOM_PORTS:
        err(
            f"Maximum {MAX_CUSTOM_PORTS} ports per scan."
        )
        wait_or_exit()
        return

    timeout = get_int(
        "Timeout (seconds)",
        2,
    )

    workers = get_int(
        "Concurrent workers",
        8,
    )

    timeout = max(
        1,
        timeout,
    )

    workers = max(
        1,
        min(workers, MAX_WORKERS),
    )

    ports = list(
        range(
            start_port,
            end_port + 1,
        )
    )

    info(
        f"Target: {target} -> {host}"
    )
    info(
        f"Range : {start_port}-{end_port}"
    )

    warn(
        "Only scan systems you own or are authorized to test."
    )

    with spinner():
        results = _scan_ports(
            host,
            ports,
            float(timeout),
            workers,
        )

    _print_open_ports(
        results
    )

    prompt_export(
        {
            "target": target,
            "resolved_ip": host,
            "start_port": start_port,
            "end_port": end_port,
            "results": results,
        },
        f"custom_scan_{host}",
    )

    wait_or_exit()
