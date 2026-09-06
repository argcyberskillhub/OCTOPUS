"""Modular submenu registry.

To add a new tool/module:
  1. Add your module file under modules/ with a function handle(sub=False) -> None
  2. Register its (function, title) here so the menu is generated automatically.
"""
from __future__ import annotations
from typing import Callable, List, Tuple

Handler = Callable[..., None]
MenuRow = Tuple[str, str, Handler, bool]   # key, label, handler, requires_clear

def build_social_menu() -> List[MenuRow]:
    from .modules.social import (
        show_banner,
        username_availability,
        profile_discovery,
        platform_search,
        email_domain_corr,
        website_lookup,
        full_enum,
    )

    show_banner()

    return [
        ("1", "Username availability checker", username_availability, False),
        ("2", "Public-profile discovery", profile_discovery, False),
        ("3", "Social-platform search", platform_search, False),
        ("4", "Public email/domain correlation", email_domain_corr, False),
        ("5", "Public website/profile lookup", website_lookup, False),
        ("6", "Username enumeration (all supported platforms)", full_enum, False),
        ("0", "Back to main menu", None, True),
    ]



def build_network_menu() -> List[MenuRow]:
    from .modules.network import (show_banner, tcp_port_scan, host_discovery, dns_lookup,
                                  reverse_dns, whois_lookup, banner_grab,
                                  local_netinfo, common_port_scan, custom_range_scan)
    show_banner()

    return [
        ("1", "TCP port scanner", tcp_port_scan, False),
        ("2", "Host discovery", host_discovery, False),
        ("3", "DNS lookup", dns_lookup, False),
        ("4", "Reverse DNS lookup", reverse_dns, False),
        ("5", "WHOIS lookup", whois_lookup, False),
        ("6", "Banner grabbing", banner_grab, False),
        ("7", "Local network information", local_netinfo, False),
        ("8", "Common-port scan", common_port_scan, False),
        ("9", "Custom-port range scan", custom_range_scan, False),
        ("0", "Back to main menu", None, True),
    ]


def build_loadtest_menu() -> List[MenuRow]:
    from .modules.loadtest import http_rate_test, show_banner

    show_banner()

    return [
        ("1", "HTTP request-rate test (authorized)", http_rate_test, False),
        ("0", "Back to main menu", None, True),
    ]


def build_phone_menu() -> List[MenuRow]:
    from .modules.phone import (
        show_banner,
        phone_lookup,
        phone_validate,
        phone_region,
    )

    show_banner()

    return [
        ("1", "Phone number detailed info", phone_lookup, False),
        ("2", "Basic validation & formatting", phone_validate, False),
        ("3", "Country / region / timezone inference", phone_region, False),
        ("0", "Back to main menu", None, True),
    ]



def build_web_menu() -> List[MenuRow]:
    from .modules.webinfo import (
        show_banner,
        http_headers,
        tls_cert,
        dns_records,
        whoisq,
        robots_check,
        security_headers,
        tech_detect,
        http_status,
        redirect_analysis,
        cookie_inspect,
        subdomain_discover,
        url_info,
        miscon_check,
    )

    show_banner()

    return [
        ("1", "HTTP headers", http_headers, False),
        ("2", "TLS/SSL certificate info", tls_cert, False),
        ("3", "DNS records", dns_records, False),
        ("4", "WHOIS info", whoisq, False),
        ("5", "robots.txt checker", robots_check, False),
        ("6", "Security-header checker", security_headers, False),
        ("7", "Technology / framework detection", tech_detect, False),
        ("8", "HTTP status checker", http_status, False),
        ("9", "Redirect analysis", redirect_analysis, False),
        ("10", "Cookie / security-flag inspection", cookie_inspect, False),
        ("11", "Subdomain discovery (passive/public)", subdomain_discover, False),
        ("12", "URL / domain info", url_info, False),
        ("13", "Basic web misconfiguration checks", miscon_check, False),
        ("14", "sitemap.xml checker", robots_check_helper_sitemap, False),
        ("0", "Back to main menu", None, True),
    ]



def robots_check_helper_sitemap():
    from .modules.webinfo import sitemap_check
    sitemap_check()


def build_iptrace_menu() -> List[MenuRow]:
    from .modules.iptrace import ip_trace, show_banner

    show_banner()

    return [
        ("1", "IP address tracer / information", ip_trace, False),
        ("0", "Back to main menu", None, True),
    ]

