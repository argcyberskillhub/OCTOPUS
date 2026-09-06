"""Centralized ANSI color and banner styling for OCTOPUS."""

from __future__ import annotations

import os
import sys

# Optional Windows ANSI support
try:
    from colorama import just_fix_windows_console

    just_fix_windows_console()
except Exception:
    pass


# ---------------------------------------------------------------------------
# ANSI COLORS
# ---------------------------------------------------------------------------

COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",

    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",

    "bred": "\033[91m",
    "bgreen": "\033[92m",
    "byellow": "\033[93m",
    "bblue": "\033[94m",
    "bmagenta": "\033[95m",
    "bcyan": "\033[96m",
    "bwhite": "\033[97m",

    "gray": "\033[90m",
}


# ---------------------------------------------------------------------------
# SHORT CONSTANTS
# ---------------------------------------------------------------------------

RESET = COLORS["reset"]
BOLD = COLORS["bold"]

RED = COLORS["red"]
GREEN = COLORS["green"]
YELLOW = COLORS["yellow"]
BLUE = COLORS["blue"]
MAGENTA = COLORS["magenta"]
CYAN = COLORS["cyan"]
WHITE = COLORS["white"]

BRED = COLORS["bred"]
BGREEN = COLORS["bgreen"]
BYELLOW = COLORS["byellow"]
BBLUE = COLORS["bblue"]
BMAGENTA = COLORS["bmagenta"]
BCYAN = COLORS["bcyan"]
BWHITE = COLORS["bwhite"]


# ---------------------------------------------------------------------------
# COLOR ENABLE / DISABLE
# ---------------------------------------------------------------------------

def _enabled() -> bool:
    """Return True when ANSI colors should be displayed."""
    if os.environ.get("NO_COLOR"):
        return False

    return sys.stdout.isatty()


# ---------------------------------------------------------------------------
# BASIC COLOR FUNCTION
# ---------------------------------------------------------------------------

def c(text: str, style: str = "reset") -> str:
    """Wrap text in an ANSI color/style when colors are enabled."""
    if not _enabled():
        return text

    colour = COLORS.get(style, COLORS["reset"])
    return f"{colour}{text}{COLORS['reset']}"


def color(text: str, colour: str = CYAN) -> str:
    """Compatibility helper for existing modules."""
    if not _enabled():
        return text

    return f"{colour}{text}{RESET}"


# ---------------------------------------------------------------------------
# BANNER STYLING
# ---------------------------------------------------------------------------

BANNER_COLORS = {
    "social": "bmagenta",
    "phone": "bcyan",
    "web": "bgreen",
    "webinfo": "bgreen",
    "web-info": "bgreen",
    "webtester": "bred",
    "web-tester": "bred",
    "network": "bblue",
    "network-info": "bblue",
    "iptrace": "byellow",
    "ip-trace": "byellow",
    "info": "bcyan",
}


def color_banner(text: str, style: str = "bcyan") -> str:
    """Apply one color to a complete ASCII banner."""
    return c(text, style)


def module_banner(text: str, module: str) -> str:
    """Color a module banner using its centralized project theme."""
    style = BANNER_COLORS.get(module.lower(), "bcyan")
    return c(text, style)


# ---------------------------------------------------------------------------
# APPLICATION STYLE
# ---------------------------------------------------------------------------

def banner_style() -> dict:
    """Common styles used across the OCTOPUS interface."""
    return {
        "title": "bcyan",
        "subtitle": "gray",
        "ok": "green",
        "warn": "yellow",
        "err": "red",
        "info": "cyan",
        "head": "magenta",
        "accent": "byellow",
    }
