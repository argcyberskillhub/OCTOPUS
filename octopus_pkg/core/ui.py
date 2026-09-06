"""Shared UI primitives: banner, menus, prompts, progress, screen, Ctrl+C."""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from typing import Iterable, Optional

import pyfiglet  # kept for compatibility with existing project imports

from . import colors as col
from .. import OCTOPUS_VERSION, OCTO_BANNER, OCTOPUS_ART


# --------------------------------------------------------------------------
# Ctrl+C handling
# --------------------------------------------------------------------------

_INTERRUPTED = threading.Event()


def _handle_sigint(signum, frame):
    """Handle the first Ctrl+C gracefully."""
    _INTERRUPTED.set()

    # Restore default SIGINT behavior so a second Ctrl+C can terminate.
    try:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    except Exception:
        pass

    sys.stdout.write("\n")
    sys.stdout.flush()


def install_interrupt_handler() -> None:
    """Install Ctrl+C handler when running on the main thread."""
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, _handle_sigint)


def interrupted() -> bool:
    return _INTERRUPTED.is_set()


def reset_interrupt() -> None:
    _INTERRUPTED.clear()


# --------------------------------------------------------------------------
# Screen & printing
# --------------------------------------------------------------------------

def clear_screen() -> None:
    """Clear terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def _rule(char: str = "=", n: int = 68) -> str:
    return col.c(char * n, "g")


def hr(char: str = "-", n: int = 60) -> None:
    print(_rule(char, n))


def section(title: str) -> None:
    print()
    print(_rule())
    print(col.c(f"  {title}", "head"))
    print(_rule())


def ok(msg: str) -> None:
    print(col.c(f"[+] {msg}", "green"))


def info(msg: str) -> None:
    print(col.c(f"[*] {msg}", "cyan"))


def warn(msg: str) -> None:
    print(col.c(f"[!] {msg}", "yellow"))


def err(msg: str) -> None:
    print(col.c(f"[x] {msg}", "red"))


# --------------------------------------------------------------------------
# Styled Octopus CLI banner
# --------------------------------------------------------------------------
def print_banner() -> None:
    clear_screen()

    banner_lines = [
        line for line in OCTO_BANNER.strip("\n").splitlines()
        if line.strip()
    ]

    octopus_lines = [
        line for line in OCTOPUS_ART.strip("\n").splitlines()
        if line.strip()
    ]

    if not banner_lines:
        banner_lines = ["OCTOPUS"]

    if not octopus_lines:
        octopus_lines = [""]

    height = max(len(banner_lines), len(octopus_lines))
    left_width = max(len(line) for line in banner_lines) + 5

    for i in range(height):
        left = banner_lines[i] if i < len(banner_lines) else ""
        right = octopus_lines[i] if i < len(octopus_lines) else ""

        print(
            col.c(left.ljust(left_width), "bcyan")
            + col.c(right, "cyan")
        )

    print(
        col.c(f"v{OCTOPUS_VERSION}", "dim")
        + " "
        + col.c(
            "Modular Cybersecurity & Authorized Testing Toolkit",
            "g",
        )
    )



# --------------------------------------------------------------------------
# Menus
# --------------------------------------------------------------------------

def menu(
    title: str,
    entries: list,
    prompt: str = "Choice",
    back_text: str = "Back",
) -> str:
    """
    Display a menu.

    entries:
        [(key, label), ...]

    Returns the selected key as a string.
    """

    print(col.c(f"\n== {title} ==", "head"))

    for key, label in entries:
        if str(key) == "0":
            print(col.c(f"   [0] {back_text}", "g"))
        elif str(key) in ("99", "b"):
            print(col.c(f"   [{key}] {label}", "g"))
        else:
            print(col.c(f"   [{key}] {label}", "white"))

    try:
        val = input(
            col.c(
                f"\n  {prompt} > ",
                "byellow",
            )
        ).strip()

    except (EOFError, KeyboardInterrupt):
        print()
        return "0"

    return str(val)


# --------------------------------------------------------------------------
# Input helpers
# --------------------------------------------------------------------------

def get_int(
    prompt: str,
    default: Optional[int] = None,
) -> int:
    """Read an integer, optionally using a default value."""

    while True:
        try:
            raw = input(
                col.c(
                    (
                        f"  {prompt} [{default}] > "
                        if default is not None
                        else f"  {prompt} > "
                    ),
                    "byellow",
                )
            ).strip()

        except (EOFError, KeyboardInterrupt):
            print()
            return default if default is not None else 0

        if not raw and default is not None:
            return default

        try:
            return int(raw)

        except ValueError:
            err("Please enter a valid integer.")


def get_str(
    prompt: str,
    default: Optional[str] = None,
) -> str:
    """Read a string, optionally using a default value."""

    try:
        raw = input(
            col.c(
                f"  {prompt}"
                + (f" [{default}]" if default is not None else "")
                + " > ",
                "byellow",
            )
        ).strip()

    except (EOFError, KeyboardInterrupt):
        print()
        return default or ""

    if not raw and default is not None:
        return default

    return raw


def yes_no(
    prompt: str,
    default: bool = False,
) -> bool:
    """Read a yes/no answer."""

    dflt = "Y/n" if default else "y/N"

    try:
        raw = input(
            col.c(
                f"  {prompt} ({dflt}) > ",
                "byellow",
            )
        ).strip().lower()

    except (EOFError, KeyboardInterrupt):
        print()
        return default

    if not raw:
        return default

    return raw in ("y", "yes")


# --------------------------------------------------------------------------
# Progress indicators
# --------------------------------------------------------------------------

def _spin(stop: threading.Event) -> None:
    glyphs = "|/-\\🐙"
    idx = 0

    while not stop.is_set():
        spin_char = glyphs[idx % len(glyphs)]

        sys.stdout.write(
            "\r  "
            + col.c(spin_char, "bcyan")
            + "  working..."
        )
        sys.stdout.flush()

        idx += 1
        time.sleep(0.10)

    sys.stdout.write("\r" + " " * 40 + "\r")
    sys.stdout.flush()


class spinner:
    """Context manager for a lightweight CLI spinner."""

    def __enter__(self):
        self._event = threading.Event()

        self._t = threading.Thread(
            target=_spin,
            args=(self._event,),
            daemon=True,
        )

        self._t.start()

        return self

    def __exit__(self, *exc):
        self._event.set()
        self._t.join(timeout=0.5)


# --------------------------------------------------------------------------
# Output printing helpers
# --------------------------------------------------------------------------

def print_two_col(
    headers: Iterable[str],
    rows: Iterable[Iterable],
    widths=None,
) -> None:
    """Print simple two/multi-column tabular output."""

    headers = list(headers)
    rows = [list(row) for row in rows]

    if not headers:
        return

    if widths is None:
        widths = []

        for i, header in enumerate(headers):
            values = [
                len(str(row[i]))
                for row in rows
                if i < len(row)
            ]

            widths.append(
                max(
                    [len(str(header))] + values
                )
            )

    # Header
    header_cells = []

    for i, header in enumerate(headers):
        width = widths[i] if i < len(widths) else len(str(header))

        header_cells.append(
            str(header).ljust(width)
        )

    print(
        "  "
        + col.c(
            "  ".join(header_cells),
            "accent",
        )
    )

    # Separator
    print(
        "  "
        + "  ".join(
            "-" * (
                widths[i]
                if i < len(widths)
                else len(str(headers[i]))
            )
            for i in range(len(headers))
        )
    )

    # Rows
    for row in rows:
        values = []

        for i in range(len(headers)):
            cell = row[i] if i < len(row) else ""
            width = widths[i] if i < len(widths) else len(str(cell))

            values.append(
                str(cell).ljust(width)
            )

        print("  " + "  ".join(values))


# --------------------------------------------------------------------------
# Pause / return
# --------------------------------------------------------------------------

def wait_or_exit() -> None:
    """Pause after a module finishes so the user can read the output."""

    try:
        input(
            col.c(
                "\n  Press Enter to return to menu...",
                "byellow",
            )
        )

    except (EOFError, KeyboardInterrupt):
        print()
