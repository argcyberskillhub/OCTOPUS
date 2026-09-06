#!/usr/bin/env python3
"""OCTOPUS - OCTOPUS modular CLI entry point.

Run:  python octopus.py
"""
from __future__ import annotations
import sys

from octopus_pkg.core import ui
from octopus_pkg.core.colors import c
from octopus_pkg import OCTOPUS_VERSION
from octopus_pkg.registry import (build_social_menu, build_network_menu,
                                  build_loadtest_menu, build_phone_menu,
                                  build_web_menu, build_iptrace_menu)


def _render_menu(title, rows):
    """Rows: list of (key,label,handler,clear_flag)."""
    entries = [(k, lbl) for (k, lbl, h, clr) in rows]
    while True:
        choice = ui.menu(title, entries, back_text="Exit to main")
        if choice == "0":
            return
        for (k, lbl, h, clr) in rows:
            if choice == k and h is not None:
                try:
                    if clr:
                        ui.clear_screen()
                    h()
                except KeyboardInterrupt:
                    ui.info("Operation cancelled (Ctrl+C).")
                except Exception as e:
                    ui.err(f"Unexpected error: {e}")
                finally:
                    ui.clear_screen()
                break
        else:
            if choice not in (str(x[0]) for x in rows):
                ui.warn("Invalid choice.")
                ui.wait_or_exit()


def main() -> int:
    ui.install_interrupt_handler()

    while True:
        ui.clear_screen()
        ui.print_banner()

        entries = [
            ("1", "Social/OSINT utilities"),
            ("2", "Network / security testing"),
            ("3", "Load & stress testing (authorized)"),
            ("4", "Phone number information"),
            ("5", "Web information / security"),
            ("6", "IP Tracer / Network Intelligence"),
            ("0", "Exit"),
        ]

        choice = ui.menu(
            "OCTOPUS",
            entries,
            back_text="Quit"
        )

        if choice == "1":
            _render_menu(
                "Social Information",
                build_social_menu()
            )



        elif choice == "2":
            _render_menu(
                "Network / Security Testing",
                build_network_menu()
            )

        elif choice == "3":
            _render_menu(
                "Load & Stress Testing",
                build_loadtest_menu()
            )

        elif choice == "4":
            _render_menu(
                "Phone Information",
                build_phone_menu()
            )

        elif choice == "5":
            _render_menu(
                "Web Information",
                build_web_menu()
            )

        elif choice == "6":
            _render_menu(
                "IP Tracer / Network Intelligence",
                build_iptrace_menu()
            )


        elif choice == "0" or choice == "":
            print(
                c(
                    "Thanks for using OCTOPUS. "
                    "Stay authorized, stay safe.",
                    "g"
                )
            )
            return 0

        else:
            ui.warn("Invalid option.")
            ui.wait_or_exit()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting.")
        sys.exit(130)
