"""Export scan/collection results to TXT, JSON or CSV."""

from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime
from typing import Any

from .ui import info, ok, warn, yes_no, get_str


OUT_DIR = "octopus_out"


def ensure_outdir() -> str:
    """Create and return the output directory."""
    os.makedirs(OUT_DIR, exist_ok=True)
    return OUT_DIR


def _now() -> str:
    """Return a filesystem-friendly timestamp."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _safe_filename(name: str) -> str:
    """Remove unsafe filesystem characters from a result filename."""
    name = str(name or "").strip()

    if not name:
        name = "result"

    # Keep normal letters, numbers, _, -, and .
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)

    # Avoid hidden/odd filenames.
    name = name.strip("._-") or "result"

    return name


def export(data: Any, name: str, fmt: str = "json") -> str:
    """
    Export data to TXT, JSON or CSV.

    CSV works best with a list of dictionaries.
    For other data types, JSON/TXT is recommended.
    """
    out = ensure_outdir()

    fmt = (fmt or "json").lower().strip()
    if fmt not in ("json", "txt", "csv"):
        fmt = "json"

    safe_name = _safe_filename(name)
    fname = f"{safe_name}_{_now()}.{fmt}"
    path = os.path.join(out, fname)

    if fmt == "txt":
        with open(path, "w", encoding="utf-8") as f:
            f.write(_as_text(data))

    elif fmt == "csv":
        _write_csv(data, path)

    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                data,
                f,
                indent=2,
                ensure_ascii=False,
                default=str,
            )

    return path


def _write_csv(data: Any, path: str) -> None:
    """Write CSV safely for common result structures."""

    with open(path, "w", newline="", encoding="utf-8") as f:

        # Normal list[dict] result.
        if isinstance(data, list) and data and all(
            isinstance(item, dict) for item in data
        ):
            fieldnames = []

            # Preserve the order in which keys first appear.
            for item in data:
                for key in item.keys():
                    if key not in fieldnames:
                        fieldnames.append(key)

            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
                extrasaction="ignore",
            )
            writer.writeheader()

            for item in data:
                writer.writerow(
                    {
                        key: _csv_value(item.get(key))
                        for key in fieldnames
                    }
                )
            return

        # Single dictionary.
        if isinstance(data, dict):
            keys = list(data.keys())

            writer = csv.writer(f)
            writer.writerow(["Field", "Value"])

            for key in keys:
                writer.writerow(
                    [
                        key,
                        _csv_value(data.get(key)),
                    ]
                )
            return

        # Fallback for strings/scalars/lists.
        f.write(_as_text(data))


def _csv_value(value: Any) -> str:
    """Convert nested values into readable CSV cells."""
    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple, set)):
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                default=str,
            )
        except Exception:
            return str(value)

    return str(value)


def _as_text(data: Any, indent: int = 0) -> str:
    """Recursively format nested structures as readable text."""

    pad = "  " * indent

    if isinstance(data, dict):
        if not data:
            return f"{pad}(empty)"

        lines = []

        for key, value in data.items():
            if isinstance(value, (dict, list, tuple, set)):
                lines.append(f"{pad}{key}:")
                lines.append(_as_text(value, indent + 1))
            else:
                lines.append(f"{pad}{key}: {value}")

        return "\n".join(lines)

    if isinstance(data, (list, tuple, set)):
        if not data:
            return f"{pad}(empty)"

        lines = []

        for item in data:
            if isinstance(item, (dict, list, tuple, set)):
                lines.append(_as_text(item, indent))
            else:
                lines.append(f"{pad}- {item}")

        return "\n".join(lines)

    return f"{pad}{data}"


def prompt_export(data: Any, default_name: str) -> None:
    """
    Ask the user whether to save results.

    Supported formats:
      - json
      - txt
      - csv
    """

    if data is None:
        info("Nothing to export.")
        return

    if not yes_no(
        "Save results to file (TXT/JSON/CSV)?",
        default=True,
    ):
        return

    name = (
        get_str(
            "Result filename (no extension)",
            default=_safe_filename(default_name),
        )
        or _safe_filename(default_name)
    )

    choice = (
        get_str(
            "Format? [json/txt/csv]",
            default="json",
        )
        or "json"
    ).lower().strip()

    if choice not in ("json", "txt", "csv"):
        warn("Unknown format, using JSON.")
        choice = "json"

    try:
        path = export(data, name, choice)
        ok(f"Saved -> {path}")
    except OSError as e:
        warn(f"Could not save result: {e}")
    except Exception as e:
        warn(f"Export failed: {e}")
