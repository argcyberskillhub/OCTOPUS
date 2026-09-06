"""
Phone information module.

Registry functions:
    phone_lookup
    phone_validate
    phone_region

This module performs basic parsing, validation, formatting, and
country/region inference using public numbering-plan metadata.

It does NOT attempt to identify a private person, carrier account,
live location, or subscriber records.
"""

from __future__ import annotations
from ..core.colors import module_banner
PHONE_BANNER = r"""
   _____  _                             __    __
  |  __ \| |                            \ \  / /
  | |__) | |__   ___  _ __   ___         \ \/ /
  |  ___/| '_ \ / _ \| '_ \ / _ \  ____   |__|
  | |    | | | | (_) | | | |  __/ |____| / /\ \
  |_|    |_| |_|\___/|_| |_|\___|       /_/  \_\

             phone-x Coded by: argcyberskillhub


       Phone Number / OSINT UTILITIES
"""


def show_banner():
    print(module_banner(PHONE_BANNER, "phone"))


from typing import Any

from ..core.ui import (
    section,
    ok,
    info,
    warn,
    err,
    get_str,
    wait_or_exit,
    print_two_col,
)
from ..core.export import prompt_export


# --------------------------------------------------------------------------
# Dependency
# --------------------------------------------------------------------------

try:
    import phonenumbers
    from phonenumbers import carrier
    from phonenumbers import geocoder
    from phonenumbers import timezone

    PHONE_AVAILABLE = True

except ImportError:
    phonenumbers = None
    carrier = None
    geocoder = None
    timezone = None

    PHONE_AVAILABLE = False


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _require_library() -> bool:
    """Check whether python-phonenumbers is available."""

    if PHONE_AVAILABLE:
        return True

    err(
        "Phone support requires the 'phonenumbers' package."
    )
    info(
        "Install with: pip install phonenumbers"
    )
    return False


def _parse_number(
    value: str,
    region: str | None = None,
):
    """
    Parse a phone number.

    Region should be an ISO-3166 alpha-2 code such as:
        IN
        US
        GB
    """

    value = (value or "").strip()

    if not value:
        raise ValueError("Phone number is required.")

    region = (region or "").strip().upper() or None

    # International numbers beginning with + don't need a region.
    if value.startswith("+"):
        region = None

    try:
        return phonenumbers.parse(
            value,
            region,
        )
    except phonenumbers.NumberParseException as exc:
        raise ValueError(
            f"Could not parse number: {exc}"
        ) from exc


def _number_info(
    number,
    include_carrier: bool = True,
) -> dict[str, Any]:
    """Build a structured public numbering-plan result."""

    result: dict[str, Any] = {}

    result["input"] = phonenumbers.format_number(
        number,
        phonenumbers.PhoneNumberFormat.E164,
    )

    result["international"] = phonenumbers.format_number(
        number,
        phonenumbers.PhoneNumberFormat.INTERNATIONAL,
    )

    result["national"] = phonenumbers.format_number(
        number,
        phonenumbers.PhoneNumberFormat.NATIONAL,
    )

    result["possible"] = phonenumbers.is_possible_number(
        number
    )

    result["valid"] = phonenumbers.is_valid_number(
        number
    )

    result["number_type"] = str(
        phonenumbers.number_type(number)
    )

    result["country_code"] = number.country_code

    result["national_number"] = number.national_number

    try:
        region_code = phonenumbers.region_code_for_number(
            number
        )
    except Exception:
        region_code = None

    result["region_code"] = region_code

    try:
        country_name = geocoder.country_name_for_number(
            number,
            "en",
        )
    except Exception:
        country_name = ""

    result["country"] = country_name or None

    try:
        location = geocoder.description_for_number(
            number,
            "en",
        )
    except Exception:
        location = ""

    result["geographic_description"] = location or None

    try:
        zones = timezone.time_zones_for_number(
            number
        )
    except Exception:
        zones = ()

    result["timezones"] = list(zones)

    if include_carrier:
        try:
            carrier_name = carrier.name_for_number(
                number,
                "en",
            )
        except Exception:
            carrier_name = ""

        result["carrier_metadata"] = (
            carrier_name or None
        )

    return result


def _display_info(result: dict[str, Any]) -> None:
    """Display phone information in a readable table."""

    rows = []

    display_order = [
        ("Input / E.164", "input"),
        ("International", "international"),
        ("National", "national"),
        ("Possible", "possible"),
        ("Valid", "valid"),
        ("Number type", "number_type"),
        ("Country code", "country_code"),
        ("National number", "national_number"),
        ("Region code", "region_code"),
        ("Country", "country"),
        ("Geographic description", "geographic_description"),
        ("Carrier metadata", "carrier_metadata"),
        ("Timezones", "timezones"),
    ]

    for label, key in display_order:
        value = result.get(key)

        if isinstance(value, list):
            value = ", ".join(str(x) for x in value)

        rows.append(
            [
                label,
                value if value not in (None, "") else "n/a",
            ]
        )

    print_two_col(
        ["Field", "Value"],
        rows,
    )


# --------------------------------------------------------------------------
# 1. Detailed phone information
# --------------------------------------------------------------------------

def phone_lookup():
    section("Phone number detailed info")

    if not _require_library():
        wait_or_exit()
        return

    value = get_str(
        "Phone number"
    ) or ""

    if not value:
        return

    region = get_str(
        "Default region (ISO code, optional)",
        default="IN",
    )

    try:
        number = _parse_number(
            value,
            region,
        )

        result = _number_info(
            number,
            include_carrier=True,
        )

        if result["valid"]:
            ok("Number is valid according to numbering-plan metadata.")
        elif result["possible"]:
            warn(
                "Number has a possible format, "
                "but could not be confirmed as valid."
            )
        else:
            warn(
                "Number does not appear valid "
                "according to numbering-plan metadata."
            )

        _display_info(result)

        info(
            "Carrier/location fields are numbering-plan metadata; "
            "they do not prove the current subscriber or live location."
        )

        prompt_export(
            result,
            "phone_lookup",
        )

    except ValueError as exc:
        err(str(exc))

    except Exception as exc:
        err(f"Phone lookup failed: {exc}")

    wait_or_exit()


# --------------------------------------------------------------------------
# 2. Validation and formatting
# --------------------------------------------------------------------------

def phone_validate():
    section("Phone validation & formatting")

    if not _require_library():
        wait_or_exit()
        return

    value = get_str(
        "Phone number"
    ) or ""

    if not value:
        return

    region = get_str(
        "Default region (ISO code, optional)",
        default="IN",
    )

    try:
        number = _parse_number(
            value,
            region,
        )

        possible = phonenumbers.is_possible_number(
            number
        )

        valid = phonenumbers.is_valid_number(
            number
        )

        result = {
            "input": value,
            "region": (
                region.upper()
                if region
                else None
            ),
            "possible": possible,
            "valid": valid,
            "e164": phonenumbers.format_number(
                number,
                phonenumbers.PhoneNumberFormat.E164,
            ),
            "international": phonenumbers.format_number(
                number,
                phonenumbers.PhoneNumberFormat.INTERNATIONAL,
            ),
            "national": phonenumbers.format_number(
                number,
                phonenumbers.PhoneNumberFormat.NATIONAL,
            ),
        }

        if valid:
            ok("Valid phone number.")
        elif possible:
            warn(
                "Possible number, but numbering-plan validation failed."
            )
        else:
            err("Invalid phone number.")

        print_two_col(
            ["Format", "Value"],
            [
                ["E.164", result["e164"]],
                ["International", result["international"]],
                ["National", result["national"]],
            ],
        )

        prompt_export(
            result,
            "phone_validate",
        )

    except ValueError as exc:
        err(str(exc))

    except Exception as exc:
        err(f"Validation failed: {exc}")

    wait_or_exit()


# --------------------------------------------------------------------------
# 3. Region / timezone inference
# --------------------------------------------------------------------------

def phone_region():
    section("Country / region / timezone inference")

    if not _require_library():
        wait_or_exit()
        return

    value = get_str(
        "Phone number"
    ) or ""

    if not value:
        return

    region = get_str(
        "Default region (ISO code, optional)",
        default="IN",
    )

    try:
        number = _parse_number(
            value,
            region,
        )

        region_code = phonenumbers.region_code_for_number(
            number
        )

        country = geocoder.country_name_for_number(
            number,
            "en",
        )

        description = geocoder.description_for_number(
            number,
            "en",
        )

        zones = list(
            timezone.time_zones_for_number(
                number
            )
        )

        result = {
            "input": value,
            "country_code": number.country_code,
            "region_code": region_code or None,
            "country": country or None,
            "geographic_description": (
                description or None
            ),
            "timezones": zones,
        }

        rows = [
            [
                "Country code",
                result["country_code"],
            ],
            [
                "Region code",
                result["region_code"] or "n/a",
            ],
            [
                "Country",
                result["country"] or "n/a",
            ],
            [
                "Geographic description",
                result["geographic_description"] or "n/a",
            ],
            [
                "Timezones",
                ", ".join(zones) if zones else "n/a",
            ],
        ]

        print_two_col(
            ["Field", "Value"],
            rows,
        )

        ok("Numbering-plan region inference completed.")

        info(
            "Timezone and geographic results are metadata-based "
            "and are not a live location lookup."
        )

        prompt_export(
            result,
            "phone_region",
        )

    except ValueError as exc:
        err(str(exc))

    except Exception as exc:
        err(f"Region lookup failed: {exc}")

    wait_or_exit()
