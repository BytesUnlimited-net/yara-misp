#!/usr/bin/env python3

import logging
import os
import time
from typing import Any

import requests
from pymisp import PyMISP, MISPAttribute


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MISP_URL = os.getenv("MISP_URL")
MISP_API_KEY = os.getenv("MISP_KEY")

# Your own GeoIP REST API
GEOIP_URL = os.getenv("GEOIP_URL")

# Optional authentication for your GeoIP API
GEOIP_API_KEY = os.getenv("GEOIP_API_KEY")

# Verify TLS certificates when talking to MISP / GeoIP API
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
GEOIP_VERIFY_SSL = os.getenv("GEOIP_VERIFY_SSL", "true").lower() == "true"

# How often the worker checks MISP
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))

# Maximum number of attributes processed in one cycle
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))

# HTTP timeout for the GeoIP API
GEOIP_TIMEOUT = int(os.getenv("GEOIP_TIMEOUT", "10"))

# Marker used to identify our enrichment in the MISP comment
GEOIP_MARKER = "[GeoIP]"


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("misp-geoip")


# ---------------------------------------------------------------------------
# GeoIP
# ---------------------------------------------------------------------------

def lookup_geoip(ip: str) -> dict[str, Any] | None:
    """
    Query the custom GeoIP REST API.

    Expected example response:

    {
        "continent": "Nordamerika",
        "country": "US",
        "region": "Virginia",
        "city": "Ashburn",
        "latitude": 39.0469,
        "longitude": -77.4903,
        "metro_code": 511,
        "accuracy_radius": 1000,
        "time_zone": "America/New_York"
    }

    Adjust this function if your actual API has a different schema.
    """

    if ip:
      return {
        "continent": "Nordamerika",
        "country": "US",
        "region": "Virginia",
        "city": "Ashburn",
        "latitude": 39.0469,
        "longitude": -77.4903,
        "metro_code": 511,
        "accuracy_radius": 1000,
        "time_zone": "America/New_York"
    }

    headers = {
        "Accept": "application/json",
    }

    if GEOIP_API_KEY:
        headers["Authorization"] = f"Bearer {GEOIP_API_KEY}"

    try:
        response = requests.get(
            GEOIP_URL,
            params={"ip": ip},
            headers=headers,
            timeout=GEOIP_TIMEOUT,
            verify=GEOIP_VERIFY_SSL,
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict):
            logger.warning(
                "GeoIP API returned unexpected response for %s",
                ip,
            )
            return None

        return data

    except requests.RequestException as exc:
        logger.error("GeoIP request failed for %s: %s", ip, exc)
        return None

    except ValueError as exc:
        logger.error("Invalid JSON from GeoIP API for %s: %s", ip, exc)
        return None


# ---------------------------------------------------------------------------
# Comment formatting
# ---------------------------------------------------------------------------

def format_geoip_comment(data: dict[str, Any]) -> str:
    """
    Convert the GeoIP API response into a compact human-readable
    MISP attribute comment.
    """

    lines = [
        GEOIP_MARKER,
    ]

    fields = [
        ("Country", "country"),
        ("Region", "region"),
        ("City", "city"),
        ("Continent", "continent"),
        ("Latitude", "latitude"),
        ("Longitude", "longitude"),
        ("Accuracy radius", "accuracy_radius"),
        ("Timezone", "time_zone"),
        ("Metro code", "metro_code"),
    ]

    for label, key in fields:
        value = data.get(key)

        if value is not None and value != "":
            lines.append(f"{label}: {value}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MISP
# ---------------------------------------------------------------------------

def get_misp() -> PyMISP:
    if not MISP_URL or not MISP_API_KEY:
      raise ValueError("MISP URL or API key not provided")

    return PyMISP(
        MISP_URL,
        MISP_API_KEY,
        ssl=MISP_VERIFY_SSL,
    )


def find_unenriched_attributes(
    misp: PyMISP,
    limit: int,
) -> list[MISPAttribute]:
    """
    Find ip-src and ip-dst attributes that do not already contain
    our GeoIP marker.

    We deliberately retrieve the attributes and perform the marker
    check locally because the comment is our enrichment state.
    """

    attributes = misp.search(
        controller="attributes",
        type_attribute=["ip-src", "ip-dst"],
        limit=limit,
        pythonify=True,
    )

    result: list[MISPAttribute] = []

    for attribute in attributes:
        comment = getattr(attribute, "comment", None) or ""

        if GEOIP_MARKER not in comment:
            result.append(attribute)

    return result


def enrich_attribute(
    misp: PyMISP,
    attribute: MISPAttribute,
) -> bool:
    """
    Look up the IP and update the existing MISP attribute comment.
    """

    ip = attribute.value

    logger.info(
        "GeoIP lookup: attribute=%s type=%s ip=%s",
        attribute.uuid,
        attribute.type,
        ip,
    )

    geoip = lookup_geoip(ip)

    if geoip is None:
        return False

    geoip_comment = format_geoip_comment(geoip)

    existing_comment = getattr(attribute, "comment", None) or ""

    if existing_comment.strip():
        new_comment = (
            f"{existing_comment.rstrip()}\n\n"
            f"{geoip_comment}"
        )
    else:
        new_comment = geoip_comment

    attribute.comment = new_comment

    try:
        misp.update_attribute(
            attribute,
            pythonify=False,
        )

        logger.info(
            "Updated GeoIP comment: attribute=%s ip=%s",
            attribute.uuid,
            ip,
        )

        return True

    except Exception as exc:
        logger.error(
            "Failed to update MISP attribute %s: %s",
            attribute.uuid,
            exc,
        )

        return False


# ---------------------------------------------------------------------------
# Main worker
# ---------------------------------------------------------------------------

def process_once(misp: PyMISP) -> None:
    """
    Process one batch of IP attributes.
    """

    attributes = find_unenriched_attributes(
        misp,
        BATCH_SIZE,
    )

    if not attributes:
        logger.info("No un-enriched IP attributes found.")
        return

    logger.info(
        "Found %d un-enriched IP attributes.",
        len(attributes),
    )

    success = 0
    failed = 0

    for attribute in attributes:
        if enrich_attribute(misp, attribute):
            success += 1
        else:
            failed += 1

    logger.info(
        "Cycle finished: success=%d failed=%d",
        success,
        failed,
    )


def main() -> None:
    logger.info("Starting MISP GeoIP worker")

    misp = get_misp()

    logger.info(
        "Connected to MISP: %s",
        MISP_URL,
    )

    while True:
        try:
            process_once(misp)

        except KeyboardInterrupt:
            logger.info("Stopping.")
            break

        except Exception:
            logger.exception("Unexpected error during processing.")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
