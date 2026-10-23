#!/usr/bin/env python3

import logging
import os
from datetime import datetime, timezone
import time
from typing import Any

import requests
from pymisp import PyMISP, MISPAttribute, MISPObject


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MISP_URL = os.environ["MISP_URL"]
MISP_API_KEY = os.environ["MISP_KEY"]

GEOIP_URL = os.environ["GEOIP_URL"]
GEOIP_API_KEY = os.getenv("GEOIP_API_KEY")

# Verify TLS certificates when talking to MISP / GeoIP API
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"
GEOIP_VERIFY_SSL = os.getenv("GEOIP_VERIFY_SSL", "true").lower() == "true"

# How often the worker checks MISP
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))

# HTTP timeout for the GeoIP API
GEOIP_TIMEOUT = int(os.getenv("GEOIP_TIMEOUT", "10"))

# Marker used to identify the enrichment in the MISP comment
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
        "zip_code": 20149,
        "latitude": 39.0469,
        "longitude": -77.4903,
        "accuracy_radius": 1000,
        "time_zone": "America/New_York"
    }
    """

    headers = {
        "Accept": "application/json",
    }

    if GEOIP_API_KEY:
        headers["x-token"] = GEOIP_API_KEY

    try:
        response = requests.get(
            GEOIP_URL + ip,
            headers=headers,
            timeout=GEOIP_TIMEOUT,
            verify=GEOIP_VERIFY_SSL,
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict) or not data.get("city"):
            logger.warning(
                "GeoIP API returned unexpected response for %s",
                ip,
            )
            return None

        geo_data = data["city"]
        subdivisions = geo_data.get("subdivisions", "")
        city = geo_data.get("city", "")
        zip_code = geo_data.get("postal", "")

        return {
            "continent": geo_data["continent"]["names"]["en"],
            "country": geo_data["country"]["names"]["en"],
            "region": subdivisions and subdivisions[0]["names"]["en"],
            "city": city and city["names"]["en"],
            "zip_code": zip_code and zip_code["code"],
            "latitude": geo_data["location"]["latitude"],
            "longitude": geo_data["location"]["longitude"],
            "accuracy_radius": geo_data["location"]["accuracy_radius"],
            "time_zone": geo_data["location"]["time_zone"],
        }

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
        ("Continent", "continent"),
        ("Country", "country"),
        ("Region", "region"),
        ("City", "city"),
        ("Zip code", "zip_code"),
        ("Latitude", "latitude"),
        ("Longitude", "longitude"),
        ("Accuracy radius", "accuracy_radius"),
        ("Timezone", "time_zone"),
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
) -> list[MISPAttribute]:
    """
    Find ip-src and ip-dst attributes that do not already contain
    our GeoIP marker.

    We deliberately retrieve the attributes and perform the marker
    check locally because the comment is our enrichment state.
    """

    attributes = misp.search(
        controller="attributes",
        type_attribute=["ip-src", "ip-dst", "ip-src|port", "ip-dst|port"],
        offset=0,
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

    ip = attribute.value.split("|")[0]

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
        ip_object = MISPObject("ip-api-address")
        ip_object.add_attribute("ip-src", ip)

        created: MISPObject = misp.add_object(attribute.event_id, ip_object, pythonify=True)

        fields = [
            ("Country", "country"),
            ("Region", "region"),
            ("City", "city"),
            ("Zipcode", "zip_code"),
            ("Latitude", "latitude"),
            ("Longitude", "longitude"),
        ]
        for label, key in fields:
            created.add_attribute(label, geoip[key])

        created.add_attribute("First-seen", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

        misp.update_object(created, pythonify=True)

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

    attributes = find_unenriched_attributes(misp)

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
