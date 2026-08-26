#!/usr/bin/env python3

import os
import logging

from pymisp import PyMISP
from yara_misp import attr_to_yara_source


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MISP_URL = os.environ["MISP_URL"]
MISP_KEY = os.environ["MISP_KEY"]

# Attribute types that should be converted to YARA.
#
# Keep this explicit rather than converting every non-YARA attribute.
SOURCE_ATTRIBUTE_TYPES = {
    "md5",
    "sha1",
    "sha256",
    "imphash",
    "filename",
    "filename|md5",
    "filename|sha1",
    "filename|sha256",
    "hex",
    "ip-dst|port",
    "ip-src|port",
    "hostname|port",
    "domain|ip",
}

# Number of events fetched per API request.
PAGE_SIZE = 100

# If True, only attributes with to_ids=True are converted.
ONLY_TO_IDS = True

# Whether newly created YARA attributes should have to_ids=True.
YARA_TO_IDS = True


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def process_event(misp, event):
    """
    Convert selected attributes in one MISP event into YARA attributes.
    """

    # Existing YARA attributes in this event.
    existing_yara_values = {
        attr.value
        for attr in event.attributes
        if attr.type == "yara"
    }

    created = 0
    skipped = 0

    for attr in event.attributes:

        # Never convert an already-existing YARA attribute.
        if attr.type == "yara":
            skipped += 1
            continue

        # Only process explicitly configured types.
        if attr.type not in SOURCE_ATTRIBUTE_TYPES:
            skipped += 1
            continue

        # Optional to_ids filtering.
        if ONLY_TO_IDS and not attr.to_ids:
            skipped += 1
            continue

        try:
            yara_rule = attr_to_yara_source(
                attr,
                related_evt=event,
                misp_url=MISP_URL,
            )
        except Exception:
            logger.exception(
                "Failed converting event %s attribute %s (%s)",
                event.id,
                attr.uuid,
                attr.type,
            )
            continue

        # Defensive check: don't create empty rules.
        if not yara_rule or not yara_rule.strip():
            logger.warning(
                "Empty YARA rule generated for event %s attribute %s",
                event.id,
                attr.uuid,
            )
            continue

        # ------------------------------------------------------------------
        # Deduplication
        #
        # attr_to_yara_source() includes the source attribute UUID in the
        # generated YARA metadata, so comparing the complete generated rule
        # is sufficient to prevent the same generated rule being added twice.
        # ------------------------------------------------------------------

        if yara_rule in existing_yara_values:
            logger.debug(
                "YARA rule already exists for event %s / attribute %s",
                event.id,
                attr.uuid,
            )
            skipped += 1
            continue

        # ------------------------------------------------------------------
        # Create the MISP YARA attribute
        # ------------------------------------------------------------------

        yara_attribute = {
            "type": "yara",
            "category": "Payload delivery",
            "value": yara_rule,
            "to_ids": YARA_TO_IDS,
            "comment": (
                "Automatically generated from MISP attribute "
                f"{attr.uuid} ({attr.type})"
            ),
        }

        try:
            misp.add_attribute(
                event.id,
                yara_attribute,
                break_on_duplicate=True,
            )

            # Keep our local duplicate set up to date in case multiple
            # operations in this run would generate the same rule.
            existing_yara_values.add(yara_rule)

            created += 1

            logger.info(
                "Created YARA attribute for event %s from %s (%s)",
                event.id,
                attr.uuid,
                attr.type,
            )

        except Exception:
            logger.exception(
                "Failed creating YARA attribute in event %s "
                "from attribute %s",
                event.id,
                attr.uuid,
            )

    return created, skipped


def main():
    misp = PyMISP(
        MISP_URL,
        MISP_KEY,
        ssl=True,
        debug=False,
    )

    page = 1
    total_events = 0
    total_created = 0
    total_skipped = 0

    while True:

        logger.info(
            "Fetching events: page=%d, limit=%d",
            page,
            PAGE_SIZE,
        )

        events = misp.search(
            controller="events",
            page=page,
            limit=PAGE_SIZE,
            pythonify=True,
        )

        if not events:
            break

        for event in events:
            total_events += 1

            logger.info(
                "Processing event %s: %s",
                event.id,
                event.info,
            )

            # The event search normally gives us the event with its
            # attributes, but explicitly fetch the event to make the
            # requirement clear and avoid depending on search settings.
            event = misp.get_event(
                event.id,
                pythonify=True,
            )

            created, skipped = process_event(
                misp,
                event,
            )

            total_created += created
            total_skipped += skipped

        # Last page.
        if len(events) < PAGE_SIZE:
            break

        page += 1

    logger.info("Finished.")
    logger.info("Events processed: %d", total_events)
    logger.info("YARA attributes created: %d", total_created)
    logger.info("YARA attributes skipped: %d", total_skipped)


if __name__ == "__main__":
    main()