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

PAGE_SIZE = 100

# If True, only attributes with to_ids=True are converted.
ONLY_TO_IDS = False

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
# Event processing
# ---------------------------------------------------------------------------

def process_event(misp, event):
    """
    Convert selected attributes in one MISP event into YARA attributes.

    Existing YARA attributes are matched to their source attribute by the
    attr_uuid stored in the generated YARA rule's metadata.

    If a YARA rule already exists for a source attribute, the old YARA
    attribute is deleted and a new one is created.
    """

    # Map:
    #
    #   source MISP attribute UUID
    #       ->
    #   generated YARA MISP attribute UUID
    #
    existing_yara_rules = {}

    for attr in event.attributes:
        if attr.type != "yara":
            continue

        if not attr.value:
            continue

        marker = "attr_uuid = "

        if marker not in attr.value:
            continue

        try:
            source_uuid = (
                attr.value
                .split(marker, 1)[1]
                .splitlines()[0]
                .strip()
                .strip('"')
            )
        except (IndexError, AttributeError):
            continue

        if not source_uuid:
            continue

        existing_yara_rules[source_uuid] = attr.uuid

    created = 0
    replaced = 0
    skipped = 0

    for attr in event.attributes:

        # Never process existing YARA attributes as source attributes.
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

        if not yara_rule or not yara_rule.strip():
            logger.warning(
                "Empty YARA rule generated for event %s attribute %s",
                event.id,
                attr.uuid,
            )
            continue

        # ---------------------------------------------------------------
        # Check whether this source attribute already has a YARA rule.
        # ---------------------------------------------------------------

        existing_yara_rule = existing_yara_rules.get(attr.uuid)

        if existing_yara_rule:
            logger.info(
                "Existing YARA attribute %s found for source attribute %s "
                "in event %s; deleting old rule",
                existing_yara_rule,
                attr.uuid,
                event.id,
            )

            try:
                misp.delete_attribute(existing_yara_rule)
                replaced += 1
            except Exception:
                logger.exception(
                    "Failed deleting existing YARA attribute %s "
                    "for source attribute %s",
                    existing_yara_rule,
                    attr.uuid,
                )
                continue

        # ---------------------------------------------------------------
        # Create the new YARA attribute.
        # ---------------------------------------------------------------

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

    return created, replaced, skipped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

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
    total_replaced = 0
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

            # Explicitly fetch the complete event including attributes.
            event = misp.get_event(
                event.id,
                pythonify=True,
            )

            created, replaced, skipped = process_event(
                misp,
                event,
            )

            total_created += created
            total_replaced += replaced
            total_skipped += skipped

        if len(events) < PAGE_SIZE:
            break

        page += 1

    logger.info("Finished.")
    logger.info("Events processed: %d", total_events)
    logger.info("YARA attributes created: %d", total_created)
    logger.info("YARA attributes replaced: %d", total_replaced)
    logger.info("YARA attributes skipped: %d", total_skipped)


if __name__ == "__main__":
    main()