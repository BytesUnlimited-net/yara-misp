#!/usr/bin/env python3

import os
import logging
from pathlib import Path

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
    "ip-dst",
    "ip-src|port",
    "ip-src",
    "hostname|port",
    "domain|ip",
}

# If True, only attributes with to_ids=True are converted.
ONLY_TO_IDS = False

# Whether newly created YARA attributes should have to_ids=True.
YARA_TO_IDS = True

# The folder where the yara files are created
OUT_DIR = "/tmp/yara/"


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

def process_event(event):
    """
    Convert selected attributes in one MISP event into YARA attributes.

    Existing YARA attributes are matched to their source attribute by the
    attr_uuid stored in the generated YARA rule's metadata.

    If a YARA rule already exists for a source attribute, the old YARA
    attribute is deleted and a new one is created.
    """

    created = 0
    skipped = 0

    for attr in event.attributes:

        # Never process existing YARA attributes as source attributes.
        if attr.type == "yara":
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
        # Create the new YARA attribute.
        # ---------------------------------------------------------------

        try:

            path = Path(f"{OUT_DIR}/{attr.uuid}.txt")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(yara_rule)

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

    total_events = 0
    total_created = 0
    total_skipped = 0

    while True:

        logger.info(
            "Fetching events: page=%d, limit=%d",
            1,
            20,
        )

        events = misp.search(
            controller="events",
            limit=20,
            order='timestamp DESC',
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

            created, skipped = process_event(
                event,
            )

            total_created += created
            total_skipped += skipped

        if True:
            break

    logger.info("Finished.")
    logger.info("Events processed: %d", total_events)
    logger.info("YARA attributes created: %d", total_created)
    logger.info("YARA attributes skipped: %d", total_skipped)


if __name__ == "__main__":
    main()