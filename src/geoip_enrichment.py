import json
import logging
from datetime import datetime, timezone

import requests
from pymisp import PyMISP, MISPAttribute, MISPObject

logger = logging.getLogger("geoip")
logger.setLevel(logging.DEBUG)
ch = logging.FileHandler('/var/log/geoip_enrichment-module.log')
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

mispattributes = {
    "input": [
        "ip-src",
        "ip-dst",
        "ip-src|port",
        "ip-dst|port",
        "domain|ip",
    ],
    "output": ["MISP objects"],
    "format": "misp_standard"
}

moduleinfo = {
    "version": "1.0",
    "author": "Silas Wieberneit",
    "description": "Enriches IP addresses with geolocation information using a configurable Geo-IP service.",
    "module-type": ["expansion"],
    "name": "Geo-IP Enrichment",
    "logo": "",
    "requirements": [
        "A reachable Geo-IP API server",
        "A valid API key for the Geo-IP service",
        "MISP API access for checking existing geolocation objects",
    ],
    "input": [
        "ip-src",
        "ip-dst",
        "ip-src|port",
        "ip-dst|port",
        "domain|ip",
    ],
    "output": [
        "Geolocation MISP object containing geographic information and a reference to the original IP attribute"
    ],
    "config": [
        "geoip_url",
        "geoip_api_key",
        "misp_api_key",
    ]
}
moduleconfig = ["geoip_url", "geoip_api_key", "misp_api_key"]

# ---------------------------------------------------------------------------
# GeoIP
# ---------------------------------------------------------------------------

def lookup_geoip(ip: str, GEOIP_API_KEY: str, GEOIP_URL: str) -> dict[str, Any] | None:
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
            timeout=10,
            verify=False,
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
        zip_code = geo_data.get("postal", "")
        empty = { "names": { "en": "" } }

        return {
            "continent": geo_data.get("continent", empty)["names"]["en"],
            "country": geo_data.get("country", empty)["names"]["en"],
            "region": subdivisions and ", ".join(region["names"]["en"] for region in subdivisions),
            "city": geo_data.get("country", empty)["names"]["en"],
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


def enrich_attribute(
    attribute: MISPAttribute, GEOIP_URL: str, GEOIP_API_KEY: str, MISP_API_KEY: str
) -> any:
    """
    Look up the IP and update the existing MISP attribute comment.
    """
    attribute_uuid = attribute["uuid"]

    misp = PyMISP(
        "https://misp-core",
        MISP_API_KEY,
        ssl=False,
    )
    event = misp.get_event(attribute["event_id"])
    if any(
        ref["referenced_uuid"] == attribute_uuid
        for obj in event.get("Event", {}).get("Object", [])
        if obj.get("name") == "geolocation"
        for ref in obj.get("ObjectReference", [])
    ):
        return { "results": {} }

    logger.info(
        "Updated GeoIP attribute: id=%s, event=%s",
    event,
        [
            obj
            for obj in event.get("Event", {}).get("Object", [])
        ],
    )

    if attribute["type"] == "domain|ip":
        ip = attribute["value"].split("|")[1]
    else:
        ip = attribute["value"].split("|")[0]

    logger.info(
        "GeoIP lookup: attribute=%s type=%s ip=%s",
        attribute["uuid"],
        attribute["type"],
        ip,
    )

    geoip = lookup_geoip(ip, GEOIP_API_KEY, GEOIP_URL)

    if geoip is None:
        return { "results": {} }

    try:
        new_object = MISPObject("geolocation", standalone=False)

        fields = [
            ("city", "city"),
            ("region", "region"),
            ("country", "country"),
            ("zipcode", "zip_code"),
            ("latitude", "latitude"),
            ("longitude", "longitude"),
            ("accuracy-radius", "accuracy_radius"),
        ]
        for label, key in fields:
            new_object.add_attribute(label, geoip[key])

        new_object.add_attribute("last-seen", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

        new_object.add_reference(
            referenced_uuid=attribute["uuid"],
            relationship_type="located",
            comment="Geo-IP information for this IP address",
        )

        logger.info(
            "Updated GeoIP attribute: attribute=%s ip=%s",
            attribute["uuid"],
            new_object.to_json(),
        )

        return {
            "results": {
                "Object": [new_object.to_dict()]
            }
        }

    except Exception as exc:
        logger.error(
            "Failed to update MISP attribute %s: %s",
            attribute["uuid"],
            exc,
        )

        return False


def handler(q=False):
  try:
    # Input checks
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute"):
        return {"error": "No attribute provided."}
    attribute = request["attribute"]
    if attribute.get("type") not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}
    if not request.get("config"):
        return {"error": "Missing config."}
    if not request["config"].get("geoip_url"):
        return {"error": "Missing geo-IP URL."}
    if not request["config"].get("geoip_api_key"):
        return {"error": "Missing geo-IP API key."}
    if not request["config"].get("misp_api_key"):
        return {"error": "Missing MISP API key."}

    return enrich_attribute(attribute, request['config']['geoip_url'], request['config']['geoip_api_key'], request['config']['misp_api_key'])
  except Exception as exc:
      logger.error(
            "Failed to update MISP attribute",
      )
      return {"error": "Unexpected error: %s" % exc}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
