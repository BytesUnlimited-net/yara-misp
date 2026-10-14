#!/usr/bin/env python3

"""
Tests for geoIp.py

Run with:

    pytest -v test_geoIp.py

The tests do not require a running MISP instance or GeoIP API.
"""

import importlib
import os
import sys
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Import helper
# ---------------------------------------------------------------------------

MODULE_NAME = "src.geoIp"


@pytest.fixture
def worker():
    """
    Import the worker module with the required environment variables set.

    This is necessary because the worker reads configuration during import.
    """

    env = {
        "MISP_URL": "https://misp.example.test",
        "MISP_KEY": "test-misp-api-key",
        "GEOIP_URL": "https://geoip.example.test/lookup",
    }

    with patch.dict(os.environ, env, clear=False):
        sys.modules.pop(MODULE_NAME, None)
        module = importlib.import_module(MODULE_NAME)

    return module


# ---------------------------------------------------------------------------
# Configuration tests
# ---------------------------------------------------------------------------

class TestConfiguration:

    def test_required_environment_variables_are_loaded(self, worker):
        assert worker.MISP_URL == "https://misp.example.test"
        assert worker.MISP_API_KEY == "test-misp-api-key"
        assert worker.GEOIP_URL == "https://geoip.example.test/lookup"

    def test_missing_misp_url_is_reported(self):
        env = {
            "MISP_KEY": "test-key",
            "GEOIP_URL": "https://geoip.example.test",
        }

        with patch.dict(os.environ, env, clear=True):
            sys.modules.pop(MODULE_NAME, None)

            with pytest.raises(KeyError) as exc:
                importlib.import_module(MODULE_NAME)

        assert "MISP_URL" in str(exc.value)

    def test_missing_MISP_KEY_is_reported(self):
        env = {
            "MISP_URL": "https://misp.example.test",
            "GEOIP_URL": "https://geoip.example.test",
        }

        with patch.dict(os.environ, env, clear=True):
            sys.modules.pop(MODULE_NAME, None)

            with pytest.raises(KeyError) as exc:
                importlib.import_module(MODULE_NAME)

        assert "MISP_KEY" in str(exc.value)

    def test_missing_geoip_url_is_reported(self):
        env = {
            "MISP_URL": "https://misp.example.test",
            "MISP_KEY": "test-key",
        }

        with patch.dict(os.environ, env, clear=True):
            sys.modules.pop(MODULE_NAME, None)

            with pytest.raises(KeyError) as exc:
                importlib.import_module(MODULE_NAME)

        assert "GEOIP_URL" in str(exc.value)


# ---------------------------------------------------------------------------
# GeoIP formatting tests
# ---------------------------------------------------------------------------

class TestGeoIPFormatting:

    def test_full_geoip_response_is_formatted(self, worker):
        data = {
            "continent": "Nordamerika",
            "country": "US",
            "region": "Virginia",
            "city": "Ashburn",
            "latitude": 39.0469,
            "longitude": -77.4903,
            "metro_code": 511,
            "accuracy_radius": 1000,
            "time_zone": "America/New_York",
        }

        result = worker.format_geoip_comment(data)

        assert "[GeoIP]" in result
        assert "Country: US" in result
        assert "Region: Virginia" in result
        assert "City: Ashburn" in result
        assert "Continent: Nordamerika" in result
        assert "Latitude: 39.0469" in result
        assert "Longitude: -77.4903" in result
        assert "Accuracy radius: 1000" in result
        assert "Timezone: America/New_York" in result
        assert "Metro code: 511" in result

    def test_empty_values_are_not_added(self, worker):
        data = {
            "country": "US",
            "region": "",
            "city": None,
            "latitude": 39.0469,
            "longitude": -77.4903,
            "time_zone": "",
        }

        result = worker.format_geoip_comment(data)

        assert "Country: US" in result
        assert "Latitude: 39.0469" in result

        assert "Region:" not in result
        assert "City:" not in result
        assert "Timezone:" not in result

    def test_empty_geoip_response_contains_marker(self, worker):
        result = worker.format_geoip_comment({})

        assert result == "[GeoIP]"


# ---------------------------------------------------------------------------
# GeoIP API tests
# ---------------------------------------------------------------------------

class TestGeoIPLookup:

    @patch("src.geoIp.requests.get")
    def test_successful_geoip_lookup(self, mock_get, worker):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "city": {
                "continent": { "names": { "en": "Nordamerika" } },
                "country": { "names": { "en": "US" } },
                "subdivisions": [{ "names": { "en": "Virginia" } }],
                "city": { "names": { "en": "Ashburn" } },
                "location": {
                    "latitude": 40,
                    "longitude": -80,
                    "metro_code": 511,
                    "accuracy_radius": 1000,
                    "time_zone": "America/New_York",
                },
            },
        }
        mock_response.raise_for_status.return_value = None

        mock_get.return_value = mock_response

        result = worker.lookup_geoip("8.8.8.8")

        assert result == {
            "continent": "Nordamerika",
            "country": "US",
            "region": "Virginia",
            "city": "Ashburn",
            "latitude": 40,
            "longitude": -80,
            "metro_code": 511,
            "accuracy_radius": 1000,
            "time_zone": "America/New_York",
        }

        mock_get.assert_called_once()

        kwargs = mock_get.call_args.kwargs

        assert mock_get.call_args_list[0].args[0].endswith("8.8.8.8")
        assert kwargs["headers"]["Accept"] == "application/json"

    @patch("src.geoIp.requests.get")
    def test_geoip_api_failure_returns_none(self, mock_get, worker):
        import requests

        mock_get.side_effect = requests.RequestException(
            "Connection failed"
        )

        result = worker.lookup_geoip("8.8.8.8")

        assert result is None

    @patch("src.geoIp.requests.get")
    def test_invalid_json_returns_none(self, mock_get, worker):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = ValueError("Invalid JSON")

        mock_get.return_value = mock_response

        result = worker.lookup_geoip("8.8.8.8")

        assert result is None

    @patch("src.geoIp.requests.get")
    def test_unexpected_response_returns_none(self, mock_get, worker):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = ["unexpected", "response"]

        mock_get.return_value = mock_response

        result = worker.lookup_geoip("8.8.8.8")

        assert result is None

    @patch("src.geoIp.requests.get")
    def test_geoip_api_key_is_sent_when_configured(
        self,
        mock_get,
        worker,
        monkeypatch,
    ):
        monkeypatch.setattr(
            worker,
            "GEOIP_API_KEY",
            "secret-api-key",
        )

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "country": "US",
        }

        mock_get.return_value = mock_response

        worker.lookup_geoip("8.8.8.8")

        headers = mock_get.call_args.kwargs["headers"]

        assert headers["x-token"] == "secret-api-key"


# ---------------------------------------------------------------------------
# MISP attribute discovery tests
# ---------------------------------------------------------------------------

class TestAttributeDiscovery:

    def test_only_unenriched_attributes_are_returned(self, worker):
        enriched = MagicMock()
        enriched.comment = "[GeoIP]\nCountry: US"

        unenriched = MagicMock()
        unenriched.comment = ""

        also_unenriched = MagicMock()
        also_unenriched.comment = None

        misp = MagicMock()

        misp.search.return_value = [
            enriched,
            unenriched,
            also_unenriched,
        ]

        result = worker.find_unenriched_attributes(
            misp,
            limit=100,
        )

        assert result == [
            unenriched,
            also_unenriched,
        ]

    def test_searches_for_ip_src_and_ip_dst(self, worker):
        misp = MagicMock()
        misp.search.return_value = []

        worker.find_unenriched_attributes(
            misp,
            limit=100,
        )

        misp.search.assert_called_once()

        kwargs = misp.search.call_args.kwargs

        assert kwargs["controller"] == "attributes"
        assert set(kwargs["type_attribute"]) == {
            "ip-src",
            "ip-dst",
        }
        assert kwargs["limit"] == 100
        assert kwargs["pythonify"] is True


# ---------------------------------------------------------------------------
# Attribute enrichment tests
# ---------------------------------------------------------------------------

class TestAttributeEnrichment:

    @patch("src.geoIp.lookup_geoip")
    def test_attribute_comment_is_updated(
        self,
        mock_lookup,
        worker,
    ):
        attribute = MagicMock()
        attribute.uuid = "attribute-uuid"
        attribute.type = "ip-dst"
        attribute.value = "8.8.8.8"
        attribute.comment = ""

        mock_lookup.return_value = {
            "country": "US",
            "region": "Virginia",
            "city": "Ashburn",
            "latitude": 39.0469,
            "longitude": -77.4903,
            "accuracy_radius": 1000,
            "time_zone": "America/New_York",
        }

        misp = MagicMock()

        result = worker.enrich_attribute(
            misp,
            attribute,
        )

        assert result is True

        assert "[GeoIP]" in attribute.comment
        assert "Country: US" in attribute.comment
        assert "Region: Virginia" in attribute.comment
        assert "City: Ashburn" in attribute.comment
        assert "Latitude: 39.0469" in attribute.comment
        assert "Longitude: -77.4903" in attribute.comment

        misp.update_attribute.assert_called_once_with(
            attribute,
            pythonify=False,
        )

    @patch("src.geoIp.lookup_geoip")
    def test_existing_comment_is_preserved(
        self,
        mock_lookup,
        worker,
    ):
        attribute = MagicMock()
        attribute.uuid = "attribute-uuid"
        attribute.type = "ip-src"
        attribute.value = "1.2.3.4"
        attribute.comment = "Suspicious source IP"

        mock_lookup.return_value = {
            "country": "DE",
            "region": "North Rhine-Westphalia",
            "city": "Cologne",
        }

        misp = MagicMock()

        result = worker.enrich_attribute(
            misp,
            attribute,
        )

        assert result is True

        assert "Suspicious source IP" in attribute.comment
        assert "[GeoIP]" in attribute.comment
        assert "Country: DE" in attribute.comment
        assert "City: Cologne" in attribute.comment

        assert (
            attribute.comment.index("Suspicious source IP")
            < attribute.comment.index("[GeoIP]")
        )

    @patch("src.geoIp.lookup_geoip")
    def test_failed_geoip_lookup_does_not_modify_attribute(
        self,
        mock_lookup,
        worker,
    ):
        attribute = MagicMock()
        attribute.uuid = "attribute-uuid"
        attribute.type = "ip-dst"
        attribute.value = "8.8.8.8"
        attribute.comment = "Existing comment"

        mock_lookup.return_value = None

        misp = MagicMock()

        result = worker.enrich_attribute(
            misp,
            attribute,
        )

        assert result is False
        assert attribute.comment == "Existing comment"

        misp.update_attribute.assert_not_called()

    @patch("src.geoIp.lookup_geoip")
    def test_misp_update_failure_returns_false(
        self,
        mock_lookup,
        worker,
    ):
        attribute = MagicMock()
        attribute.uuid = "attribute-uuid"
        attribute.type = "ip-dst"
        attribute.value = "8.8.8.8"
        attribute.comment = ""

        mock_lookup.return_value = {
            "country": "US",
            "city": "Ashburn",
        }

        misp = MagicMock()
        misp.update_attribute.side_effect = Exception(
            "MISP API error"
        )

        result = worker.enrich_attribute(
            misp,
            attribute,
        )

        assert result is False


# ---------------------------------------------------------------------------
# Processing-cycle tests
# ---------------------------------------------------------------------------

class TestProcessing:

    @patch("src.geoIp.enrich_attribute")
    @patch("src.geoIp.find_unenriched_attributes")
    def test_process_once_processes_all_attributes(
        self,
        mock_find,
        mock_enrich,
        worker,
    ):
        attribute1 = MagicMock()
        attribute2 = MagicMock()
        attribute3 = MagicMock()

        mock_find.return_value = [
            attribute1,
            attribute2,
            attribute3,
        ]

        mock_enrich.side_effect = [
            True,
            True,
            False,
        ]

        misp = MagicMock()

        worker.process_once(misp)

        assert mock_enrich.call_count == 3

        mock_enrich.assert_any_call(
            misp,
            attribute1,
        )

        mock_enrich.assert_any_call(
            misp,
            attribute2,
        )

        mock_enrich.assert_any_call(
            misp,
            attribute3,
        )

    @patch("src.geoIp.enrich_attribute")
    @patch("src.geoIp.find_unenriched_attributes")
    def test_process_once_does_nothing_when_no_attributes(
        self,
        mock_find,
        mock_enrich,
        worker,
    ):
        mock_find.return_value = []

        misp = MagicMock()

        worker.process_once(misp)

        mock_enrich.assert_not_called()


# ---------------------------------------------------------------------------
# Security-related tests
# ---------------------------------------------------------------------------

class TestSecurity:

    @patch("src.geoIp.requests.get")
    def test_MISP_KEY_is_not_sent_to_geoip_api(
        self,
        mock_get,
        worker,
    ):
        """
        Make sure the MISP API key is never accidentally forwarded
        to the GeoIP API.
        """

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "country": "US",
        }

        mock_get.return_value = mock_response

        worker.lookup_geoip("8.8.8.8")

        headers = mock_get.call_args.kwargs["headers"]

        assert "Authorization" not in headers
        assert "X-MISP-API-Key" not in headers
