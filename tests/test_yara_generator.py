# test_yara_generator.py

import pytest
from unittest.mock import MagicMock
from pymisp import PyMISP

import yara_generator

@pytest.fixture
def misp(monkeypatch) -> PyMISP:
    """Mock the MISP API so no requests are made."""
    mock = MagicMock(spec=PyMISP)
    monkeypatch.setattr(yara_generator, "PyMISP", MagicMock(return_value=mock))
    return mock

def test_no_events(misp):
    misp.search.return_value = []

    yara_generator.main()
    misp.search.assert_called_once()

def test_no_attributes(misp, misp_event):
    misp.search.return_value = [misp_event]

    yara_generator.main()
    misp.search.assert_called_once()

def test_one_attribute(misp, misp_event, misp_attribute):
    misp_event.attributes = [misp_attribute]
    misp.search.return_value = [misp_event]

    yara_generator.main()
    misp.search.assert_called_once()

def test_hundred_attribute(misp, misp_event, misp_attribute):
    misp_event.attributes = []
    for _ in range(100):
        misp_event.attributes.append(misp_attribute)
    misp.search.return_value = [misp_event]

    yara_generator.main()
    misp.search.assert_called_once()


def test_hundred_events_with_each_one_attribute(misp, misp_event, misp_attribute):
    misp_event.attributes = [misp_attribute]
    misp_events = []
    for _ in range(100):
        misp_events.append(misp_event)
    misp.search.return_value = misp_events

    yara_generator.main()
    misp.search.assert_called_once()
