# test_yara_generator.py
import logging

import pytest
from unittest.mock import MagicMock
from pymisp import PyMISP

import yara_generator

@pytest.fixture
def misp(monkeypatch) -> MagicMock:
    """Mock the MISP API so no requests are made."""
    mock = MagicMock(spec=PyMISP)
    monkeypatch.setattr(yara_generator, "PyMISP", MagicMock(return_value=mock))
    return mock

def test_no_events(misp, caplog):
    misp.search.return_value = []

    with caplog.at_level(logging.INFO):
        yara_generator.main()
    misp.search.assert_called_once()

    assert "Events processed: 0\n" in caplog.text
    assert "YARA attributes created: 0\n" in caplog.text

def test_no_attributes(misp, caplog, misp_event):
    misp.search.return_value = [misp_event]
    misp.get_event.return_value = misp_event

    with caplog.at_level(logging.INFO):
        yara_generator.main()
    misp.search.assert_called_once()

    assert "Events processed: 1\n" in caplog.text
    assert "YARA attributes created: 0\n" in caplog.text

def test_one_attribute(misp, caplog, misp_event, misp_attribute):
    misp_event.attributes = [misp_attribute]
    misp.search.return_value = [misp_event]
    misp.get_event.return_value = misp_event

    with caplog.at_level(logging.INFO):
        yara_generator.main()
    misp.search.assert_called_once()

    assert "Events processed: 1\n" in caplog.text
    assert "YARA attributes created: 1\n" in caplog.text

def test_hundred_attribute(misp, caplog, misp_event, misp_attribute):
    misp_event.attributes = []
    for _ in range(100):
        misp_event.attributes.append(misp_attribute)
    misp.search.return_value = [misp_event]
    misp.get_event.return_value = misp_event

    with caplog.at_level(logging.INFO):
        assert len(misp_event.attributes) == 100
        yara_generator.main()
    misp.search.assert_called_once()

    assert "Events processed: 1\n" in caplog.text
    assert "YARA attributes created: 100\n" in caplog.text


def test_hundred_events_with_each_one_attribute(misp, caplog, misp_event, misp_attribute):
    misp_event.attributes = [misp_attribute]
    misp_events = []
    for _ in range(100):
        misp_events.append(misp_event)
    misp.search.return_value = misp_events
    misp.get_event.return_value = misp_event

    with caplog.at_level(logging.INFO):
        yara_generator.main()
    misp.search.assert_called_once()

    assert "Events processed: 100\n" in caplog.text
    assert "YARA attributes created: 100\n" in caplog.text
