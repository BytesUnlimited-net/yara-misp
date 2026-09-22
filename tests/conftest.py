# test_yara_generator.py

import pytest
from pymisp import MISPAttribute, MISPEvent

@pytest.fixture
def misp_attribute():
    attribute = MISPAttribute()

    attribute.id = "123"
    attribute.uuid = "550e8400-e29b-41d4-a716-446655440000"
    attribute.event_id = "456"
    attribute.type = "ip-dst"
    attribute.category = "Network activity"
    attribute.value = "192.168.1.100"
    attribute.to_ids = False
    attribute.deleted = False
    attribute.comment = "Mock attribute for testing"

    return attribute

@pytest.fixture
def misp_event():
    event = MISPEvent()
    event.id = "123"
    event.info = "test info"

    return event
