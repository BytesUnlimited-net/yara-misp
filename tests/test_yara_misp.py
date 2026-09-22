# test_yara_generator.py

from yara_misp import attr_to_yara_source

def test_ignored_attribute(misp_event, misp_attribute):
    misp_attribute.type = "comment"
    yara_rule = attr_to_yara_source(misp_attribute)

    assert '// Ignored attribute' in yara_rule

def test_hashed_attribute(misp_event, misp_attribute):
    misp_attribute.type = "sha256"
    misp_attribute.value = "test value"
    yara_rule = attr_to_yara_source(misp_attribute)

    assert 'hash.sha256' in yara_rule
    assert '"test value"' in yara_rule

def test_hex_attribute(misp_event, misp_attribute):
    misp_attribute.type = "hex"
    misp_attribute.value = "0123456789ABCDEF"
    yara_rule = attr_to_yara_source(misp_attribute)

    assert "{ 01 23 45 67 89 AB CD EF }" in yara_rule

def test_with_port_attribute(misp_event, misp_attribute):
    misp_attribute.type = "ip-src|port"
    misp_attribute.value = "192.168.1.100|8080"
    yara_rule = attr_to_yara_source(misp_attribute)

    assert '"192.168.1.100"' in yara_rule

