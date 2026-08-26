# -*- coding: utf-8 -*-

"""
A minimally modernized version of MISP/yara-misp's yara_misp.py.

The rule-generation logic is intentionally kept close to the original
implementation.  The main changes are:
  * no dependency on the obsolete yara_validator package;
  * no dependency on six;
  * current PyMISP's MISPAttribute.from_dict() is used instead of the
    removed/changed set_all_values() behaviour;
  * current PyMISP constructor/search response handling is supported;
  * YARA validation uses yara-python directly.

Dependencies:
    pip install pymisp yara-python
"""

import re
import warnings

import yara
from pymisp import MISPAttribute, PyMISP, PyMISPError


FILENAME_TAG = '@yara-filename:'


class YaraMISPAttribute(MISPAttribute):
    """MISPAttribute with the small amount of behaviour used by yara-misp."""

    def __init__(self, misp_attribute=None, **kwargs):
        MISPAttribute.__init__(self)

        if (misp_attribute is not None and kwargs) or (
            misp_attribute is None and not kwargs
        ):
            raise SyntaxError(
                "YaraMISPAttribute's constructor expects either "
                "misp_attribute or **kwargs to be set"
            )

        if misp_attribute is not None:
            if isinstance(misp_attribute, MISPAttribute):
                # Current PyMISP loads attributes through from_dict().
                self.from_dict(**misp_attribute.to_dict())
            elif isinstance(misp_attribute, dict):
                self.from_dict(**misp_attribute)
            else:
                raise TypeError(
                    "YaraMISPAttribute's constructor expects "
                    "misp_attribute to be MISPAttribute or dict, or None"
                )
        else:
            self.from_dict(**kwargs)

    @property
    def _yaramisp_source(self):
        return attr_to_yara_source(self)

    @property
    def _yaramisp_include_name(self):
        comment = getattr(self, 'comment', None)
        if comment:
            regex = re.compile(
                r'^\s*' + re.escape(FILENAME_TAG) + r'(.*)$',
                re.MULTILINE,
            )
            match = regex.search(comment)
            return match.group(1).strip() if match else None
        return None

    def __str__(self):
        res = '// EVENT:     {}\n// ATTRIBUTE: {}\n'.format(
            getattr(self, 'event_id', ''),
            getattr(self, 'uuid', ''),
        )
        return res + self._yaramisp_source


class YaraMISP:
    # Note on naming conventions:
    # 'attribute' represents a MISP attribute (object) of type 'yara'
    # 'rule' represents a yara signature (string) or set of signatures

    @staticmethod
    def _attribute_from_dict(attr):
        """Turn a current PyMISP search dictionary into a MISPAttribute."""
        if isinstance(attr, MISPAttribute):
            return attr

        if not isinstance(attr, dict):
            raise TypeError(
                'Expected a MISPAttribute or dict, got {}'.format(
                    type(attr).__name__
                )
            )

        # API responses normally contain the attribute fields directly.
        # Be tolerant of {"Attribute": {...}} as well.
        if 'Attribute' in attr and isinstance(attr['Attribute'], dict):
            attr = attr['Attribute']

        result = MISPAttribute()
        result.from_dict(**attr)
        return result

    @classmethod
    def _fetch_attrs(
        cls,
        server,
        key,
        enforce_ids=True,
        yara_only=True,
        published_only=False,
        include=None,
        exclude=None,
        verifycert=True,
    ):
        # Current PyMISP signature is PyMISP(url, key, ssl=True, debug=False).
        misp = PyMISP(server, key, ssl=verifycert)

        if yara_only:
            type_attribute = ['yara']
        else:
            type_attribute = [
                '!' + exc for exc in attributes_without_processing.keys()
            ]

        yara_dict_attrs = []

        # Keep the old published-event workaround.  Current MISP versions
        # still expose search_index(), while attribute searches are the
        # canonical way to retrieve the actual attributes.
        if include is None:
            include = []

        if (not include and not type_attribute) or published_only is False:
            if not include:
                all_events_dicts = misp.search_index(published=published_only)

                if isinstance(all_events_dicts, dict):
                    if 'errors' in all_events_dicts:
                        raise PyMISPError(all_events_dicts['message'])
                    event_rows = all_events_dicts.get('response', [])
                else:
                    event_rows = all_events_dicts

                for evt in event_rows:
                    if isinstance(evt, dict):
                        event_id = evt.get('id')
                        if event_id is None and isinstance(
                            evt.get('Event'), dict
                        ):
                            event_id = evt['Event'].get('id')
                        if event_id is not None:
                            include.append(event_id)

                print('Index fetched ({})'.format(len(include)))

        search_results = misp.search(
            controller='attributes',
            type_attribute=type_attribute,
            to_ids=enforce_ids,
            eventid=include,
        )

        if isinstance(search_results, dict) and 'errors' in search_results:
            raise PyMISPError(search_results['message'])

        # Depending on the PyMISP version/options, search() can return either
        # the raw API response or pythonified MISP objects.  Accept both.
        if isinstance(search_results, dict):
            attrs = search_results.get('response', [])
            if isinstance(attrs, dict):
                attrs = attrs.get('Attribute', [])
            if attrs:
                yara_dict_attrs.extend(attrs)
        elif isinstance(search_results, (list, tuple)):
            yara_dict_attrs.extend(search_results)

        yara_pymisp_attrs = []
        for attr in yara_dict_attrs:
            event_id = getattr(attr, 'event_id', None)
            if isinstance(attr, dict):
                event_id = attr.get('event_id', event_id)
                if event_id is None and isinstance(attr.get('Event'), dict):
                    event_id = attr['Event'].get('id')

            if not exclude or event_id not in exclude:
                yara_pymisp_attrs.append(
                    YaraMISPAttribute(
                        misp_attribute=cls._attribute_from_dict(attr)
                    )
                )

        return yara_pymisp_attrs

    @classmethod
    def check_all(cls, **kwargs):
        """
        Validate all supplied/fetched YARA attributes.

        The original project delegated this to yara_validator, which is no
        longer needed for syntax validation.  We retain the original return
        shape: (valid, broken, repaired).

        'repaired' is always empty because the old yara_validator repair
        engine is not part of current PyMISP/YARA tooling.  No automatic
        rewriting of user rules is performed here.
        """
        attributes = kwargs.get('attributes')
        server = kwargs.get('server', '')
        key = kwargs.get('key')
        exclude_evts = kwargs.get('exclude_evts', [])
        include_evts = kwargs.get('include_evts', [])
        enforce_ids = kwargs.get('enforce_ids', True)
        verifycert = kwargs.get('verifycert', True)

        if (attributes and server and key) or (
            not attributes and not (server and key)
        ):
            raise Exception(
                'yara_misp.check_all() requires either '
                '("attributes") or ("server" and "key") '
                'but not both'
            )

        if not attributes:
            raw_yara_attributes_buffer = cls._fetch_attrs(
                server,
                key,
                enforce_ids,
                True,       # yara_only
                False,      # published_only
                None,       # include
                None,       # exclude
                verifycert,
            )
        else:
            raw_yara_attributes_buffer = []
            for attr in attributes:
                event_id = getattr(attr, 'event_id', None)
                if (
                    (not exclude_evts or event_id not in exclude_evts)
                    and (not include_evts or event_id not in include_evts)
                ):
                    raw_yara_attributes_buffer.append(
                        YaraMISPAttribute(misp_attribute=attr)
                    )

        valid = []
        broken = []
        repaired = []

        for attr in raw_yara_attributes_buffer:
            source = attr._yaramisp_source
            try:
                yara.compile(source=source)
                valid.append(attr)
            except yara.Error:
                broken.append(attr)

        return valid, broken, repaired


# ================== ================== ================== ==================
# ============= Tools to build yara rules from non-yara attrs ===============
# ================== ================== ================== ==================

attributes_with_special_processing = {
    'yara': 'yara_rule_rule',
    'hex': 'single_hex_rule',
    'md5': 'hash_rule',
    'sha1': 'hash_rule',
    'sha256': 'hash_rule',
    'impash': 'hash_rule',
    'imphash': 'hash_rule',
    'filename|md5': 'hash_rule',
    'filename|sha1': 'hash_rule',
    'filename|sha256': 'hash_rule',
    'filename|impash': 'hash_rule',
    'filename|imphash': 'hash_rule',
    'filename': 'filename_rule',
    # # 'size-in-bytes': filesize_rule,
    # partial support
    'filename|sha224': 'filename_partial_rule',
    'filename|sha384': 'filename_partial_rule',
    'filename|sha512': 'filename_partial_rule',
    'filename|sha512/224': 'filename_partial_rule',
    'filename|sha512/256': 'filename_partial_rule',
    'filename|ssdeep': 'filename_partial_rule',
    'filename|impfuzzy': 'filename_partial_rule',
    'filename|tlsh': 'filename_partial_rule',
    'filename|authentihash': 'filename_partial_rule',
    'ip-dst|port': 'host_port_rule',
    'ip-src|port': 'host_port_rule',
    'hostname|port': 'host_port_rule',
    'domain|ip': 'domaip_ip_rule',
}

attributes_without_processing = {
    # unsupported
    'sha224': 'ignore_rule_unsupported',
    'sha384': 'ignore_rule_unsupported',
    'sha512': 'ignore_rule_unsupported',
    'sha512/224': 'ignore_rule_unsupported',
    'sha512/256': 'ignore_rule_unsupported',
    'regkey|value': 'ignore_rule_unsupported',
    'malware-sample': 'ignore_rule_unsupported',
    'snort': 'ignore_rule_unsupported',
    'sigma': 'ignore_rule_unsupported',
    # irrelevant or too many false-positives expected
    'http-method': 'ignore_rule_irrelevant',
    'attachment': 'ignore_rule_irrelevant',
    'comment': 'ignore_rule_irrelevant',
    'link': 'ignore_rule_irrelevant',
}


def attr_to_yara_source(
    attr,
    related_evt=None,
    misp_url=None,
    meta_blacklist=None,
):
    extra_meta = {}
    extra_meta['event_id'] = getattr(attr, 'event_id', '')
    extra_meta['attr_uuid'] = getattr(attr, 'uuid', '')
    extra_meta['comment'] = getattr(attr, 'comment', '')
    extra_meta['category'] = getattr(attr, 'category', '')
    extra_meta['type'] = getattr(attr, 'type', '')

    if related_evt is not None:
        extra_meta['event_info'] = related_evt.info

    if misp_url is not None:
        extra_meta['event_link'] = (
            misp_url.rstrip('/') + '/events/view/' +
            str(getattr(attr, 'event_id', ''))
        )

    if meta_blacklist:
        for tag in meta_blacklist:
            extra_meta.pop(tag, None)

    if attr.type in attributes_with_special_processing:
        processing_func = globals()[
            attributes_with_special_processing[attr.type]
        ]
        generated_yara = processing_func(attr, meta=extra_meta)
    elif attr.type in attributes_without_processing:
        processing_func = globals()[
            attributes_without_processing[attr.type]
        ]
        generated_yara = processing_func(attr)
    else:
        generated_yara = single_hex_or_string_rule(
            attr,
            meta=extra_meta,
        )

    return generated_yara


# ----- HELPERS FOR RULES CONSTRUCTION -------------------------------------


def basic_rule(attribute, strings_stmts, condition_stmts, **kwargs):
    modules = kwargs.get('modules')

    if not modules:
        modules = []
    elif isinstance(modules, str):
        modules = [modules]

    if isinstance(strings_stmts, str):
        strings_stmts = [strings_stmts]
    if isinstance(condition_stmts, str):
        condition_stmts = [condition_stmts]

    rulename = 'Attr_{}'.format(
        re.sub(r'\W+', '_', attribute.uuid)
    )

    if kwargs.get('meta') is not None:
        meta_dict = kwargs['meta']
        meta = '\r\n\t\t'.join(
            [
                key + ' = ' + text_str(
                    str(meta_dict[key])
                ).replace('\n', ' ').replace('\r', ' ')
                for key in meta_dict
            ]
        )
    else:
        meta = ''

    strings = (
        '\r\n\t\t'.join(strings_stmts)
        if strings_stmts else ''
    )
    condition = (
        '\r\n\t\t'.join(condition_stmts)
        if condition_stmts else ''
    )
    imports_section = '\r\n'.join(
        ['import "{}"'.format(m) for m in modules]
    ) if modules else ''

    rule_start_section = 'rule ' + rulename + '{'
    meta_section = '\tmeta:\r\n\t\t' + meta
    strings_section = (
        '\tstrings:\r\n\t\t' + strings
        if strings else ''
    )
    condition_section = (
        '\tcondition:\r\n\t\t' + condition
        if condition else ''
    )
    rule_end_section = '}'

    return '\r\n'.join([
        imports_section,
        rule_start_section,
        meta_section,
        strings_section,
        condition_section,
        rule_end_section,
    ])


def text_str(str_ioc, ascii_wide_nocase=False):
    str_ioc = str(str_ioc)
    quoted = u'"{}"'.format(
        str_ioc.replace('\\', '\\\\').replace('"', '\\"')
    )
    if ascii_wide_nocase:
        return quoted + ' nocase ascii wide'
    return quoted


def hex_str(hex_ioc):
    trimmed_ioc = re.sub(r'\s', '', str(hex_ioc))
    trimmed_ioc = trimmed_ioc.strip('}"{\'')
    if (
        all(c.upper() in '0123456789ABCDEF' for c in trimmed_ioc)
        and len(trimmed_ioc) % 2 == 0
    ):
        trimmed_spaced = ' '.join(
            trimmed_ioc[i:i + 2]
            for i in range(0, len(trimmed_ioc), 2)
        )
        return '{ ' + trimmed_spaced + ' }'

    raise ValueError(
        'hex_str expects a string in hex format possibly '
        'surrounded by curly brackets, spaces or quotes'
    )


def hash_cond(hashtype, hashvalue):
    if hashtype in ['md5', 'sha1', 'sha256']:
        condition_stmt = (
            'hash.{}(0, filesize) == {}'
            .format(hashtype, text_str(str(hashvalue).lower()))
        )
        required_module = 'hash'
    elif hashtype == 'imphash':
        condition_stmt = (
            'pe.imphash() == ' +
            text_str(str(hashvalue).lower())
        )
        required_module = 'pe'
    else:
        condition_stmt = ''
        required_module = None
        warnings.warn(
            'Hash type "{}" unsupported'.format(hashtype)
        )

    return condition_stmt, required_module


def pe_filename_cond(filename):
    return (
        'pe.version_info["OriginalFilename"] == ' +
        text_str(filename)
    )


# ----- FUNCTIONS TO CONVERT ATTRIBUTES TO YARA RULES ----------------------


def yara_rule_rule(attribute, **kwargs):
    return attribute.value


def single_string_rule(attribute, **kwargs):
    strings_stmt = []
    i = 0

    for line in attribute.value.splitlines():
        if line:
            strings_stmt += [
                '$ioc_l_{} = {}'.format(
                    str(i),
                    text_str(line, True),
                )
            ]
            i += 1

    condition_stmt = 'all of them'
    return basic_rule(
        attribute,
        strings_stmt,
        condition_stmt,
        **kwargs
    )


def single_hex_rule(attribute, **kwargs):
    strings_stmt = '$ioc = ' + hex_str(attribute.value)
    condition_stmt = '$ioc'
    return basic_rule(
        attribute,
        strings_stmt,
        condition_stmt,
        **kwargs
    )


def single_hex_or_string_rule(attribute, **kwargs):
    strings_stmt = []
    strings_id = []
    i = 0

    for line in attribute.value.splitlines():
        if line:
            strings_stmt += [
                '$ioc_l_{} = {}'.format(
                    str(i),
                    text_str(line, True),
                )
            ]
            strings_id += ['$ioc_l_' + str(i)]
            i += 1

    if len(strings_id) > 1:
        condition_stmt = 'all of ({})'.format(
            ', '.join(strings_id)
        )
    elif strings_id:
        condition_stmt = '$ioc_l_0'
    else:
        # Preserve the old intent but avoid generating an invalid
        # condition for an empty attribute.
        condition_stmt = 'false'

    try:
        hex_value = hex_str(attribute.value)
        strings_stmt += ['$ioc_hex = ' + hex_value]
        condition_stmt += ' or $ioc_hex'
    except ValueError:
        pass

    return basic_rule(
        attribute,
        strings_stmt,
        condition_stmt,
        **kwargs
    )


def hash_rule(attribute, **kwargs):
    if attribute.type.startswith('filename|'):
        _, hashtype = attribute.type.rsplit('|', 1)
        filename, hashvalue = attribute.value.rsplit('|', 1)
        condition_stmt, required_module = hash_cond(
            hashtype,
            hashvalue,
        )
        condition_stmt = (
            condition_stmt + ' or ' +
            pe_filename_cond(filename)
        )

        if required_module != 'pe':
            required_module = [
                required_module,
                'pe',
            ]
    else:
        hashtype = attribute.type
        hashvalue = attribute.value
        condition_stmt, required_module = hash_cond(
            hashtype,
            hashvalue,
        )

    return basic_rule(
        attribute,
        None,
        condition_stmt,
        modules=required_module,
        **kwargs
    )


def filename_rule(attribute, **kwargs):
    condition_stmt = pe_filename_cond(attribute.value)
    return basic_rule(
        attribute,
        None,
        condition_stmt,
        modules='pe',
        **kwargs
    )


def filename_partial_rule(attribute, **kwargs):
    filename, _ = attribute.value.rsplit('|', 1)
    condition_stmt = pe_filename_cond(filename)
    return basic_rule(
        attribute,
        None,
        condition_stmt,
        modules='pe',
        **kwargs
    )


def host_port_rule(attribute, **kwargs):
    host, port = attribute.value.rsplit('|', 1)
    strings_stmt = [
        '$ioc_host_only = ' + text_str(host, True)
    ]
    condition_stmt = '$ioc_host_only'
    return basic_rule(
        attribute,
        strings_stmt,
        condition_stmt,
        **kwargs
    )


def domaip_ip_rule(attribute, **kwargs):
    domain, ip = attribute.value.rsplit('|', 1)
    strings_stmt = [
        '$ioc_domain = ' + text_str(domain, True),
        '$ioc_ip = ' + text_str(ip, True),
    ]
    condition_stmt = '$ioc_domain and $ioc_ip'
    return basic_rule(
        attribute,
        strings_stmt,
        condition_stmt,
        **kwargs
    )


def ignore_rule(attribute, **kwargs):
    ignore_reason = (
        '//\t' + kwargs['ignore_reason']
        if 'ignore_reason' in kwargs else ''
    )
    return (
        '// Ignored attribute\r\n'
        '//\tType: {}\r\n'
        '//\tuuid: {}\r\n{}'
    ).format(
        attribute.type,
        attribute.uuid,
        ignore_reason,
    )


def ignore_rule_unsupported(attribute, **kwargs):
    reason = (
        'IOC type "{}" is not supported by yara '
        'or any of its native modules.'
    ).format(attribute.type)
    return ignore_rule(
        attribute,
        ignore_reason=reason,
        **kwargs
    )


def ignore_rule_irrelevant(attribute, **kwargs):
    reason = (
        'Creating a yara IOC from a "{}" attribute '
        'does not make sense'
    ).format(attribute.type)
    return ignore_rule(
        attribute,
        ignore_reason=reason,
        **kwargs
    )
