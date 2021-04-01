# File: parser.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import re
import socket
import phantom.utils as ph_utils
import phantom.app as phantom

_container_common = {
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

URI_REGEX = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
EMAIL_REGEX = r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
EMAIL_REGEX2 = r'".*"@[A-Z0-9.-]+\.[A-Z]{2,}\b'
HASH_REGEX = r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b"
IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
IPV6_REGEX = r'\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))'
IPV6_REGEX += r'|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*'


def _extract_domain_from_url(url):
    domain = phantom.get_host_from_url(url)
    if domain and not _is_ip(domain):
        return domain
    return None


def _is_ip(input_ip):
    if (ph_utils.is_ip(input_ip)):
        return True

    if (is_ipv6(input_ip)):
        return True

    return False


def _clean_url(url):
    url = url.strip('>),.]\r\n')

    # Check before splicing, find returns -1 if not found
    # _and_ you will end up splicing on -1 (incorrectly)
    if ('<' in url):
        url = url[:url.find('<')]

    if ('>' in url):
        url = url[:url.find('>')]

    return url


def is_ipv6(input_ip):
    try:
        socket.inet_pton(socket.AF_INET6, input_ip)
    except:  # not a valid v6 address
        return False

    return True


class TextIOCParser():
    BASE_PATTERNS = [
        {
            'cef': 'ip',             # Name of CEF field
            'pattern': IP_REGEX,     # Regex to match
            'name': 'IP Artifact',   # Name of artifact
            'validator': _is_ip      # Additional function to verify matched string (Should return true or false)
        },
        {
            'cef': 'ip',
            'pattern': IPV6_REGEX,
            'name': 'IP Artifact',
            'validator': _is_ip
        },
        {
            'cef': 'requestURL',
            'pattern': URI_REGEX,
            'name': 'URL Artifact',
            'clean': _clean_url,     # Additional cleaning of data from regex (Should return a string)
            'subtypes': [            # Additional IOCs to find in a matched one
                # If you really wanted to, you could also have subtypes in the subtypes
                {
                    'cef': 'domain',
                    'name': 'Domain Artifact',
                    'callback': _extract_domain_from_url   # Method to extract substring
                }
            ]
            # We dont need to worry about the case where an IP is the 'main' part of the url, since the two
            # IP regexes are already going to find those
        },
        {
            'cef': 'fileHash',
            'pattern': HASH_REGEX,
            'name': 'Hash Artifact'
        },
        {
            'cef': 'email',
            'pattern': EMAIL_REGEX,
            'name': 'Email Artifact',
            'subtypes': [
                {
                    'cef': 'domain',
                    'name': 'Domain Artifact',
                    'callback': lambda x: x[x.rfind('@') + 1:],
                    'validator': lambda x: not _is_ip(x)
                }
            ]
        },
        {
            'cef': 'email',
            'pattern': EMAIL_REGEX2,
            'name': 'Email Artifact',
            'subtypes': [
                {
                    'cef': 'domain',
                    'name': 'Domain Artifact',
                    'callback': lambda x: x[x.rfind('@') + 1:],
                    'validator': lambda x: not _is_ip(x)
                }
            ]
        }
    ]
    found_values = set()

    def __init__(self, patterns=None):
        self.patterns = self.BASE_PATTERNS if patterns is None else patterns
        self.added_artifacts = 0

    def _create_artifact(self, artifacts, value, cef, name):
        artifact = {}
        artifact['source_data_identifier'] = self.added_artifacts
        artifact['cef'] = {cef: value}
        artifact['name'] = name
        artifacts.append(artifact)
        self.added_artifacts += 1
        self.found_values.add(value)

    def _parse_ioc_subtype(self, artifacts, value, subtype):
        callback = subtype.get('callback')
        if callback:
            sub_val = callback(value)
            self._pass_over_value(artifacts, sub_val, subtype)

    def _pass_over_value(self, artifacts, value, ioc):
        validator = ioc.get('validator')
        clean = ioc.get('clean')
        subtypes = ioc.get('subtypes', [])
        if not value:
            return
        if value in self.found_values:
            return
        if clean:
            value = clean(value)
        if validator and not validator(value):
            return
        self._create_artifact(artifacts, value, ioc['cef'], ioc['name'])
        for st in subtypes:
            self._parse_ioc_subtype(artifacts, value, st)

    def parse_to_artifacts(self, text):
        artifacts = []
        for ioc in self.patterns:
            regexp = re.compile(ioc['pattern'], re.IGNORECASE)
            found = regexp.findall(text)
            for match in found:
                if type(match) == tuple:
                    for x in match:
                        self._pass_over_value(artifacts, x, ioc)
                else:
                    self._pass_over_value(artifacts, match, ioc)
        return artifacts
