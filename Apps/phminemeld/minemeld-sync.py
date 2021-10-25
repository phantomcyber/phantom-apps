# File: minemeld-sync.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
"""Script for synchronizing a MineMeld local DB Miner with indicators read from
local file using MineMeld API.

## EXAMPLES

To only add the indicators stored in Miner IPv4ListMiner with the IPv4
indicators contained in the file my-ipv4-addresses:

./minemeld-sync.py -m https://my-minemeld-address -u my-admin -p my-password -t IPv4 IPv4ListMiner my-ipv4-addresses

By default old indicators are not removed from the Miner. To synchronize
indicators in DomainListMiner with indicators contained in file my-domains,
adding new indicators and removing old indicators, use the --delete option:

./minemeld-sync.py -m https://my-minemeld-address -u my-admin -p my-password -t domain --delete DomainListMiner my-domains

Default share_level of the added indicators is red. To specify a different
share level use the --share-level option:

./minemeld-sync.py -m https://my-minemeld-address -u my-admin -p my-password -t IPv6 IPv6ListMiner my-ipv6-addresses

## CERT VERIFICATION

By default remote MineMeld certificate is verified using certifi (if installed),
or using the CA bundle file or CA certs directory specified via the --ca-path option.

./minemeld-sync.py -m https://my-minemeld-address --ca-path /etc/ssl/certs -u my-admin -p my-password -t IPv6 IPv6ListMiner my-ipv6-addresses

To disable remote certificate verification use the option -k:

./minemeld-sync.py -m https://my-minemeld-address -k -u my-admin -p my-password -t IPv6 IPv6ListMiner my-ipv6-addresses

## INPUT FILE FORMAT

Version 0.1.4 add support for input files in JSON format.

### JSON

MineMeld output feeds in JSON format. Example:

[
    {
        "indicator": "8.8.8.8",
        "value": {
            "comment": "Google DNS 1",
            "confidence": 100,
            "type": "IPv4",
            "share_level": "green"
        }
    },
    {
        "indicator": "8.8.4.4",
        "value": {
            "comment": "Google DNS 2",
            "confidence": 100,
            "type": "IPv4",
            "share_level": "green"
        }
    }
]

### PLAIN TEXT

Input file format is quite simple: a list of indicators. One per line. Example:

http://malicious1.example.com
https://malicious2.example.com

To add comments to each indicator, include it in a line before the indicator starting with
the # character:

# indicator provided by my cousin
http://malicious1.example.com
# indicator provided by SOC
https://malicious2.example.com

It is also possible to add custom attributes, using the format @<attribute name>: <attribute value>

# Google Public DNS (this is the comment)
# @direction: outbound
8.8.8.8
# Google Public DNS (this is the comment)
# @direction: outbound
8.8.4.4

"""

__version__ = '0.1.5'


import logging
import argparse
import urllib2
import json
import base64
import ssl
import os.path
from urlparse import urljoin

try:
    import certifi
    CERTIFI_PATH = certifi.where()
except ImportError:
    CERTIFI_PATH = None


LOG = logging.getLogger(__name__)


_MINEMELD_CLASS_TO_TYPE = {
    'minemeld.ft.local.YamlIPv4FT': {
        'data_file_type': 'yaml',
        'types': ['IPv4']
    },
    'minemeld.ft.local.YamlIPv6FT': {
        'data_file_type': 'yaml',
        'types': ['IPv6']
    },
    'minemeld.ft.local.YamlDomainFT': {
        'data_file_type': 'yaml',
        'types': ['domain']
    },
    'minemeld.ft.local.YamlURLFT': {
        'data_file_type': 'yaml',
        'types': ['URL']
    },
    'minemeld.ft.localdb.Miner': {
        'data_file_type': 'localdb',
        'types': ['IPv4', 'IPv6', 'domain', 'URL']
    }
}


class MineMeldAPIClient(object):
    def __init__(self, url, username, password, capath):
        self.url = url
        self.username = username
        self.password = password

        self.cafile = None
        self.capath = None
        self.context = None
        self.data_file_type = None

        if capath is None:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        else:
            if os.path.isfile(capath):
                self.cafile = capath
            elif os.path.isdir(capath):
                self.capath = capath
            else:
                raise RuntimeError('CA path should be a file or a directory')

    def _call_api(self, uri, data=None, headers=None, method=None):
        if headers is None:
            headers = {}

        api_url = urljoin(self.url, uri)
        api_request = urllib2.Request(api_url, headers=headers)
        basic_authorization = base64.b64encode('{}:{}'.format(self.username, self.password))
        api_request.add_header(
            'Authorization',
            'Basic {}'.format(basic_authorization)
        )

        if method is not None:
            api_request.get_method = lambda: method

        LOG.debug('MineMeld API Request: {} {}'.format(
            method if method is not None else 'GET',
            api_url
        ))

        result = urllib2.urlopen(
            api_request,
            data=data,
            timeout=30,
            capath=self.capath,
            cafile=self.cafile,
            context=self.context
        )
        content = result.read()
        result.close()

        return content

    def check(self, miner, type_):
        content = self._call_api('/status/minemeld')

        minemeld_status = json.loads(content)['result']
        for node in minemeld_status:
            if node['name'] == miner:
                if not node['class'] in _MINEMELD_CLASS_TO_TYPE:
                    raise RuntimeError('Unhandled Miner class {}'.format(node['class']))

                if type_ not in _MINEMELD_CLASS_TO_TYPE[node['class']]['types']:
                    LOG.critical('Miner {} of class {} does not support {} indicators'.format(miner, node['class'], type_))
                    return False

                self.data_file_type = _MINEMELD_CLASS_TO_TYPE[node['class']]['data_file_type']

                return True

        LOG.critical('Miner {} not found'.format(miner))

        return False

    def retrieve_list(self, miner):
        try:
            content = self._call_api('/config/data/{}_indicators?t={}'.format(miner, self.data_file_type))
        except urllib2.HTTPError, e:
            if e.code != 400:
                raise
            content = '{"result":[]}'

        return json.loads(content)['result']

    def upload(self, miner, data):
        if self.data_file_type == 'localdb':
            self._call_api(
                '/config/data/{}_indicators/append?h={}&t=localdb'.format(miner, miner, self.data_file_type),
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            return

        self._call_api(
            '/config/data/{}_indicators?h={}'.format(miner, miner),
            data=data,
            headers={'Content-Type': 'application/json'},
            method='PUT'
        )


def _iterate_over_json(listname):
    with open(listname, 'r') as f:
        ilist = json.load(f)

    if not isinstance(ilist, list):
        LOG.error('List of indicators expected in {}'.format(listname))
        return

    for e in ilist:
        i = e.pop('indicator', None)
        if i is None:
            LOG.error('Missing indicator in entry in {} - ignored'.format(listname))
            continue

        e = e.pop('value', e)

        e.pop('first_seen', None)
        e.pop('last_seen', None)
        e.pop('sources', None)

        yield i, e


def _iterate_over_list(listname):
    with open(listname, 'r') as f:
        value = {}

        for i in f:
            i = i.strip()
            if not i:
                continue

            if i.startswith('#'):
                # if line starts with # it's an attribute for the next indicator
                # format could be
                # # <comment>
                # # @<attribute name>: <attribute value>
                i = i[1:].strip()
                if not i:
                    continue

                if i.startswith('@'):
                    a, v = [x.strip() for x in i[1:].split(':', 1)]

                    if a == 'confidence':
                        v = int(v)
                    elif a == 'ttl':
                        try:
                            v = int(v)
                        except ValueError:
                            v = 'disabled'

                    value[a] = v
                else:
                    value['comment'] = i

            else:
                # add to the set
                yield i, value
                value = {}


def _merge_lists(lists, vdefault=None):
    """Returns a dictionary with all the indicators of the lists
    """

    result = {}
    for l in lists:
        _, extension = os.path.splitext(l)

        if extension == '.json':
            g = _iterate_over_json(l)
        else:
            g = _iterate_over_list(l)

        for indicator, ivalue in g:
            value = dict(vdefault if vdefault is not None else {})
            value.update(ivalue)

            result[indicator] = value

    return result


def _compute_actions(current, new_indicators):
    current_list = set(current.keys())
    new_list = set(new_indicators.keys())

    result = []

    for e in (new_list - current_list):
        result.append(['add', e])

    for e in (current_list - new_list):
        result.append(['delete', e])

    for e in (current_list & new_list):
        oldrepr = current[e]
        newrepr = json.dumps(dict(indicator=e, **new_indicators[e]), sort_keys=True)
        if oldrepr != newrepr:
            result.append(['update', e])

    return result


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Upload indicators to a MineMeld list Miner"
    )
    parser.add_argument(
        '--version',
        action='version',
        version=__version__
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='verbose'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='do not perform any action, displays actions that would be taken instead'
    )
    parser.add_argument(
        '--ca-path',
        action='store',
        help='CA bundle or CA directory to be used for MineMeld cert verification'
    )
    parser.add_argument(
        '-k',
        action='store_true',
        help='disable MineMeld cert verification'
    )
    parser.add_argument(
        '-m', '--minemeld',
        action='store',
        required=True,
        help='URL of MineMeld API. Example: https://myminemeld.example.com (required)'
    )
    parser.add_argument(
        '-u', '--username',
        action='store',
        required=True,
        help='username for authenticating to the MineMeld instance (required)'
    )
    parser.add_argument(
        '-p', '--password',
        action='store',
        required=True,
        help='password for authenticating to the MineMeld instance (required)'
    )
    parser.add_argument(
        '-t', '--type',
        action='store',
        required=True,
        help='type of indicators (required)'
    )
    parser.add_argument(
        '--delete',
        action='store_true',
        help='delete old indicators'
    )
    parser.add_argument(
        '--update',
        action='store_true',
        help='update existing indicators if different'
    )
    parser.add_argument(
        '--share-level',
        action='store',
        default='red',
        choices=['white', 'green', 'yellow', 'amber', 'red']
    )
    parser.add_argument(
        'miner',
        action='store',
        help='Miner name'
    )
    parser.add_argument(
        'list',
        action='store',
        nargs='+',
        help='path of the file with the list of indicators'
    )
    return parser.parse_args()


def main():
    args = _parse_args()

    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)

    capath = CERTIFI_PATH
    if args.ca_path:
        capath = args.ca_path

    if args.k:
        LOG.warning('MineMeld cert verification disabled')
        capath = None
    elif capath is None:
        LOG.critical('MineMeld cert verification enabled but no CA path specified and certifi is not installed')
        return 1

    MM = MineMeldAPIClient(
        url=args.minemeld,
        username=args.username,
        password=args.password,
        capath=capath
    )

    if not MM.check(miner=args.miner, type_=args.type):
        return 1

    current_list = MM.retrieve_list(miner=args.miner)
    current = {e['indicator']: json.dumps(e, sort_keys=True) for e in current_list}

    new_indicators = _merge_lists(args.list, {'share_level': args.share_level, 'type': args.type})

    actions = _compute_actions(current, new_indicators)

    if not args.update:
        actions = [a for a in actions if a[0] != 'update']

    if not args.delete:
        actions = [a for a in actions if a[0] != 'delete']

    if MM.data_file_type == 'localdb':
        result = {}
    else:
        result = current

    for aidx, (action, indicator) in enumerate(actions):
        if action == 'delete':
            LOG.info('A#{} - {} (delete)'.format(aidx, indicator))
            if MM.data_file_type == 'localdb':
                # with localdb with set a negative ttl to remove it
                value = json.loads(current[indicator])
                value['ttl'] = 0
                result[indicator] = json.dumps(value, sort_keys=True)
            else:
                result.pop(indicator)
        elif action == 'update' or action == 'add':
            LOG.info('A#{} - {} ({})'.format(aidx, indicator, action))
            result[indicator] = json.dumps(dict(indicator=indicator, **new_indicators[indicator]), sort_keys=True)
        else:
            raise RuntimeError('Unknown action {}'.format(action))

    if args.dry_run:
        LOG.info('Dry-run active, actions not performed')
        return 0

    if result:
        MM.upload(args.miner, '[{}]'.format(','.join(result.values())))

    LOG.info('Done')


if __name__ == "__main__":
    main()
