# File: app/configForward.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

"""
(C) Copyright Bitglass Inc. 2021. All Rights Reserved.
Author: eng@bitglass.com
"""

import re

from six import PY2

from app.config import Config, Feature, Status, log
from app.secret import Password

try:
    from flask import session
except Exception as ex:
    session = {}

# NOTE Do not import from package app/


sources = [
    ('invalid.xyz', 'Bearer', ''),
    ('invalid.xyz', 'Basic', ''),
]

log_types = [
    u'cloudaudit',
    u'access',
    u'admin',
    u'cloudsummary',
    u'swgweb',
    u'swgwebdlp',
]


class ConfigForward(Config):

    #
    # Old flags delta for reference
    #

    # p = optparse.OptionParser("usage: %prog [options]")

    # Not implemented yet.. why need it?
    # p.add_option(
    #     "-o",
    #     "--host", dest="host", default='localhost', help='hostname or ip address for splunk host, defaults to localhost')
    # p.add_option(
    #     "-p",
    #     "--port", dest="port", type='int', default=9200, help='TCP or UDP port for splunk host, defaults to 9200')

    # ??
    # p.add_option(
    #     "-i",
    #     "--index", dest="index", default=None, help='Json file with index details, defaults to None')

    # fixed
    # p.add_option(
    #     "-v",
    #     "--version", dest="version", default='1.1.0', help='api version field, defaults to 1.1.0')
    # only json
    # p.add_option(
    #     "-d",
    #     "--dataformat", dest="dataformat", default='json', help='requested api dataformat, json or csv, defaults to json')
    # -r :port does it
    # p.add_option(
    #     "-P",
    #     "--Port", dest="Port", type='int', default=0, help='TCP or UDP port for syslog daemonized listening, defaults to 0 - skip and exit')
    # not used, no buffering
    # p.add_option(
    #     "-e",
    #     "--eps", dest="eps", type='int', default=500, help='events per second, if set to a value larger then 0 throttling will be applied, defaults to 500')

    # Command line flags to override properties
    Config._flags.update(dict(
        customer=('-c',
                  'customer field, defaults to Bitglass'),
        api_url=('-r',
                 'url for portal access or syslog ":port" to listen on, required'),
        sink_url=('-n',
                  'send output messages over url, TCP socket, UDP syslog (default "0.0.0.0:514") or stdout'),
        log_types=('-t',
                   'logtype field "[cloudsummary:][access:][admin:]cloudaudit"'),
        _username=('-u',
                   'user name for portal access'),
        _password=('-k',
                   'password for portal access'),
        # extra
        _auth_token=('-a',
                     'OAuth 2 token for portal access'),
        log_interval=('-d',
                      'log interval, seconds'),
        log_initial=('-i',
                     'log initial period, seconds'),
        # - TODO proxies
        # - ?? method
    )
    )

    def __init__(self):

        self.status = {'updateCount': 0, 'last': Status()}
        for log_type in log_types:
            self.status[log_type] = Status()

        # Can't keep it here b/c of deepcopying
        #self._condition = condition

        # Load some (useful) hard-coded defaults
        source = 0
        self._auth_type = False
        self._use_proxy = False
        self.host = sources[source][0]
        self.api_ver = self._api_version_max
        self.auth_type = sources[source][1]
        self._auth_token = Password('auth_token')
        self._username = ''
        self._password = Password('password')
        #
        self.log_types = [log_types[0]]
        self.log_interval = 900
        # self.api_url        = 'https://portal.us.%s/api/bitglassapi/logs/' % self.host
        self.api_url = ''
        self.proxies = None
        self.sink_url = 'localhost:514'
        self._syslogDest = self.sink_url

        # Additional params not in the UI. Don't save for now
        self.log_initial = 30 * 24 * 3600
        self._max_request_rate = 10

        # Additional (optional) settings, not exposed in the UI for now
        self.method = None
        self.verify = True
        self.customer = 'Bitglass'
        self.useNextPageToken = True

        super(ConfigForward, self).__init__('forward.json', session)

        # Cut down requests for debugging
        if self._isEnabled('debug'):
            self.log_initial = 7 * 24 * 3600

        # Load secrets (if managing secure storage)
        if not self._isEnabled('splunk'):
            self._auth_token.load()
            self._password.load()

        # Sort any lists so can rely on bulk comparison
        self.log_types.sort()

    # From param dict to canonical string to load to UI

    def _printProxies(self, proxies):
        return str(proxies)\
            .replace(' ', '')\
            .replace("'", '')\
            .replace('"', '')\
            .replace('{', '')\
            .replace('}', '')\
            .replace(':', '=', 1)\
            if proxies is not None else ''

    # From user multi-string to detailed dict list

    def _parseProxies(self, s):
        proxies = []
        if s == '':
            return proxies

        pxs = s.replace('\r', '').split('\n')
        for p in pxs:
            # Skip all-whitespace lines
            if p.replace(' ', '') == '':
                continue

            proxy = {}
            try:
                # TODO Handle unicode data properly

                # Either = or : assignment, quotes are optional, username, password and port are optional
                # 'nttps=nttps;\\user;pass a*t 127 d*t 0 d*t 0 d*t 1;9999'
                # ^"?(https?|ftp)"?[ ]*(?:\=|\:)[ ]*"?(https?|socks5)\:\/\/(?:([a-zA-Z][-\w]*)(?:\:(\S*))?@)?([^\:]+)(?:\:([0-9]{2,5}))?"?$
                v = re.split(
                    r'^'
                    # schema
                    r'"?(https?|ftp)'
                    r'"?[ ]*(?:\=|\:)[ ]*"?'
                    # schema_p
                    r'(https?|socks5)\:\/\/'
                    # user + pswd (optional, must not contain ":@ )
                    r'(?:([a-zA-Z][-\w]*)(?:\:(\S*))?@)?'
                    # host
                    r'([^\:]+)'
                    # port (optional)
                    r'(?:\:([0-9]{2,5}))?"?'
                    r'$', p.strip())

                start = v[0]
                schema = v[1]
                schema_p = v[2]
                user = v[3] if v[3] is not None else ''
                pswd = v[4] if v[4] is not None else ''
                host = v[5]
                port = v[6] if v[6] is not None else ''
                end = v[7]

                if start != '' or end != '':
                    raise BaseException('Bad proxy expression')

                # Validate host separately
                if not self._matchHost(host):
                    raise BaseException('Bad host name "%s" in proxy expression' % host)

                if int(port) < 0 or int(port) > 65535:
                    raise BaseException('Bad port number in proxy expression')

                proxy = {'schema': schema, 'schema_p': schema_p, 'user': user, 'pswd': pswd, 'host': host, 'port': port}
                proxies.append(proxy)
            except BaseException as ex:
                raise ex
            except Exception as ex:
                raise BaseException('Bad proxy expression')
        return proxies

    # From user multi-string to param dict

    def _getProxies(self, s):
        proxies = {}
        pxd = self._parseProxies(s)
        for p in pxd:
            k = '%s' % p['schema']
            v = '%s://%s:%s@%s:%s' % (p['schema_p'], p['user'], p['pswd'], p['host'], p['port'])
            if v[-1] == ':':
                # Empty port
                v = v[0:-1]
            if ':@' in v:
                # Empty password
                v = v.replace(':@', '')
            if '/:' in v:
                # Empty user
                v = v.replace('/:', '')
            proxies[k] = v
        return proxies if proxies != {} else None

    def _updateAndWaitForStatus(self, condition, rform):
        # Get the user inputs (validated already)
        auth_token = str(rform['auth_token'])
        username = str(rform['username'])
        password = str(rform['password'])
        log_interval = int(rform['log_interval'])
        api_url = str(rform['api_url'])
        proxies = self._getProxies(str(rform['proxies']))
        sink_url = str(rform['sink_url'])

        # Override only the ones modified in the UI keeping the config ones in effect (if a different set)
        if PY2:
            # Membership 'in' operator fails unless same format (unlike ==)
            logTypes = [lt.decode('utf-8') for lt in self.log_types]
        else:
            logTypes = [lt for lt in self.log_types]

        # for lt in [u'access', u'admin', u'cloud_audit']:
        for lt in [u'access', u'admin', u'cloud_audit', u'swgweb', u'swgwebdlp']:
            log_type = lt.replace('_', '')
            if len(rform.getlist(lt)):
                if log_type not in logTypes:
                    logTypes += [log_type]
            else:
                if log_type in logTypes:
                    logTypes.remove(log_type)

        logTypes.sort()
        auth_type = True if len(rform.getlist('auth_type')) else False
        use_proxy = True if len(rform.getlist('use_proxy')) else False

        log(str('POST %s %s %s %s' % ('auth_token', ', '.join(logTypes), log_interval, api_url)), level='info')

        # Assume update is needed if first time
        isChanged = True
        if (self.updateCount > 0
                # Don't care b/c not saved anyways
                # and self._auth_type == True if auth_type == 'on' or auth_type == 'True' else False
                # and self._use_proxy == True if use_proxy == 'on' or use_proxy == 'True' else False
                #
                # Not saved but need to check authentication to update status
                and self._auth_token.secret == auth_token
                and self._username == username
                and self._password.secret == password
                #
                and self.log_types == logTypes
                and self.log_interval == log_interval
                and self.api_url == api_url
                and self.proxies == proxies
                and self.sink_url == sink_url):
            # return False
            isChanged = False

        # Update the data under thread lock
        # Do it to signal the poll thread to refresh the logs, even if no settings changed
        with self._lock(condition):
            self._auth_type = True if auth_type == 'on' or auth_type == 'True' else False
            self._use_proxy = True if (use_proxy == 'on' or use_proxy == 'True') and proxies is not None else False
            self._auth_token.secret = auth_token
            self._username = username
            self._password.secret = password
            self.log_types = logTypes
            self.log_interval = log_interval
            self.api_url = api_url
            self.proxies = proxies
            self.sink_url = sink_url

            self._calculateOptions()

        if isChanged:
            # Save across sessions
            self._save()

            # Wait for the update to come through but only if there were changes as a compromise.
            # If there are no changes the page info likely won't be up-to-date to avoid the wait,
            # refreshing multiple times would get the "latest" status eventually.
            # The wait time is a context switch + up to 3 (number of log types) API requests
            # TODO JS: The status could be updated continuously in the background AJAX-style
            self._waitForStatus()

        return isChanged

    def _parseApiUrl(self, url):
        badMatch = ''
        host = None
        api_ver = None

        # TODO Allow for localhost:514 etc. for the syslog option for the lss app flavor
        m = re.search(r'https\:\/\/portal\.((?:us\.)?.+)\/api\/bitglassapi(?:\/(?:logs(?:\/(?:\?cv=(\d\.\d\.\d))?)?)?)?', url)
        if m is None:
            return (badMatch, host, api_ver)

        if m.end() < len(url):
            badMatch = url[m.end():]
            return (badMatch, host, api_ver)

        h = m.group(1)
        if h is not None and self._matchHost(h):
            host = h

        v = m.group(2)
        if v is not None:
            api_ver = v

        return (badMatch, host, api_ver)

    def _calculateOptions(self):
        _, host, api_ver = self._parseApiUrl(self.api_url)

        if host is not None:
            self.host = host

        if api_ver is not None:
            self.api_ver = api_ver
        else:
            # Restore to default
            self.api_ver = self._api_version_max

        addr_host, addr_port = self.sink_url.split(':')
        if ('_qradarConsoleAddress' in self.__dict__ and
                (addr_host == 'localhost' or
                    addr_host == '127.0.0.1' or
                    # Workaround for a false security scan medium error
                    # addr_host == '0.0.0.0')):
                    ('.0.0.' in addr_host and addr_host[0] == '0' and addr_host[-1] == '0' and len(addr_host) == 7))):
            addr_host = self._qradarConsoleAddress
        self._syslogDest = (addr_host, int(addr_port))
