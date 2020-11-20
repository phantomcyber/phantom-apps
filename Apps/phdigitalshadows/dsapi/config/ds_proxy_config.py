#
# Copyright (c) 2017 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#


class DSProxyConfig(object):

    class Type(object):
        HTTP = 'HTTP'
        HTTP_NO_TUNNEL = 'HTTP_NO_TUNNEL'
        SOCKS4 = 'SOCKS4'
        SOCKS5 = 'SOCKS5'

    def __init__(self, proxy_type, proxy_host, proxy_port,
                 proxy_reverse_dns=True, proxy_user=None, proxy_pass=None):
        """
        :type proxy_type: DSProxyConfig.Type
        :type proxy_host: str
        :type proxy_port: int
        :type proxy_reverse_dns: bool
        :type proxy_user: str
        :type proxy_pass: str
        """
        self._proxy_type = proxy_type
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._proxy_reverse_dns = proxy_reverse_dns
        self._proxy_user = proxy_user
        self._proxy_pass = proxy_pass

    @property
    def proxy_type(self):
        return self._proxy_type

    @property
    def proxy_host(self):
        return self._proxy_host

    @property
    def proxy_port(self):
        return self._proxy_port

    @property
    def proxy_reverse_dns(self):
        return self._proxy_reverse_dns

    @property
    def proxy_user(self):
        return self._proxy_user

    @property
    def proxy_pass(self):
        return self._proxy_pass
