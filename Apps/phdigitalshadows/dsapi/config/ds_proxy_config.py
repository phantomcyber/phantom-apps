# File: ds_proxy_config.py
#
# Copyright (c) 2020-2021 Digital Shadows Ltd.
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
