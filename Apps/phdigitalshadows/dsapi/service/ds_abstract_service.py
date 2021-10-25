# File: ds_abstract_service.py
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
from abc import ABCMeta
from ..httplib2 import Http, ProxyInfo, socks, proxy_info_from_environment

from dsapi.config.ds_proxy_config import DSProxyConfig


class DSAbstractService(object, metaclass=ABCMeta):
    """
    Abstract Service that provides http methods to implementing services.

    Proxy Settings - By default this class will use proxy settings from the environment.
    For more control, pass a DSProxyConfig object as the keyword argument 'proxy' to
    this class. The keyword argument will take precedence.
    """

    def __init__(self, proxy=None):
        if proxy is None:
            proxy = proxy_info_from_environment()
        else:
            proxy = self._prepare_proxy(proxy)

        self._http = Http(proxy_info=proxy)

    def _request(self, url, method='GET', body=None, headers=None):
        return self._http.request(url, method=method, body=body, headers=headers)

    def _prepare_proxy(self, ds_proxy_config):
        """
        Transform a DSProxyConfig object to httplib ProxyInfo object

        :type ds_proxy_config: DSProxyConfig
        :return: ProxyInfo
        """
        proxy_type_map = {
            DSProxyConfig.Type.HTTP: socks.PROXY_TYPE_HTTP,
            DSProxyConfig.Type.HTTP_NO_TUNNEL: socks.PROXY_TYPE_HTTP_NO_TUNNEL,
            DSProxyConfig.Type.SOCKS4: socks.PROXY_TYPE_SOCKS4,
            DSProxyConfig.Type.SOCKS5: socks.PROXY_TYPE_SOCKS5
        }
        return ProxyInfo(
            proxy_type=proxy_type_map[ds_proxy_config.proxy_type],
            proxy_host=ds_proxy_config.proxy_host,
            proxy_port=ds_proxy_config.proxy_port,
            proxy_rdns=ds_proxy_config.proxy_reverse_dns,
            proxy_user=ds_proxy_config.proxy_user,
            proxy_pass=ds_proxy_config.proxy_pass
        )
