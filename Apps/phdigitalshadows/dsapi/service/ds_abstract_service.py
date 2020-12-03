#
# Copyright (c) 2017 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from abc import ABCMeta
from httplib2 import Http, ProxyInfo, socks, proxy_info_from_environment

from dsapi.config.ds_proxy_config import DSProxyConfig


class DSAbstractService(object):
    """
    Abstract Service that provides http methods to implementing services.

    Proxy Settings - By default this class will use proxy settings from the environment.
    For more control, pass a DSProxyConfig object as the keyword argument 'proxy' to
    this class. The keyword argument will take precedence.
    """

    __metaclass__ = ABCMeta

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
