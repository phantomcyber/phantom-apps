# File: ds_infrastructure_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import phantom.app as phantom
from phantom.action_result import ActionResult

from digital_shadows_consts import DS_API_KEY_CFG, DS_API_SECRET_KEY_CFG
from digital_shadows_consts import DS_GET_INFRASTRUCTURE_SUCCESS, DS_GET_INFRASTRUCTURE_NOT_FOUND
from digital_shadows_consts import DS_GET_INFRASTRUCTURE_SSL_SUCCESS, DS_GET_INFRASTRUCTURE_SSL_NOT_FOUND
from digital_shadows_consts import DS_GET_INFRASTRUCTURE_VULNERABILITIES_SUCCESS, DS_GET_INFRASTRUCTURE_VULNERABILITIES_NOT_FOUND

from dsapi.service.infrastructure_service import InfrastructureService
from dsapi.service.infrastructure_ssl_service import InfrastructureSSLService
from dsapi.service.infrastructure_vulnerabilities_service import InfrastructureVulnerabilitiesService


class DSInfrastructureConnector(object):

    def __init__(self, connector):
        """
        :param connector: DigitalShadowsConnector
        """
        self._connector = connector

        config = connector.get_config()
        self._ds_api_key = config[DS_API_KEY_CFG]
        self._ds_api_secret_key = config[DS_API_SECRET_KEY_CFG]

    def get_infrastructure_ip_ports(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        infrastructure_service = InfrastructureService(self._ds_api_key, self._ds_api_secret_key)
        infrastructure_view = InfrastructureService.infrastructure_view()
        infrastructure_pages = infrastructure_service.find_all_pages(view=infrastructure_view)

        infrastructure_total = len(infrastructure_pages)
        if infrastructure_total > 0:
            summary = {
                'infrastructure_count': infrastructure_total,
                'infrastructure_found': True
            }
            action_result.update_summary(summary)

            for infrastructure_page in infrastructure_pages:
                for infrastructure in infrastructure_page:
                    data = {
                        'id': infrastructure.id,
                        'ipAddress': infrastructure.ip_address,
                        'portNumber': str(infrastructure.port_number),
                        'transport': infrastructure.transport,
                        'discoveredOpen': infrastructure.discovered_open,
                        'incident': {
                            'id': infrastructure.incident_id,
                            'scope': infrastructure.incident_scope,
                            'type': infrastructure.incident_type,
                            'subType': infrastructure.incident_sub_type,
                            'severity': infrastructure.incident_severity,
                            'title': infrastructure.incident_title,
                        }
                    }
                    action_result.add_data(data)
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INFRASTRUCTURE_SUCCESS)
        else:
            summary = {
                'infrastructure_count': 0,
                'infrastructure_found': False
            }
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INFRASTRUCTURE_NOT_FOUND)
        return action_result.get_status()

    def get_infrastructure_ssl(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        infrastructure_ssl_service = InfrastructureSSLService(self._ds_api_key, self._ds_api_secret_key)
        infrastructure_ssl_view = InfrastructureSSLService.infrastructure_ssl_view()
        infrastructure_ssl_pages = infrastructure_ssl_service.find_all_pages(view=infrastructure_ssl_view)

        infrastructure_ssl_total = len(infrastructure_ssl_pages)
        if infrastructure_ssl_total > 0:
            summary = {
                'infrastructure_ssl_count': infrastructure_ssl_total,
                'infrastructure_ssl_found': True
            }
            action_result.update_summary(summary)

            for infrastructure_ssl_page in infrastructure_ssl_pages:
                for infrastructure_ssl in infrastructure_ssl_page:
                    data = {
                        'id': infrastructure_ssl.id,
                        'domainName': infrastructure_ssl.payload['domainName'],
                        'ipAddress': infrastructure_ssl.payload['ipAddress'],
                        'portNumber': infrastructure_ssl.payload['portNumber'],
                        'transport': infrastructure_ssl.payload['transport'],
                        'discovered': infrastructure_ssl.payload['discovered'],
                        'grade': infrastructure_ssl.payload['grade'],
                        'certificateCommonName': infrastructure_ssl.payload['certificateCommonName'],
                        'expires': infrastructure_ssl.payload['expires'],
                        'incident': {
                            'id': infrastructure_ssl.payload['incident']['id'],
                            'scope': infrastructure_ssl.payload['incident']['scope'],
                            'type': infrastructure_ssl.payload['incident']['type'],
                            'subType': infrastructure_ssl.payload['incident']['subType'],
                            'severity': infrastructure_ssl.payload['incident']['severity'],
                            'title': infrastructure_ssl.payload['incident']['title'],
                        }
                    }
                    action_result.add_data(data)
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INFRASTRUCTURE_SSL_SUCCESS)
        else:
            summary = {
                'infrastructure_ssl_count': 0,
                'infrastructure_ssl_found': False
            }
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INFRASTRUCTURE_SSL_NOT_FOUND)
        return action_result.get_status()

    def get_infrastructure_vulnerabilities(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        infrastructure_vulnerabilities_service = InfrastructureVulnerabilitiesService(self._ds_api_key, self._ds_api_secret_key)
        infrastructure_vulnerabilities_view = InfrastructureVulnerabilitiesService.infrastructure_vulnerabilities_view()
        infrastructure_vulnerabilities_pages = infrastructure_vulnerabilities_service.find_all_pages(view=infrastructure_vulnerabilities_view)

        infrastructure_vulnerabilities_total = len(infrastructure_vulnerabilities_pages)
        if infrastructure_vulnerabilities_total > 0:
            summary = {
                'infrastructure_vulnerabilities_count': infrastructure_vulnerabilities_total,
                'infrastructure_vulnerabilities_found': True
            }
            action_result.update_summary(summary)

            for infrastructure_vulnerabilities_page in infrastructure_vulnerabilities_pages:
                for infrastructure_vulnerabilities in infrastructure_vulnerabilities_page:
                    data = {
                        'id': infrastructure_vulnerabilities.id,
                        'reverseDomainName': infrastructure_vulnerabilities.payload['reverseDomainName'],
                        'ipAddress': infrastructure_vulnerabilities.payload['ipAddress'],
                        'cveId': infrastructure_vulnerabilities.payload['cveId'],
                        'discovered': infrastructure_vulnerabilities.payload['discovered'],
                        'determinedResolved': infrastructure_vulnerabilities.payload['determinedResolved'],
                        'incident': {
                            'id': infrastructure_vulnerabilities.payload['incident']['id'],
                            'scope': infrastructure_vulnerabilities.payload['incident']['scope'],
                            'type': infrastructure_vulnerabilities.payload['incident']['type'],
                            'subType': infrastructure_vulnerabilities.payload['incident']['subType'],
                            'severity': infrastructure_vulnerabilities.payload['incident']['severity'],
                            'title': infrastructure_vulnerabilities.payload['incident']['title'],
                            'published': infrastructure_vulnerabilities.payload['incident']['published'],
                            'closedSource': infrastructure_vulnerabilities.payload['incident']['closedSource'],
                        }
                    }
                    action_result.add_data(data)
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INFRASTRUCTURE_VULNERABILITIES_SUCCESS)
        else:
            summary = {
                'infrastructure_vulnerabilities_count': 0,
                'infrastructure_vulnerabilities_found': False
            }
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INFRASTRUCTURE_VULNERABILITIES_NOT_FOUND)
        return action_result.get_status()
