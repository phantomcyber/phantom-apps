# File: ds_intelligence_incidents_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import phantom.app as phantom
from phantom.action_result import ActionResult
# from datetime import date, timedelta
# from unidecode import unidecode

from digital_shadows_consts import *

from dsapi.service.intelligence_incident_service import IntelligenceIncidentService
from exception_handling_functions import ExceptionHandling


class DSIntelligenceIncidentsConnector(object):

    def __init__(self, connector):
        """
        :param connector: DigitalShadowsConnector
        """
        self._connector = connector

        config = connector.get_config()
        self._handle_exception_object = ExceptionHandling()
        self._ds_api_key = config[DS_API_KEY_CFG]
        self._ds_api_secret_key = config[DS_API_SECRET_KEY_CFG]

    def get_intelligence_incident_by_id(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)
        try:
            intelligence_incident_service = IntelligenceIncidentService(self._ds_api_key, self._ds_api_secret_key)
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        intel_incident_id = param['intel_incident_id']
        # validate 'intel_incident_id' action parameter
        ret_val, intel_incident_id = self._handle_exception_object.validate_integer(action_result, intel_incident_id, INTEL_INCIDENT_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        try:
            intelligence_incident = intelligence_incident_service.find_intel_incident_by_id(intel_incident_id)
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(error_message))
        # intelligence_incident_total = len(intelligence_incident_pages)
        # if intelligence_incident_total > 0:
        if 'id' in intelligence_incident:
            summary = {
                'intelligence_incident_count': 1,
                'intelligence_incident_found': True
            }
            action_result.update_summary(summary)
            action_result.add_data(intelligence_incident)

            """
            for intelligence_incident_page in intelligence_incident_pages:
                for intelligence_incident in intelligence_incident_page:
                    data = {
                        'incident_id': intelligence_incident.id,
                        'type': intelligence_incident.payload['type'],
                        'severity': intelligence_incident.payload['severity'],
                        'title': intelligence_incident.payload['title'],
                        'summary': unidecode(intelligence_incident.payload['summary']),
                        'published': intelligence_incident.payload['published'],
                        'modified': intelligence_incident.payload['modified'],
                        'occurred': intelligence_incident.payload['occurred'],
                        'verified': intelligence_incident.payload['verified'],
                        'description': unidecode(intelligence_incident.payload['description']),
                        'entitysummary': {
                            'source': intelligence_incident.payload['entitySummary']['source'],
                            'summarytext': intelligence_incident.payload['entitySummary']['summarytext'] if 'summarytext' in intelligence_incident.payload['entitySummary'] else '',
                            'domain': intelligence_incident.payload['entitySummary']['domain'],
                            'sourceDate': intelligence_incident.payload['entitySummary']['sourceDate'],
                            'type': intelligence_incident.payload['entitySummary']['type']
                        }
                    }

                    action_result.add_data(data)
            """
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INTELLIGENCE_INCIDENT_SUCCESS)
        return action_result.get_status()

    def get_intel_incident_ioc_by_id(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        param_types = None if 'types' not in param else param.get('types').split(',')

        try:
            intelligence_incident_service = IntelligenceIncidentService(self._ds_api_key, self._ds_api_secret_key)
            intelligence_incident_view = IntelligenceIncidentService.intelligence_incident_ioc_view(types=param_types)
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        intel_incident_id = param['intel_incident_id']
        # validate 'intel_incident_id' action parameter
        ret_val, intel_incident_id = self._handle_exception_object.validate_integer(action_result, intel_incident_id, INTEL_INCIDENT_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            intelligence_incident_ioc_pages = intelligence_incident_service.find_intel_incident_ioc_by_id(intel_incident_id=intel_incident_id, view=intelligence_incident_view)
            intelligence_incident_ioc_total = len(intelligence_incident_ioc_pages)
            self._connector.save_progress("II IoC Total: {}".format(intelligence_incident_ioc_total))
        except StopIteration:
            error_message = 'No Incident review objects retrieved from the Digital Shadows API'
            return action_result.set_status(phantom.APP_ERROR, "Error Details: {0}".format(error_message))
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {}".format(error_message))
        if intelligence_incident_ioc_total > 0:
            summary = {
                'intelligence_incident_ioc_count': intelligence_incident_ioc_total,
                'intelligence_incident_ioc_found': True
            }
            action_result.update_summary(summary)

            for intelligence_incident_ioc_page in intelligence_incident_ioc_pages:
                for intelligence_incident_ioc in intelligence_incident_ioc_page:
                    self._connector.save_progress("loop id: {}".format(intelligence_incident_ioc.payload))
                    action_result.add_data(intelligence_incident_ioc.payload)

            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INTELLIGENCE_INCIDENT_SUCCESS)
        return action_result.get_status()

    def get_intelligence_incident(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        # interval_startdate = date.today() - timedelta(int(param['date_range']))
        date_ranges = param.get('date_range')
        incident_types = []
        if param.get('incident_types') is not None:
            param_incident_types = param.get('incident_types').split(',')

            for inc_type in param_incident_types:
                if inc_type == "DATA_LEAKAGE":
                    incident_types.append({'type': 'DATA_LEAKAGE', 'subTypes': DS_DL_SUBTYPE })
                if inc_type == "BRAND_PROTECTION":
                    incident_types.append({'type': 'BRAND_PROTECTION', 'subTypes': DS_BP_SUBTYPE })
                if inc_type == "INFRASTRUCTURE":
                    incident_types.append({'type': 'INFRASTRUCTURE', 'subTypes': DS_INFR_SUBTYPE })
                if inc_type == "PHYSICAL_SECURITY":
                    incident_types.append({'type': 'PHYSICAL_SECURITY', 'subTypes': DS_PS_SUBTYPE })
                if inc_type == "SOCIAL_MEDIA_COMPLIANCE":
                    incident_types.append({'type': 'SOCIAL_MEDIA_COMPLIANCE', 'subTypes': DS_SMC_SUBTYPE })
                if inc_type == "CYBER_THREAT":
                    incident_types.append({'type': 'CYBER_THREAT'})
        else:
            param_incident_types = None

        try:
            intelligence_incident_service = IntelligenceIncidentService(self._ds_api_key, self._ds_api_secret_key)
            intelligence_incident_view = IntelligenceIncidentService.intelligence_incidents_view(date_range=date_ranges, date_range_field='published', types=incident_types)
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        try:
            intelligence_incident_pages = intelligence_incident_service.find_all_pages(view=intelligence_incident_view)
            intelligence_incident_total = len(intelligence_incident_pages)
        except StopIteration:
            error_message = 'No IntelligenceIncident objects retrieved from the Digital Shadows API in page groups'
            return action_result.set_status(phantom.APP_ERROR, "Error Details: {0}".format(error_message))
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {}".format(error_message))
        if intelligence_incident_total > 0:
            summary = {
                'intelligence_incident_count': intelligence_incident_total,
                'intelligence_incident_found': True
            }
            action_result.update_summary(summary)
            for intelligence_incident_page in intelligence_incident_pages:
                for intelligence_incident in intelligence_incident_page:
                    action_result.add_data(intelligence_incident.payload)

            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INTELLIGENCE_INCIDENT_SUCCESS)
        return action_result.get_status()
