# File: ds_incidents_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import phantom.app as phantom
from phantom.action_result import ActionResult
# from datetime import date, timedelta

from digital_shadows_consts import *

from dsapi.service.incident_service import IncidentService
from exception_handling_functions import ExceptionHandling
# import json


class DSIncidentsConnector(object):

    def __init__(self, connector):
        """
        :param connector: DigitalShadowsConnector
        """
        self._connector = connector

        config = connector.get_config()
        self._handle_exception_object = ExceptionHandling()
        self._ds_api_key = config[DS_API_KEY_CFG]
        self._ds_api_secret_key = config[DS_API_SECRET_KEY_CFG]

    def get_incident_by_id(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        try:
            incident_service = IncidentService(self._ds_api_key, self._ds_api_secret_key)
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        incident_id = param['incident_id']
        # validate 'incident_id' action parameter
        ret_val, incident_id = self._handle_exception_object.validate_integer(action_result, incident_id, INCIDENT_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            incident = incident_service.find_incident_by_id(incident_id)
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(error_message))
        if 'id' in incident:
            summary = {
              'incident_found': True
            }
            action_result.update_summary(summary)
            action_result.add_data(incident)
            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INCIDENT_SUCCESS)

        return action_result.get_status()

    def get_incident_review_by_id(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        incident_id = param['incident_id']
        # validate 'incident_id' action parameter
        ret_val, incident_id = self._handle_exception_object.validate_integer(action_result, incident_id, INCIDENT_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            incident_service = IncidentService(self._ds_api_key, self._ds_api_secret_key)
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        try:
            incident_reviews = incident_service.find_all_reviews(incident_id)
            incident_reviews_total = len(incident_reviews)
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(error_message))
        if incident_reviews_total > 0:
            summary = {
              'incident_reviews_count': incident_reviews_total,
              'incident_reviews_found': True
            }
            action_result.update_summary(summary)
            for incident_review in incident_reviews:
                action_result.add_data(incident_review)
            action_result.set_status(phantom.APP_SUCCESS, "Digital Shadows incident reviews fetched for the Incident ID: {}".format(incident_id))
        return action_result.get_status()

    def get_incident_list(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        # interval_startdate = date.today() - timedelta(int(param['date_range']))
        incident_types = []
        if param.get('incident_types') is not None:
            param_incident_types = str(param['incident_types']).split(',')
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
            incident_service = IncidentService(self._ds_api_key, self._ds_api_secret_key)
            incident_view = IncidentService.incidents_view(
                date_range=param.get('date_range'),
                date_range_field='published', types=incident_types)
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))
        self._connector.save_progress("incident view: {}".format(incident_view))
        try:
            incident_pages = incident_service.find_all_pages(view=incident_view)
            self._connector.save_progress("incident_pages next: {}".format(incident_pages))
            incident_total = len(incident_pages)
        except StopIteration:
            error_message = 'No Incident objects retrieved from the Digital Shadows API in page groups'
            return action_result.set_status(phantom.APP_ERROR, "Error Details: {0}".format(error_message))
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(error_message))

        if incident_total > 0:
            summary = {
                'incident_count': incident_total,
                'incident_found': True
            }
            action_result.update_summary(summary)
            self._connector.save_progress("incident_pages: {}".format(incident_pages))

            for incident_page in incident_pages:
                for incident in incident_page:
                    self._connector.save_progress('incident: {}'.format(incident.payload))
                    action_result.add_data(incident.payload)

            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INCIDENT_SUCCESS)
        return action_result.get_status()

    def post_incident_review(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)
        try:
            incident_service = IncidentService(self._ds_api_key, self._ds_api_secret_key)
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))

        incident_id = param.get('incident_id')
        # validate 'incident_id' action parameter
        ret_val, incident_id = self._handle_exception_object.validate_integer(action_result, incident_id, INCIDENT_ID_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        post_data = {
          'note': param.get('review_note'),
          'status': param.get('review_status')
        }
        self._connector.save_progress("post_data: {}".format(post_data))
        try:
            response = incident_service.post_incident_review(post_data, incident_id=incident_id)
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(error_message))
        self._connector.save_progress("response: {}".format(response))

        try:
            summary = {
                'incident_reviews_status_code': response['status'],
                'incident_reviews_message': response['message']
            }
            action_result.update_summary(summary)
            action_result.add_data(response['content'][0])
            if response['message'] == "SUCCESS":
                action_result.set_status(phantom.APP_SUCCESS, "Digital Shadows Incident review posted successfully")
            else:
                action_result.set_status(phantom.APP_SUCCESS, "Error in incident review post request")
        except Exception as e:
            error_message = self._handle_exception_object.get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching data from response. {}".format(error_message))

        return action_result.get_status()
