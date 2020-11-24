#
# Copyright (c) 2020 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import phantom.app as phantom
from phantom.action_result import ActionResult
# from datetime import date, timedelta

from digital_shadows_consts import DS_API_KEY_CFG, DS_API_SECRET_KEY_CFG
from digital_shadows_consts import DS_GET_INCIDENT_SUCCESS
from digital_shadows_consts import DS_DL_SUBTYPE, DS_BP_SUBTYPE, DS_INFR_SUBTYPE, DS_PS_SUBTYPE, DS_SMC_SUBTYPE

from dsapi.service.incident_service import IncidentService
from bs4 import UnicodeDammit
import json


class DSIncidentsConnector(object):

    def __init__(self, connector):
        """
        :param connector: DigitalShadowsConnector
        """
        self._connector = connector

        config = connector.get_config()
        self._ds_api_key = UnicodeDammit(config[DS_API_KEY_CFG]).unicode_markup.encode('utf-8')
        self._ds_api_secret_key = config[DS_API_SECRET_KEY_CFG]

    def get_incident_by_id(self, param):
        self._connector.debug_print('Starting get_incident_by_id function.')
        self._connector.debug_print('Action Parameters: {}'.format(param))

        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)
        self._connector.debug_print('Initial action_result dictionary: {}'.format(action_result.get_dict()))

        incident_service = IncidentService(self._ds_api_key, self._ds_api_secret_key)
        incident_id = param['incident_id']
        try:
            if isinstance(incident_id, float):
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in the 'incident_id' parameter")
            incident_id = int(incident_id)
        except:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in the 'incident_id' parameter")

        if incident_id < 0:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-negative integer value in the 'incident_id' parameter")

        try:
            incident = incident_service.find_incident_by_id(incident_id)
            self._connector.debug_print('Incident ID: {}'.format(incident_id))
            self._connector.debug_print('Incident Data: {}'.format(incident))
        except Exception as e:
            if hasattr(e, 'message'):
                error_message = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
            else:
                error_message = "Error message unavailable. Please check the asset configuration and|or action parameters."
            self._connector.debug_print('Error message is {}'.format(error_message))

            action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_message))
            self._connector.debug_print('Interim action_result dictionary after adding FAILURE status: {}'.format(action_result.get_dict()))
            return action_result.get_status()
        if 'id' in incident:
            summary = {
              'incident_found': True
            }
            self._connector.debug_print('Updating the action_result summary.')
            action_result.update_summary(summary)

            self._connector.debug_print('Adding the incident data to the action_result object.')
            action_result.add_data(incident)

            self._connector.debug_print('Interim action_result dictionary after adding data: {}'.format(action_result.get_dict()))

            action_result.set_status(phantom.APP_SUCCESS, DS_GET_INCIDENT_SUCCESS)
            self._connector.debug_print('Interim action_result dictionary after adding SUCCESS status: {}'.format(action_result.get_dict()))

        act_dict = action_result.get_dict()
        self._connector.debug_print('Final action_result dictionary: {}'.format(act_dict))
        self._connector.debug_print('Final preprocessed action_result dictionary: {}'.format(json.dumps(act_dict, indent=4)))
        return action_result.get_status()

    def get_incident_review_by_id(self, param):
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        incident_id = param['incident_id']
        try:
            if isinstance(incident_id, float):
                return action_result.set_status(phantom.APP_ERROR,
                                                "Please provide a valid integer value in the 'incident_id' parameter")
            incident_id = int(incident_id)
        except:
            return action_result.set_status(phantom.APP_ERROR,
                                            "Please provide a valid integer value in the 'incident_id' parameter")

        if incident_id < 0:
            return action_result.set_status(phantom.APP_ERROR,
                                            "Please provide a valid non-negative integer value in the 'incident_id' parameter")

        try:
            incident_service = IncidentService(self._ds_api_key, self._ds_api_secret_key)
            incident_reviews = incident_service.find_all_reviews(incident_id)
            incident_reviews_total = len(incident_reviews)
        except Exception as e:
            if hasattr(e, 'message'):
                error_message = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
            else:
                error_message = "Error message unavailable. Please check the asset configuration and|or action parameters."
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_message))
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

        incident_service = IncidentService(self._ds_api_key, self._ds_api_secret_key)
        incident_view = IncidentService.incidents_view(
            date_range=UnicodeDammit(param.get('date_range')).unicode_markup.encode('utf-8'),
            date_range_field='published', types=incident_types)
        self._connector.save_progress("incident view: {}".format(incident_view))
        try:
            incident_pages = incident_service.find_all_pages(view=incident_view)
            self._connector.save_progress("incident_pages next: {}".format(incident_pages))
            incident_total = len(incident_pages)
        except StopIteration:
            error_message = 'No Incident objects retrieved from the Digital Shadows API in page groups'
            return action_result.set_status(phantom.APP_ERROR, "Error Details: {0}".format(error_message))
        except Exception as e:
            if hasattr(e, 'message'):
                error_message = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
            else:
                error_message = "Error message unavailable. Please check the asset configuration and|or action parameters."
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_message))

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
        incident_service = IncidentService(self._ds_api_key, self._ds_api_secret_key)

        incident_id = param.get('incident_id')
        try:
            if isinstance(incident_id, float):
                return action_result.set_status(phantom.APP_ERROR,
                                                "Please provide a valid integer value in the 'incident_id' parameter")
            incident_id = int(incident_id)
        except:
            return action_result.set_status(phantom.APP_ERROR,
                                            "Please provide a valid integer value in the 'incident_id' parameter")

        if incident_id < 0:
            return action_result.set_status(phantom.APP_ERROR,
                                            "Please provide a valid non-negative integer value in the 'incident_id' parameter")
        post_data = {
          'note': param.get('review_note'),
          'status': param.get('review_status')
        }
        self._connector.save_progress("post_data: {}".format(post_data))
        try:
            response = incident_service.post_incident_review(post_data, incident_id=incident_id)
        except Exception as e:
            if hasattr(e, 'message'):
                error_message = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
            else:
                error_message = "Error message unavailable. Please check the asset configuration and|or action parameters."
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_message))
        self._connector.save_progress("response: {}".format(response))

        if response['message'] == "SUCCESS":
            summary = {
              'incident_reviews_status_code': response['status'],
              'incident_reviews_message': response['message']
            }
            action_result.update_summary(summary)
            action_result.add_data(response['content'][0])
            action_result.set_status(phantom.APP_SUCCESS, "Digital Shadows Incident review posted successfully")
        else:
            summary = {
              'incident_reviews_status_code': response['status'],
              'incident_reviews_message': response['message']
            }
            action_result.update_summary(summary)
            action_result.add_data(response['content'][0])
            action_result.set_status(phantom.APP_SUCCESS, "Error in incident review post request")
        return action_result.get_status()
