# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Originally Created by Thomas (Phantom)
# 11-11-2019
#   Added action on_poll to ingest alerts.
#   Added comments for all actions and made the code easier to follow by adding new lines.
#   Added default fields in the tanium_detect_consts.py

import requests
import json
from bs4 import BeautifulSoup
import hashlib
import pytz
from datetime import datetime
import time
from taniumdetect_consts import *
from bs4 import UnicodeDammit

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TaniumDetectConnector(BaseConnector):

    def __init__(self):
        super(TaniumDetectConnector, self).__init__()
        self._state = None
        self._base_url = None
        self.headers = []
        return

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})
        return RetVal(action_result.set_status(phantom.APP_ERROR, 'Empty response and no information in the header'), None)

    def _process_html_response(self, response, action_result):
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [ x.strip() for x in split_lines if x.strip() ]
            error_text = ('\n').join(split_lines)
        except:
            error_text = 'Cannot parse error details'

        message = ('Status Code: {0}. Data from server:\n{1}\n').format(status_code, error_text)
        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, ('Unable to parse JSON response. Error: {0}').format(str(e))), None)
        else:
            if 200 <= r.status_code < 399:
                return RetVal(phantom.APP_SUCCESS, resp_json)

        message = ('Error from server. Status Code: {0} Data from server: {1}').format(r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)
        if not r.text:
            return self._process_empty_response(r, action_result)

        message = ("Can't process response from server. Status Code: {0} Data from server: {1}").format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method='get', **kwargs):
        config = self.get_config()

        username = config.get('Username', '')
        password = config.get('Password', '')

        resp_json = None

        header = {'X-Requested-With': 'REST API',
           'Content-type': 'application/json',
           'Accept': 'application/json'}

        login_url = "{0}{1}".format(UnicodeDammit(self._base_url).unicode_markup.encode('utf-8'), TANIUM_DETECT_API_PATH_AUTH)

        try:
            req = requests.post(login_url, auth=(username, password), verify=False, headers=header)
            if req.status_code >= 200 and req.status_code <= 204:
                header['session'] = req.text
        except Exception as e:
            if e.message:
                try:
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                except:
                    error_msg = "Unknown error occurred. Please check the asset configuration and|or the action parameters."
            else:
                error_msg = "Unknown error occurred. Please check the asset configuration and|or the action parameters."
            return RetVal(action_result.set_status(phantom.APP_ERROR, ('Error Logging Into Server. Details: {0}').format(str(error_msg))), resp_json)
        else:
            try:
                request_func = getattr(requests, method)
            except AttributeError:
                return RetVal(action_result.set_status(phantom.APP_ERROR, ('Invalid method: {0}').format(method)), resp_json)

            url = self._base_url + TANIUM_DETECT_API_BASE_URL + endpoint
            try:
                r = request_func(url, auth=(username, password), verify=config.get('verify_server_cert', False), headers=header, **kwargs)
            except Exception as e:
                return RetVal(action_result.set_status(phantom.APP_ERROR, ('Error Connecting to server. Details: {0}').format(str(e))), resp_json)

        if r.headers:
            self.headers = r.headers

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        """ This function is used test connectivity to Tanium Detect
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress('Connecting to endpoint')

        ret_val, response = self._make_rest_call(TANIUM_DETECT_API_PATH_SOURCES, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress('Test Connectivity Failed.')
            return action_result.get_status()

        self.save_progress('Test Connectivity Passed')

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_get_suppression_rule(self, param):
        """ This function is used to get a specific suppression rule.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')

        endpoint = ('{}/{}').format(TANIUM_DETECT_API_PATH_SUPPRESSION_RULES, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to get suppression rule: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_create_suppression_rule(self, param):
        """ This function is used to create a suppression rule.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = param.get('config', '')
        description = param.get('description', '')
        inteldocid = param.get('inteldocid', '')

        try:
            if inteldocid:
                inteldocid = int(inteldocid)
        except ValueError as ve:
            return action_result.set_status("Please provide a valid integer in [inteldocid] action parameter. Error: {}".format(str(ve)))
        except Exception as e:
            return action_result.set_status("Error: {}".format(str(e)))

        name = UnicodeDammit(param['name']).unicode_markup.encode("utf-8")
        config = UnicodeDammit(config).unicode_markup.encode("utf-8")
        description = UnicodeDammit(description).unicode_markup.encode("utf-8")
        data = json.dumps(name + config + description + str(inteldocid))
        ret_val, response = self._make_rest_call(TANIUM_DETECT_API_PATH_SUPPRESSION_RULES, action_result, method='post', data=data, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to create suppression rule: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_list_suppression_rules(self, param):
        """ This function is used to list all the suppression rules.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = self._process_parameters(TANIUM_DETECT_API_PATH_SUPPRESSION_RULES, param)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to list suppression rules: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_delete_suppression_rule(self, param):
        """ This function is used to delete a specific suppression rule.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')

        endpoint = ('{}?id={}').format(TANIUM_DETECT_API_PATH_SUPPRESSION_RULES, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='delete', params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to delete suppression rule: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_get_source(self, param):
        """ This function is used to get a specific source configured to manage IOCs in the system.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')

        endpoint = ('{}/{}').format(TANIUM_DETECT_API_PATH_SOURCES, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to delete source: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_delete_source(self, param):
        """ This function is used to delete a source configured to manage IOCs in the system.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')

        endpoint = ('{}/{}').format(TANIUM_DETECT_API_PATH_SOURCES, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='delete', params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to delete source: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_list_sources(self, param):
        """ This function is used to list sources configured to manage IOCs in the system.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = self._process_parameters(TANIUM_DETECT_API_PATH_SOURCES, param)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to get source: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_get_sourcetype(self, param):
        """ This function is used to get a specific source type.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')

        endpoint = ('{}/{}').format(TANIUM_DETECT_API_PATH_SOURCE_TYPES, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to get source type: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_list_sourcetypes(self, param):
        """ This function is used to list source types.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._make_rest_call(TANIUM_DETECT_API_PATH_SOURCE_TYPES, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to list source types').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_get_notification_count(self, param):
        """ This function is used to get the count of notifications by day.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}

        if param.get('num_days'):
            params['n'] = param.get('num_days')

        if param.get('inteldocid'):
            params['inteldocid'] = param.get('inteldocid')

        if param.get('scanconfigid'):
            params['scanconfigid'] = param.get('scanconfigid')

        endpoint = self._process_parameters(TANIUM_DETECT_API_PATH_ALERTS_COUNT, params)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to get notification count: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_get_notification(self, param):
        """ This function is used to get a list notification.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = self._process_parameters(TANIUM_DETECT_API_PATH_NOTIFICATIONS, param)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to get notification: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_update_notification(self, param):
        """ This function is used to update an existing notification.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')
        state = param.get('state', '')

        endpoint = ('{}?id={}').format(TANIUM_DETECT_API_PATH_NOTIFICATIONS, id)

        data = json.dumps(state)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='put', data=data, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to update notification: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_list_notifications(self, param):
        """ This function is used to list all notifications.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = self._process_parameters(TANIUM_DETECT_API_PATH_NOTIFICATIONS, param)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to list notifications: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_delete_notification(self, param):
        """ This function is used to delete a notification.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')
        endpoint = ('{}?id={}').format(TANIUM_DETECT_API_PATH_NOTIFICATIONS, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='delete', params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to delete notification: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_modify_label(self, param):
        """ This function is used to modifiy an existing label.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')
        name = param.get('name')
        description = param.get('description')

        endpoint = ('{}?id={}').format(TANIUM_DETECT_API_PATH_LABELS, id)

        data = json.dumps(name + description)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='put', data=data, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to modify label: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_get_label(self, param):
        """ This function is used to get a specific label.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')

        endpoint = ('{}/{}').format(TANIUM_DETECT_API_PATH_LABELS, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to get label: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_delete_label(self, param):
        """ This function is used to delete a label.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')

        endpoint = ('{}/{}').format(TANIUM_DETECT_API_PATH_LABELS, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='delete', params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to delete label: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_create_label(self, param):
        """ This function is used to create a new label.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        name = param.get('name')
        description = param.get('description')

        data = json.dumps(name + description)

        ret_val, response = self._make_rest_call(TANIUM_DETECT_API_PATH_LABELS, action_result, method='post', data=data, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to create label: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_list_labels(self, param):
        """ This function is used to list the labels.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = self._process_parameters(TANIUM_DETECT_API_PATH_LABELS, param)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to list labels: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_get_intel(self, param):
        """ This function is used to get a specific intel document.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')
        endpoint = ('{}/{}').format(TANIUM_DETECT_API_PATH_INTELS, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to get intel: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_delete_intel(self, param):
        """ This function is used to delete an intel document for detections.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')

        endpoint = ('{}/{}').format(TANIUM_DETECT_API_PATH_INTELS, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='delete', params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to delete intel: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_list_intel(self, param):
        """ This function is used to list out the intel document for detections.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = self._process_parameters(TANIUM_DETECT_API_PATH_INTELS, param)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to list intel: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_get_counts_group(self, param):
        """ This function is used to get the count of alerts by a parameter (computerName or alternative values).
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = self._process_parameters(TANIUM_DETECT_API_PATH_ALERTS_COUNT, param)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to alert counts by group: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_get_alert_count(self, param):
        """ This function is used to get the number of alerts per day.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}
        if param.get('num_days'):
            params['n'] = param.get('num_days')
        if param.get('inteldocid'):
            params['inteldocid'] = param.get('inteldocid')
        if param.get('scanconfigid'):
            params['scanconfigid'] = param.get('scanconfigid')

        endpoint = self._process_parameters(TANIUM_DETECT_API_PATH_ALERTS_COUNT, params)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to get alert count: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_get_alert(self, param):
        """ This function is used to handle getting a specific alert.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')
        endpoint = ('{}/{}').format(TANIUM_DETECT_API_PATH_ALERTS, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to get alert: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_update_state(self, param):
        """ This function is used to handle updating the state alert(s).
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')
        state = param.get('state', '')

        endpoint = ('{}?id={}').format(TANIUM_DETECT_API_PATH_ALERTS, id)

        data = json.dumps(state)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='put', data=data, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to update state: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_list_alerts(self, param):
        """ This function is used to handle listing alert(s).
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        max_limit = TANIUM_DETECT_MAX_LIMIT
        self.save_progress('Getting alerts data')

        params = {}

        # If the limit is greater than the max_limit set it to the max_limit
        # Tanium Responds with a 400 error when the limit is greater than 500
        if param.get('limit') and param.get('limit') > max_limit:
            params['limit'] = max_limit
        elif param.get('limit') is None:
            params['limit'] = TANIUM_DETECT_DEFAULT_LIMIT

        endpoint = self._process_parameters(TANIUM_DETECT_API_PATH_ALERTS, params)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to get alerts: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alerts(self, param, limit, offset, sort, start_time, end_time, tz):
        """ This function is used to handle the on poll function to get alert(s).
        :param param: Dictionary of input parameters
        :param limit: Number of alerts to get
        :param page: Page number to get, for pagination
        :param sort: Sets the sorting of the alerts
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress('Getting alert data')

        # If the limit is greater than the max_limit set it to the max_limit
        # Tanium Responds with a 400 error when the limit is greater than 500
        if limit and limit > TANIUM_DETECT_MAX_LIMIT:
            param['limit'] = TANIUM_DETECT_MAX_LIMIT
        elif limit is None:
            param['limit'] = TANIUM_DETECT_DEFAULT_LIMIT
        else:
            param['limit'] = limit

        param['offset'] = offset
        param['sort'] = sort

        param['alertedAtFrom'] = self._convert_timestamp_to_string(start_time, tz)
        param['alertedAtUntil'] = self._convert_timestamp_to_string(end_time, tz)

        endpoint = self._process_parameters(TANIUM_DETECT_API_PATH_ALERTS, param)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to get alerts: {}').format(action_result.get_message()))
            return action_result.get_status(), None

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _convert_timestamp_to_string(self, timestamp, tz):
        """ This function is used to handle of timestamp converstion for on_poll action.
        :param timestamp: Epoch time stamp
        :param tz: Timezone configued in the Asset
        :return: datetime string
        """

        date_time = datetime.fromtimestamp(timestamp, pytz.timezone(tz))

        return (date_time.strftime('%Y-%m-%dT%H:%M:%S:%fZ'))

    def _handle_delete_alert(self, param):
        """ This function is used to handle deleting alert(s).
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')

        endpoint = ('{}?id={}').format(TANIUM_DETECT_API_PATH_ALERTS, id)

        ret_val, response = self._make_rest_call(endpoint, action_result, method='delete', params=None)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, ('Failed to delete alert: {}').format(action_result.get_message()))
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):
        """ This function is used to handle on_poll.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get the config to get timezone parameter
        config = self.get_config()

        # If timezone is not set then cancel. We need the timezone to set the correct query times for ingestion.
        try:
            tz = config.get('timezone')
        except:
            return action_result.set_status(phantom.APP_ERROR, "Asset configuration timezone is not set.")

        # Always sort by id
        # Use -id to sort descending
        sort = "id"

        limit = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))

        # End time is current time
        end_time = time.time()

        # If it is a manual poll or first run, ingest data from the last 1 hour
        if self.is_poll_now() or self._state.get('first_run', True):
            start_time = end_time - TANIUM_DETECT_HOUR_GAP

        # If it is a scheduled poll, ingest from last_ingestion_time
        else:
            start_time = self._state.get('last_ingestion_time', end_time - TANIUM_DETECT_HOUR_GAP)

        response_status, alerts_list = self._handle_get_alerts(param, limit, 0, sort, start_time, end_time, tz)

        if phantom.is_fail(response_status):
            return action_result.get_status()

        if alerts_list:
            self.save_progress('Ingesting {} Tanium Detect alerts'.format(len(alerts_list)))

            for alert in alerts_list:
                # Reset parameters dict
                param = dict()
                param['id'] = alert.get('intelDocId')

                self.save_progress('Gathering Tanium Intel data for artifacts')

                # Call /plugin/products/detect3/api/v1/intels?noLimit=true to get the name of the trigger of the alert.
                # We should use the name of the tigger in the event name when added to Phantom
                response_status, intel_list = self._handle_get_intel(param)

                if phantom.is_fail(response_status):
                    return action_result.get_status()

                # Copy the Intel data for to be added for the name of the containter / artifacts
                alert['intel'] = intel_list

                # Create a container for each alert
                container_creation_status, container_id = self._create_container(alert)

                if phantom.is_fail(container_creation_status) or not container_id:
                    self.debug_print('Error while creating artifacts for container with ID {container_id}. {error_msg}'.
                                format(container_id=container_id, error_msg=container_creation_status))
                    continue
                else:
                    # Create artifacts for specific alert
                    artifacts_creation_status, artifacts_creation_msg = self._create_artifacts(alert=alert,
                                                                                            container_id=container_id)

                    if phantom.is_fail(artifacts_creation_status):
                        self.debug_print('Error while creating artifacts for container with ID {container_id}. {error_msg}'.
                                        format(container_id=container_id, error_msg=artifacts_creation_msg))
        else:
            self.save_progress('No alerts found')

        # Store it into state_file, so that it can be used in next ingestion
        self._state['first_run'] = False
        self._state['last_ingestion_time'] = end_time

        return self.set_status(phantom.APP_SUCCESS)

    def _create_container(self, alert):
        """ This function is used to create the container in Phantom using alert data.
        :param alert: Data of single alert
        :return: status(success/failure), container_id
        """
        container_dict = dict()

        container_dict['name'] = '{computerName} - {alert_name}'.format(computerName=alert['computerName'], alert_name=alert['intel']['name'])
        container_dict['source_data_identifier'] = container_dict['name']
        container_dict['description'] = alert['intel']['description']

        container_creation_status, container_creation_msg, container_id = self.save_container(container=container_dict)

        if phantom.is_fail(container_creation_status):
            self.debug_print(container_creation_msg)
            self.save_progress('Error while creating container for alert {alert_name}. '
                               '{error_message}'.format(alert_name=alert['intel']['name'], error_message=container_creation_msg))
            return self.set_status(phantom.APP_ERROR)

        return self.set_status(phantom.APP_SUCCESS), container_id

    def _create_artifacts(self, alert, container_id):
        """ This function is used to create artifacts in given container using alert data.
        :param alert: Data of single alert
        :param container_id: ID of container in which we have to create the artifacts
        :return: status(success/failure), message
        """
        artifacts_list = []
        temp_dict = {}
        cef = {}

        # List to transform the data to CEF acceptable fields.
        transforms = {'computerName': 'sourceHostName', 'computerIpAddress': 'sourceAddress',
                    'fullpath': 'filePath', 'md5': 'fileHashMd5', 'sha1': 'fileHashSha1', 'sha256': 'fileHashSha256'}

        # Process the details section.
        details = json.loads(alert['details'])
        for detail in details['match']['properties'].items():
            if detail[0] in transforms:
                cef[transforms[detail[0]]] = detail[1]
            else:
                cef[detail[0]] = detail[1]

        # Process the rest of the alert
        for artifact_name, artifact_value in alert.items():
            if artifact_name in transforms:
                cef[transforms[artifact_name]] = artifact_value
            else:
                cef[artifact_name] = artifact_value

        # Add into artifacts dictionary if it is available
        if cef:
            temp_dict['cef'] = cef
            temp_dict['name'] = alert['intel']['name']
            temp_dict['container_id'] = container_id
            temp_dict['source_data_identifier'] = self._create_dict_hash(temp_dict)

        artifacts_list.append(temp_dict)

        create_artifact_status, create_artifact_msg, _ = self.save_artifact(temp_dict)

        if phantom.is_fail(create_artifact_status):
            return self.set_status(phantom.APP_ERROR), create_artifact_msg

        return self.set_status(phantom.APP_SUCCESS), 'Artifacts created successfully'

    def _create_dict_hash(self, input_dict):
        """ This function is used to generate the hash from dictionary.
        :param input_dict: Dictionary for which we have to generate the hash
        :return: hash
        """
        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str).hexdigest()

    def _process_parameters(self, endpoint, params):
        """ This function is used process the parameters and creates a valid endpoint URL.
        If parameters are passed but left blank then Tanium still tries to filter by those parameters, causing data to not be returned.

        :param endpoint: The endpoint we want to send data to
        :param param: Dictionary of input parameters
        :return: endpoint
        """
        first_param = True
        if len(params) > 0:
            endpoint += "?"
            for param, value in params.items():
                if isinstance(value, basestring):
                    value = UnicodeDammit(value).unicode_markup.encode("utf-8")
                if first_param:
                    endpoint += "{}={}".format(param, value)
                    first_param = False
                else:
                    endpoint += "&{}={}".format(param, value)
        else:
            self.save_progress('Error while processing parameters for endpoint {endpoint}. '
                               'No parameters to process!'.format(endpoint=endpoint))
            return self.set_status(phantom.APP_ERROR)

        return endpoint

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.
        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """
        self.debug_print('action_id', self.get_action_identifier())

        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'get_suppression_rule': self._handle_get_suppression_rule,
            'create_suppression_rule': self._handle_create_suppression_rule,
            'list_suppression_rules': self._handle_list_suppression_rules,
            'delete_suppression_rule': self._handle_delete_suppression_rule,
            'get_source': self._handle_get_source,
            'delete_source': self._handle_delete_source,
            'list_sources': self._handle_list_sources,
            'get_sourcetype': self._handle_get_sourcetype,
            'list_sourcetypes': self._handle_list_sourcetypes,
            'get_notification_count': self._handle_get_notification_count,
            'get_notification': self._handle_get_notification,
            'update_notification': self._handle_update_notification,
            'list_notifications': self._handle_list_notifications,
            'delete_notification': self._handle_delete_notification,
            'modify_label': self._handle_modify_label,
            'get_label': self._handle_get_label,
            'delete_label': self._handle_delete_label,
            'create_label': self._handle_create_label,
            'list_labels': self._handle_list_labels,
            'get_intel': self._handle_get_intel,
            'delete_intel': self._handle_delete_intel,
            'list_intel': self._handle_list_intel,
            'get_counts_group': self._handle_get_counts_group,
            'get_alert_count': self._handle_get_alert_count,
            'get_alert': self._handle_get_alert,
            'update_state': self._handle_update_state,
            'list_alerts': self._handle_list_alerts,
            'delete_alert': self._handle_delete_alert,
            'on_poll': self._handle_on_poll
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)
        return action_execution_status

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()
        self._base_url = config.get('base_url')
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print ("Accessing the Login page")
            response = requests.get(login_url, verify=False)
            csrftoken = response.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            response2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = response2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: {}".format(str(e)))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TaniumDetectConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
