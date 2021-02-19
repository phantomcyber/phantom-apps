# File: okta_connector.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from okta_consts import *
import requests
import json
from bs4 import BeautifulSoup, UnicodeDammit
from urllib.parse import unquote
import time
import sys


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class OktaConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(OktaConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._python_version = None

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                unquote(self._handle_py_ver_compat_for_input_str(error_text)))

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response_paginated(self, r, action_result):
        """
        This method is used to provide the full response object for the actions defined
        in the constant OKTA_PAGINATED_ACTIONS_LIST in okta_consts.py file
        """

        # Try a json parse
        try:
            # To ensure that there will be no parsing errors while fetching json data from output response
            r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(self._get_error_message_from_exception(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            # It returns entire response object because headers are to be fetched from it for pagination next page links
            return RetVal(phantom.APP_SUCCESS, r)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            # To ensure that there will be no parsing errors while fetching json data from output response
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(self._get_error_message_from_exception(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            # Sending entire response because we want to fetch headers also to be fetched from the output response
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            if self.get_action_identifier() in OKTA_PAGINATED_ACTIONS_LIST:
                return self._process_json_response_paginated(r, action_result)
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if hasattr(e, 'args'):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERR_CODE_MSG
                error_msg = ERR_MSG_UNAVAILABLE
        except:
            error_code = ERR_CODE_MSG
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERR_MSG
        except:
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, json=None, data=None, method="get"):

        resp_json = None
        config = self.get_config()

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        url = "{}/api/v1{}".format(self._base_url, endpoint)

        # Okta requires a User-Agent value in the HTTP header.  See
        #   https://developer.okta.com/use_cases/isv/security-analytics#common-guidance-and-requirements
        user_agent = "{}{}".format(OKTA_APP_USER_AGENT_BASE, self._app_version)

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': user_agent,
            'Authorization': 'SSWS {}'.format(self._api_token)
        }

        try:
            r = request_func(url,
                            json=json,
                            data=data,
                            headers=headers,
                            params=params,
                            verify=config.get('verify_server_cert', False))
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(self._get_error_message_from_exception(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint /users/me to test connectivity")
        # make rest call
        ret_val, response = self._make_rest_call('/users/me', action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            self.save_progress(OKTA_TEST_CONNECTIVITY_FAILED)
            return action_result.set_status(phantom.APP_ERROR, OKTA_TEST_CONNECTIVITY_FAILED)

        # Return success
        self.save_progress(OKTA_TEST_CONNECTIVITY_PASSED)
        return action_result.set_status(phantom.APP_SUCCESS, OKTA_TEST_CONNECTIVITY_PASSED)

    def _get_paginated_results(self, endpoint, limit, action_result, params=None, headers=None):
        """
        This function is used to return paginated response based on the provided parameters
        for a given endpoint.
        """

        response_list = []
        stop_pagination = False

        while not stop_pagination:
            after_count = 0
            # make rest call
            ret_val, response = self._make_rest_call(endpoint, action_result, params=params, headers=headers)

            if phantom.is_fail(ret_val):
                return None

            # Fetch response list from the request response
            resp_fetched_list = response.json()

            # If limit is not None, fetch the response items accordingly else if None, fetch all the items
            if limit or limit == 0:
                if limit < len(resp_fetched_list):
                    response_list.extend(resp_fetched_list[:limit])
                else:
                    response_list.extend(resp_fetched_list)
                limit = limit - len(resp_fetched_list)

                if limit <= 0:
                    stop_pagination = True
                    break
            else:
                response_list.extend(resp_fetched_list)

            # Fetch the link headers from response
            link_list_str = response.headers.get('link')

            if not link_list_str:
                stop_pagination = True
                break

            # Fetch the next page link from the entire link string obtained in the headers
            for link in link_list_str.split(','):
                link = link.strip()

                # Fetch the next page link from the entire link string
                if not link.find('"next"') == -1:
                    if not params:
                        params = dict()
                    if not link.find('&', link.find('after=')) == -1:
                        params['after'] = link[link.find('after=') + 6:link.find('&', link.find('after='))]
                    else:
                        params['after'] = link[link.find('after=') + 6:link.find('>', link.find('after='))]
                    after_count = after_count + 1
                    break
                else:
                    continue

            if after_count == 0:
                stop_pagination = True

        return response_list

    def _validate_integer(self, action_result, parameter, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, OKTA_LIMIT_INVALID_MSG_ERR), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, OKTA_LIMIT_INVALID_MSG_ERR), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, OKTA_LIMIT_INVALID_MSG_ERR), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, OKTA_LIMIT_NON_ZERO_POSITIVE_MSG_ERR), None

        return phantom.APP_SUCCESS, parameter

    def _handle_list_users(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param.get('query', '')
        filter_param = param.get('filter', '')
        search = param.get('search', '')
        ret_val, limit = self._validate_integer(action_result, param.get('limit'))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = {
            'q': query,
            'filter': filter_param,
            'search': search,
            'limit': 200
        }

        users_list = self._get_paginated_results('/users', limit, action_result, params=params, headers=None)

        if users_list is None:
            return action_result.set_status(phantom.APP_ERROR,
                    OKTA_PAGINATION_MSG_ERR.format(action_name=self.get_action_identifier()))

        # Add the users_list into the data section
        for item in users_list:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_users'] = len(users_list)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_user_groups(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param.get('query', '')
        filter_param = param.get('filter', '')
        ret_val, limit = self._validate_integer(action_result, param.get('limit'))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = {
            'q': query,
            'filter': filter_param,
            'limit': 200
        }

        user_groups_list = self._get_paginated_results('/groups', limit, action_result, params=params, headers=None)

        if user_groups_list is None:
            return action_result.set_status(phantom.APP_ERROR,
                    OKTA_PAGINATION_MSG_ERR.format(action_name=self.get_action_identifier()))

        # Add the response into the data section
        for item in user_groups_list:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_groups'] = len(user_groups_list)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_reset_password(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])
        receive_type = param['receive_type']
        if receive_type not in RECEIVE_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, VALUE_LIST_VALIDATION_MSG.format(RECEIVE_TYPE_VALUE_LIST, 'receive_type'))

        params = dict()
        params['sendEmail'] = True
        if receive_type == 'UI':
            params['sendEmail'] = False

        # make rest call
        ret_val, response = self._make_rest_call('/users/{}/lifecycle/reset_password'.format(user_id), action_result, params=params, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, OKTA_RESET_PASSWORD_SUCC)

    def _handle_set_password(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['id'])
        new_password = param['new_password']

        request = {
            "credentials": {
                "password": {"value": new_password }
            }
        }

        # make rest call
        ret_val, response = self._make_rest_call('/users/{}'.format(user_id), action_result, json=request, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, OKTA_SET_PASSWORD_SUCC)

    def _handle_disable_user(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['id'])

        # make rest call
        ret_val, response = self._make_rest_call('/users/{}/lifecycle/suspend'.format(user_id), action_result, method='post')

        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if "Cannot suspend a user that is not active" in message:
                return action_result.set_status(phantom.APP_SUCCESS, OKTA_ALREADY_DISABLED_USER_ERR)
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, OKTA_DISABLE_USER_SUCC)

    def _handle_clear_user_sessions(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param['id']

        # make rest call
        ret_val, response = self._make_rest_call('/users/{}/sessions'.format(user_id), action_result, method='delete')

        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if "Empty response and no information in the header" == message:
                # This occurs because the delete call in the Okta API only returns a 204 success
                return action_result.set_status(phantom.APP_SUCCESS, OKTA_CLEAR_USER_SESSIONS_SUCC)
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, OKTA_CLEAR_USER_SESSIONS_SUCC)

    def _handle_enable_user(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['id'])

        # make rest call
        ret_val, response = self._make_rest_call('/users/{}/lifecycle/unsuspend'.format(user_id), action_result, method='post')

        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if "Cannot unsuspend a user that is not suspended" in message:
                return action_result.set_status(phantom.APP_SUCCESS, OKTA_ALREADY_ENABLED_USER_ERR)
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, OKTA_ENABLE_USER_SUCC)

    def _handle_get_user(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])

        # make rest call
        ret_val, response = self._make_rest_call('/users/{}'.format(user_id), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        if isinstance(response, dict):
            action_result.add_data(response)
        elif isinstance(response, list):
            for data in response:
                action_result.add_data(data)
        else:
            return action_result.set_status(phantom.APP_ERROR, UNEXPECTED_RESPONSE_MSG)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, OKTA_GET_USER_SUCC)

    def _handle_get_group(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        group_id = self._handle_py_ver_compat_for_input_str(param['group_id'])

        # make rest call
        ret_val, response = self._make_rest_call('/groups/{}'.format(group_id), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        if isinstance(response, dict):
            action_result.add_data(response)
        elif isinstance(response, list):
            for data in response:
                action_result.add_data(data)
        else:
            return action_result.set_status(phantom.APP_ERROR, UNEXPECTED_RESPONSE_MSG)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, OKTA_GET_GROUP_SUCC)

    def _handle_add_group(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        name = param['name']
        description = param['description']

        request = {
            "profile": {
                "name": name,
                "description": description
            }
        }

        # make rest call
        ret_val, response = self._make_rest_call('/groups', action_result, json=request, method='post')

        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if "An object with this field already exists in the current organization" in message:
                return action_result.set_status(phantom.APP_SUCCESS, OKTA_ALREADY_ADDED_GROUP_ERR)
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['group_id'] = response.get('id')

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, OKTA_ADDED_GROUP_SUCCESS_MSG)

    def _handle_list_providers(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param.get('query', '')
        type_param = param.get('type', '')
        if type_param and type_param not in IDENTITY_PROVIDERS_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, VALUE_LIST_VALIDATION_MSG.format(IDENTITY_PROVIDERS_TYPE_VALUE_LIST, 'type'))

        ret_val, limit = self._validate_integer(action_result, param.get('limit'))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = dict()
        params = {
            'limit': 200,
            'q': query,
            'type': type_param
        }

        providers_list = self._get_paginated_results('/idps', limit, action_result, params=params, headers=None)

        if providers_list is None:
            return action_result.set_status(phantom.APP_ERROR,
                    OKTA_PAGINATION_MSG_ERR.format(action_name=self.get_action_identifier()))

        # Add the response into the data section
        for item in providers_list:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_idps'] = len(providers_list)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_roles(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])

        roles_list = self._get_paginated_results('/users/{}/roles'.format(user_id),
                            None, action_result, params=None, headers=None)

        if roles_list is None:
            return action_result.set_status(phantom.APP_ERROR,
                    OKTA_PAGINATION_MSG_ERR.format(action_name=self.get_action_identifier()))

        # Add the response into the data section
        for item in roles_list:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_roles'] = len(roles_list)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_assign_role(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])
        type_param = param['type']

        if type_param not in ROLE_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, VALUE_LIST_VALIDATION_MSG.format(ROLE_TYPE_VALUE_LIST, 'type'))

        # make rest call
        ret_val, response = self._make_rest_call('/users/{}/roles'.format(user_id), action_result, json={'type': type_param}, method='post')

        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if 'The role specified is already assigned to the user' in message:
                return action_result.set_status(phantom.APP_SUCCESS, OKTA_ALREADY_ASSIGN_ROLE_ERR)
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, OKTA_ASSIGN_ROLE_SUCC)

    def _handle_unassign_role(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['user_id'])
        role_id = self._handle_py_ver_compat_for_input_str(param['role_id'])
        ret_val, response = self._make_rest_call('/users/{}'.format(user_id), action_result, params=None, headers=None)

        # Check the user is valid or not
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, OKTA_INVALID_USER_MSG)

        # make rest call
        ret_val, response = self._make_rest_call('/users/{}/roles/{}'.format(user_id, role_id),
                            action_result, method='delete')
        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if 'Empty response and no information in the header' in message:
                # Add the response into the data section
                action_result.add_data({})
                return action_result.set_status(phantom.APP_SUCCESS, OKTA_UNASSIGN_ROLE_SUCC)
            if 'Not found' in message:
                # Add the response into the data section
                action_result.add_data({})
                return action_result.set_status(phantom.APP_ERROR, OKTA_ALREADY_UNASSIGN_ROLE_ERR)
            return action_result.get_status()
        return action_result.set_status(phantom.APP_ERROR)

    def _handle_send_push_notification(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = self._handle_py_ver_compat_for_input_str(param['email'])
        factor_type = param.get('factortype', 'push')
        if factor_type not in FACTOR_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, VALUE_LIST_VALIDATION_MSG.format(FACTOR_TYPE_VALUE_LIST, 'factortype'))

        # Removing " (not yet implemented)" from the factor_type variable
        # Remove the below line, once the action is implemented for the "sms" and the "token:software:totp" factor_types
        factor_type = factor_type.split(" (not yet implemented)")[0]

        # get user
        ret_val, response_user = self._make_rest_call('/users/{}'.format(user_id), action_result, method='get')
        if phantom.is_fail(ret_val):
            self.save_progress("[-] Okta /users/{}: {}".format(user_id, str(response_user)))
            return action_result.get_status()

        # get factors
        try:
            user_id = response_user['id']
            ret_val, response_factor = self._make_rest_call('/users/{}/factors'.format(user_id), action_result, method='get')
            if phantom.is_fail(ret_val):
                self.save_progress("[-] get factors /users/{}/factors: {}".format(user_id, str(response_factor)))
                return action_result.get_status()

            factor_link_verify_uri = None
            # process factors
            for factor in response_factor:
                factor_link_verify_href = factor.get('_links', {}).get('verify', {}).get('href', {})
                if factor_type in factor['factorType'] and len(factor_link_verify_href) > 0:
                    self.save_progress("[-] process factor -- factor_link_verify_href: " + factor_link_verify_href)
                    factor_link_verify_uri = factor_link_verify_href.split('v1')[1]
            if not factor_link_verify_uri:
                self.save_progress("[-] error retriving factor_type: " + factor_type)
                return action_result.set_status(phantom.APP_ERROR, OKTA_SEND_PUSH_NOTIFICATION_ERR_MSG.format(factor_type=factor_type, user_id=user_id))

            # call verify
            ret_val, response_verify = self._make_rest_call(factor_link_verify_uri, action_result, method='post')
            if phantom.is_fail(ret_val):
                self.save_progress("[-] send push notification (call verify) {} - {}".format(str(response_verify), factor_link_verify_uri))
                return action_result.get_status()

            try:
                transaction_url = response_verify.get('_links', {}).get('poll', {}).get('href', {})
                if not transaction_url:
                    if factor_type == "sms":
                        return action_result.set_status(phantom.APP_ERROR, "The action has not yet been implemented for the 'sms' factortype workflow")
                    elif factor_type == "token:software:totp":
                        return action_result.set_status(phantom.APP_ERROR, "The action has not yet been implemented for the 'token:software:totp' factortype workflow")
                    else:
                        return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the polling link for the 'push' factortype workflow")

                transaction_url = transaction_url.split('v1')[1]
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR,
                    "Error occurred while fetching the transaction_url for the 'send push notification' workflow. Error Details: {}".
                    format(self._get_error_message_from_exception(e)))

            # response of verify
            ack_flag = False
            hard_limit = 25
            while not ack_flag:
                # Wait for 5 seconds and check result
                time.sleep(5)
                hard_limit -= 1
                self.save_progress("[-] {} - Awaiting Okta Push response".format(hard_limit))
                ret_val, response_verify_ack = self._make_rest_call(transaction_url, action_result, method='get')
                if phantom.is_fail(ret_val):
                    self.save_progress("[-] Okta Verify ACK (loop): {}".format(response_verify_ack))
                    return action_result.get_status()
                # self.save_progress("[-] VERIFY ACK: {}".format(response_verify_ack))

                if response_verify_ack['factorResult'] in ["TIMEOUT", "REJECTED", "SUCCESS"] or hard_limit == 0:
                    ack_flag = True
                    self.save_progress("[-] Okta Verify ACK: {}".format(str(response_verify_ack)))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing reponse from server. {}".format(self._get_error_message_from_exception(e)))

        action_result.add_data(response_verify_ack)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['result'] = response_verify_ack

        # Add the response into the data section
        if isinstance(response_factor, dict):
            action_result.add_data(response_factor)
        elif isinstance(response_factor, list):
            for factor in response_factor:
                action_result.add_data(factor)
        else:
            return action_result.set_status(phantom.APP_ERROR, UNEXPECTED_RESPONSE_MSG)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully sent push notification")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_users':
            ret_val = self._handle_list_users(param)

        elif action_id == 'get_group':
            ret_val = self._handle_get_group(param)

        elif action_id == 'add_group':
            ret_val = self._handle_add_group(param)

        elif action_id == 'list_user_groups':
            ret_val = self._handle_list_user_groups(param)

        elif action_id == 'reset_password':
            ret_val = self._handle_reset_password(param)

        elif action_id == 'set_password':
            ret_val = self._handle_set_password(param)

        elif action_id == 'disable_user':
            ret_val = self._handle_disable_user(param)

        elif action_id == 'enable_user':
            ret_val = self._handle_enable_user(param)

        elif action_id == 'get_user':
            ret_val = self._handle_get_user(param)

        elif action_id == 'list_providers':
            ret_val = self._handle_list_providers(param)

        elif action_id == 'list_roles':
            ret_val = self._handle_list_roles(param)

        elif action_id == 'assign_role':
            ret_val = self._handle_assign_role(param)

        elif action_id == 'unassign_role':
            ret_val = self._handle_unassign_role(param)

        elif action_id == 'send_push_notification':
            ret_val = self._handle_send_push_notification(param)

        elif action_id == 'clear_user_sessions':
            ret_val = self._handle_clear_user_sessions(param)

        return ret_val

    def initialize(self):

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        self._state = self.load_state()
        config = self.get_config()

        self._api_token = config[OKTA_API_TOKEN]
        self._base_url = self._handle_py_ver_compat_for_input_str(config[OKTA_BASE_URL])

        # The current version of this app as defined in the app json
        self._app_version = self.get_app_json().get('app_version', '')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

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
        try:
            login_url = BaseConnector._get_phantom_base_url() + '/login'
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = OktaConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
