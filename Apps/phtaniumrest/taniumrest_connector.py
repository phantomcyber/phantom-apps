# File: taniumrest_connector.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from taniumrest_consts import *

import os
import sys
import requests
import json
from time import sleep
from bs4 import BeautifulSoup
from bs4 import UnicodeDammit


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TaniumRestConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TaniumRestConnector, self).__init__()

        self._state = None
        self._base_url = None
        self._username = None
        self._password = None
        self._verify = None
        self._session_id = None
        self._percentage = None

    def _handle_py_ver_compat_for_input_str(self, python_version, input_str):
        """
        This method returns the encoded|original string based on the Python version.

        :param python_version: Information of the Python version
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _get_error_message_from_exception(self, e):
        """ This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = "Error code unavailable"
                    error_msg = e.args[0]
            else:
                error_code = "Error code unavailable"
                error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."
        except:
            error_code = "Error code unavailable"
            error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(self._python_version, error_msg)
        except TypeError:
            error_msg = "Error occurred while connecting to the Tanium server. Please check the asset configuration and|or the action parameters."
        except:
            error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."

        return error_code, error_msg

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script and style from the HTML message
            for element in soup(["script", "style"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                self._handle_py_ver_compat_for_input_str(self._python_version, error_text))

        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = "Error while connecting to the server"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        try:
            if resp_json.get('text'):
                message = "Error from server. Status Code: {0} Data from \
                    server: {1}".format(r.status_code, self._handle_py_ver_compat_for_input_str(self._python_version, resp_json.get('text')))
            else:
                message = "Error from server. Status Code: {0} Data from server: {1}".format(
                        r.status_code, self._handle_py_ver_compat_for_input_str(self._python_version, r.text.replace('{', '{{').replace('}', '}}')))
        except Exception:
            message = "Error from server. Status Code: {0}. Please provide valid input".format(r.status_code)

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
                r.status_code, self._handle_py_ver_compat_for_input_str(self._python_version, r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, verify=True, headers=None, params=None, data=None, json=None, method="get"):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            r = request_func(endpoint, json=json, data=data, headers=headers, verify=verify, params=params)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error occurred while making the REST call to the Tanium server. Error Code: {0}. Error Message: {1}"
                    .format(error_code, error_msg)), None)

        return self._process_response(r, action_result)

    def _make_rest_call_helper(self, action_result, endpoint, verify=True, headers=None, params=None, data=None, json=None, method="get"):
        """ Function that helps setting REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        url = "{0}{1}".format(self._base_url, endpoint)
        if headers is None:
            headers = {}

        if not self._session_id:
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        headers.update({
                'session': str(self._session_id),
                'Content-Type': 'application/json'
            })

        ret_val, resp_json = self._make_rest_call(url, action_result, verify=verify, headers=headers, params=params, data=data, json=json, method=method)

        # If token is expired, generate a new token
        msg = action_result.get_message()

        if msg and ("403" in msg or "401" in msg):
            self.debug_print("Refreshing Tanium API and re-trying request to [{0}] because API token was expired or invalid with error code [{1}]".format(url, msg))
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                self.debug_print("Attempt to refresh Tanium API session token failed!")
                return action_result.get_status(), None

            headers.update({'session': str(self._session_id), 'Content-Type': 'application/json'})

            ret_val, resp_json = self._make_rest_call(url, action_result, verify=verify, headers=headers, params=params, data=data, json=json, method=method)

        if phantom.is_fail(ret_val):
            self.debug_print("REST API Call Failure! Failed call to Tanium API endpoint {0} with error code {1}".format(url, msg))
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _get_token(self, action_result, from_action=False):
        """ This function is used to get a token via REST Call.

        :param action_result: Object of action result
        :param from_action: Boolean object of from_action
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        data = {
            'username': self._username,
            'password': self._password
        }
        headers = {
            'Content-Type': 'application/json'
        }

        ret_val, resp_json = self._make_rest_call("{}{}".format(self._base_url, SESSION_URL), action_result, verify=self._verify, headers=headers, json=data, method='post')

        if (phantom.is_fail(ret_val)):
            self.debug_print("Failed to fetch a session token from Tanium API!")
            self.save_progress("Failed to fetch a session token from Tanium API!")
            self._state['session_id'] = None
            self._session_id = None
            self.save_state(self._state)
            return action_result.get_status()

        self._state['session_id'] = resp_json.get('data', {}).get('session')
        self._session_id = resp_json.get('data', {}).get('session')
        self.save_state(self._state)

        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")

        ret_val = self._get_token(action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()
        # make rest call
        ret_val, response = self._make_rest_call_helper(action_result, TANIUMREST_GET_SAVED_QUESTIONS, verify=self._verify, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_questions(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        if param.get('list_saved_questions', False):
            summary_txt = "num_saved_questions"
            ret_val, response = self._make_rest_call_helper(action_result, TANIUMREST_GET_SAVED_QUESTIONS, verify=self._verify, params=None, headers=None)
        else:
            summary_txt = "num_questions"
            ret_val, response = self._make_rest_call_helper(action_result, TANIUMREST_GET_QUESTIONS, verify=self._verify, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        question_list = list()

        # Add the response into the data section
        for question in response.get("data", []):

            if question.get("id") and not param.get('list_saved_questions', False) and question.get('query_text') not in question_list:
                question_list.append(question.get('query_text'))
                action_result.add_data(question)

            if question.get("id") and param.get('list_saved_questions', False):
                action_result.add_data(question)

        summary = action_result.update_summary({})
        summary[summary_txt] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_response_data(self, response_data, action_result, tanium_content):

        if isinstance(response_data, list):
            if len(response_data) != 1:
                action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the {}".format(tanium_content))
                return None
            elif not isinstance(response_data[0], dict):
                action_result.set_status(phantom.APP_ERROR, "Unexpected API response")
                return None
            else:
                return response_data[0]

        elif isinstance(response_data, dict):
            return response_data

        else:
            action_result.set_status(phantom.APP_ERROR, "Unexpected API response")
            return None

    def _execute_action_support(self, param, action_result):
        action_grp = self._handle_py_ver_compat_for_input_str(self._python_version, param['action_group'])
        package_name = self._handle_py_ver_compat_for_input_str(self._python_version, param['package_name'])
        action_name = param['action_name']
        expire_seconds = param['expire_seconds']
        package_parameter = param.get('package_parameters', None)
        distribute_seconds = param.get('distribute_seconds', None)
        issue_seconds = param.get('issue_seconds', None)
        group_name = param.get('group_name')

        if group_name:
            group_name = self._handle_py_ver_compat_for_input_str(self._python_version, group_name)

        if expire_seconds is not None:
            try:
                expire_seconds = int(expire_seconds)
            except:
                return action_result.set_status(phantom.APP_ERROR, TANIUMREST_ERR_INVALID_PARAM.format(param="expire_seconds"))

            if expire_seconds <= 0:
                return action_result.set_status(phantom.APP_ERROR, TANIUMREST_ERR_INVALID_PARAM.format(param="expire_seconds"))

        if distribute_seconds is not None:
            try:
                distribute_seconds = int(distribute_seconds)
            except:
                return action_result.set_status(phantom.APP_ERROR, TANIUMREST_ERR_INVALID_PARAM.format(param="distribute_seconds"))

            if distribute_seconds <= 0:
                return action_result.set_status(phantom.APP_ERROR, TANIUMREST_ERR_INVALID_PARAM.format(param="distribute_seconds"))

        if issue_seconds is not None:
            try:
                issue_seconds = int(issue_seconds)
            except:
                return action_result.set_status(phantom.APP_ERROR, TANIUMREST_ERR_INVALID_PARAM.format(param="issue_seconds"))

            if issue_seconds <= 0:
                return action_result.set_status(phantom.APP_ERROR, TANIUMREST_ERR_INVALID_PARAM.format(param="issue_seconds"))

        # Get the package details
        endpoint = TANIUMREST_GET_PACKAGE.format(package=package_name)
        ret_val, response = self._make_rest_call_helper(action_result, endpoint, verify=self._verify, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        response_data = response.get("data")

        if not response_data:
            return action_result.set_status(phantom.APP_ERROR, "No package exists with name {}. \
                    Also, please verify that your account has sufficient permissions to access the packages".format(package_name))

        resp_data = self._get_response_data(response_data, action_result, "package")

        if resp_data is None:
            return action_result.get_status()

        package_id = resp_data.get("id")

        self.debug_print("Fetching parameter definition of the package")
        parameter_definition = response.get("data", {}).get("parameter_definition")

        if parameter_definition is not None:
            self.debug_print("Parameter definition fetched successfully")

        try:
            if parameter_definition and not isinstance(parameter_definition, dict):
                parameter_definition = json.loads(parameter_definition)
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, "Error while fetching package details. Error: {0}".format(str(e)))

        if parameter_definition and len(parameter_definition.get("parameters")) != 0:
            self.debug_print("Provided package is a parameterized package")
            if package_parameter is None:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide the required package parameter in the following format\
                    :- [{"<parameter_label_1>": "<parameter_value_1>"}, {"<parameter_label_2>": "<parameter_value_2>"}]')

            try:
                package_parameter = json.loads(package_parameter)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error while parsing the 'package_parameter' field. Error: {0}".format(str(e)))

            if len(package_parameter) != len(parameter_definition.get("parameters")):
                return action_result.set_status(phantom.APP_ERROR, "Please provide all the required package parameters in 'package_parameter' parameter")

            param_list = list()
            invalid_keys = list()
            for param in parameter_definition.get("parameters"):
                param_list.append(param.get("key"))

            for key in list(package_parameter.keys()):
                if key not in param_list:
                    invalid_keys.append(key)

            if invalid_keys:
                return action_result.set_status(phantom.APP_ERROR, "The following key(s) are incorrect: {}. Please provide correct key(s)".format(', '.join(invalid_keys)))

        data = dict()
        package_param = dict()
        package_spec = {
            "source_id": package_id
        }
        if package_parameter and parameter_definition and len(parameter_definition.get("parameters")) != 0:
            for parameter_key, parameter_value in list(package_parameter.items()):
                package_param.update({"key": parameter_key, "value": parameter_value})

            package_spec.update({"parameters": [package_param]})

        if group_name:
            endpoint = "{}/{}".format("/api/v2/groups/by-name", group_name)
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, verify=self._verify, params=None, headers=None)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            response_data = response.get("data")

            if not response_data:
                return action_result.set_status(phantom.APP_ERROR, "No group exists with name {}. \
                        Also, please verify that your account has sufficient permissions to access the groups".format(group_name))

            resp_data = self._get_response_data(response_data, action_result, "group")

            if resp_data is None:
                return action_result.get_status()

            group_id = resp_data.get("id")
            group_name = resp_data.get("name")
            data["target_group"] = {"source_id": group_id, "name": str(group_name)}

        # Get the action group details
        endpoint = TANIUMREST_GET_ACTION_GROUP.format(action_group=action_grp)

        ret_val, response = self._make_rest_call_helper(action_result, endpoint, verify=self._verify, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        response_data = response.get("data")

        if not response_data:
            return action_result.set_status(phantom.APP_ERROR, "No action group exists with name {}. \
                    Also, please verify that your account has sufficient permissions to access the action groups".format(action_grp))

        resp_data = self._get_response_data(response_data, action_result, "action group")

        if resp_data is None:
            return action_result.get_status()

        action_group_id = resp_data.get("id")

        data["action_group"] = {
            "id": action_group_id
        }
        data["package_spec"] = package_spec
        data["name"] = action_name
        data["expire_seconds"] = expire_seconds

        if distribute_seconds:
            data['distribute_seconds'] = distribute_seconds

        if issue_seconds:
            data["issue_seconds"] = issue_seconds

        # make rest call
        ret_val, response = self._make_rest_call_helper(action_result, TANIUMREST_EXECUTE_ACTION, verify=self._verify, params=None, headers=None, json=data, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response.get('data'))
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully executed the action")

    def _handle_execute_action(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        self._execute_action_support(param, action_result)

        return action_result.get_status()

    def _question_result(self, timeout_seconds, results_percentage, endpoint, action_result):

        max_range = int(timeout_seconds / WAIT_SECONDS) + (1 if timeout_seconds % WAIT_SECONDS == 0 else 2)

        for i in range(1, max_range):
            if timeout_seconds > WAIT_SECONDS:
                if i == max_range - 1:
                    sleep(timeout_seconds - (i - 1) * WAIT_SECONDS - 1)
                else:
                    sleep(WAIT_SECONDS)
            else:
                sleep(timeout_seconds - 1)

            ret_val, response = self._make_rest_call_helper(action_result, endpoint, verify=self._verify, params=None, headers=None)

            if (phantom.is_fail(ret_val)):
                return None

            # Checking to see if all the results have been returned by the question. Keeps questioning until all results have been returned.
            question_id = os.path.basename(endpoint)
            self.debug_print("Checking if Tanium question ID {} has completed and returned all results . . .".format(question_id))
            mr_tested = response.get("data", {}).get("result_sets", [])[0].get("mr_tested")
            estimated_total = response.get("data", {}).get("result_sets", [])[0].get("estimated_total")
            if mr_tested and estimated_total:
                percentage_returned = float(mr_tested) / float(estimated_total) * 100
                self.debug_print("mr_tested: {} | est_total: {} | perc_returned: {} | results_perc: {}".format(mr_tested, estimated_total, percentage_returned, results_percentage))
                if int(percentage_returned) < int(results_percentage):
                    self.debug_print("Tanium question ID {} is {}% done out of {}%. Fetching more results . . .".format(question_id, percentage_returned, results_percentage))
                    continue
            else:
                continue

            if response.get("data", {}).get("result_sets", [])[0].get("columns"):
                return response

        else:
            action_result.set_status(phantom.APP_ERROR, "Error while fetching the results from the Tanium server in '{}' expire seconds. Please try increasing the timeout value."
                                        .format(timeout_seconds))
            return None

    def _handle_list_processes(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        # config = self.get_config()

        sensor_name = param['sensor']
        group_name = param.get('group_name')
        if group_name:
            group_name = self._handle_py_ver_compat_for_input_str(self._python_version, group_name)
        timeout_seconds = param.get('timeout_seconds', 600)

        if timeout_seconds == 0 or (timeout_seconds and (not str(timeout_seconds).isdigit() or timeout_seconds <= 0)):
            return action_result.set_status(phantom.APP_ERROR, TANIUMREST_ERR_INVALID_PARAM.format(param="timeout_seconds"))

        data = dict()
        data["expire_seconds"] = timeout_seconds

        if group_name:
            endpoint = "{}/{}".format("/api/v2/groups/by-name", group_name)
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, verify=self._verify, params=None, headers=None)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            response_data = response.get("data")

            if not response_data:
                return action_result.set_status(phantom.APP_ERROR, "No group exists with name {}. \
                        Also, please verify that your account has sufficient permissions to access the groups".format(group_name))

            resp_data = self._get_response_data(response_data, action_result, "group")

            if resp_data is None:
                return action_result.get_status()

            group_id = resp_data.get("id")
            data["context_group"] = {"id": group_id}

        select_list = list()
        sensor_dict = dict()
        sensor_dict["sensor"] = {"name": sensor_name}
        select_list.append(sensor_dict)
        data["selects"] = select_list

        # Ask the 'List Processes' question to Tanium
        ret_val, response = self._make_rest_call_helper(action_result, "/api/v2/questions", verify=self._verify, params=None, headers=None, json=data, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now that the question has been processed, fetch the results from the Tanium API
        question_id = response.get("data", {}).get("id")
        self.debug_print("Successfully queried Tanium for list_proccesses action, got question results id {0}".format(question_id))
        endpoint = "{}/{}".format("/api/v2/result_data/question", question_id)

        response = self._question_result(timeout_seconds, int(self._percentage), endpoint, action_result)

        if response is None:
            self.debug_print("Warning! Tanium returned empty response for list_processes action")
            return action_result.get_status()

        action_result.add_data(response)

        result_sets = response.get("data", {}).get("result_sets")
        if result_sets:
            row_count = result_sets[0].get("row_count")
        else:
            self.debug_print("Warning! Tanium returned empty result set for list_processes action")
            row_count = 0

        summary = action_result.update_summary({})
        summary['num_results'] = row_count
        summary['timeout_seconds'] = timeout_seconds

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_terminate_process(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        self._execute_action_support(param, action_result)

        return action_result.get_status()

    def _handle_parse_question(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        query_text = param['query_text']
        data = {"text": query_text}

        ret_val, response = self._make_rest_call_helper(action_result, TANIUMREST_PARSE_QUESTION, verify=self._verify, params=None, headers=None, json=data, method="post")
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        parsed_questions = response.get("data", [])

        for question in parsed_questions:
            action_result.add_data(question)

        summary = action_result.update_summary({})
        summary['number_of_parsed_questions'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_query(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        query_text = self._handle_py_ver_compat_for_input_str(self._python_version, param.get('query_text'))
        group_name = param.get('group_name')
        if group_name:
            group_name = self._handle_py_ver_compat_for_input_str(self._python_version, group_name)
        timeout_seconds = param.get('timeout_seconds')

        if timeout_seconds == 0 or (timeout_seconds and (not str(timeout_seconds).isdigit() or timeout_seconds <= 0)):
            return action_result.set_status(phantom.APP_ERROR, TANIUMREST_ERR_INVALID_PARAM.format(param="timeout_seconds"))

        is_saved_question = param.get('is_saved_question', False)
        summary = action_result.update_summary({})

        if is_saved_question:
            endpoint = TANIUMREST_GET_SAVED_QUESTION.format(saved_question=query_text)

            ret_val, response = self._make_rest_call_helper(action_result, endpoint, verify=self._verify, params=None, headers=None)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            response_data = response.get("data")

            if not response_data:
                return action_result.set_status(phantom.APP_ERROR, "No saved question exists with name {}. \
                        Also, please verify that your account has sufficient permissions to access the saved questions".format(query_text))

            resp_data = self._get_response_data(response_data, action_result, "saved question")

            if resp_data is None:
                return action_result.get_status()

            saved_question_id = resp_data.get("id")

            endpoint = TANIUMREST_GET_SAVED_QUESTION_RESULT.format(saved_question_id=saved_question_id)

            response = self._question_result(timeout_seconds, int(self._percentage), endpoint, action_result)

            if response is None:
                return action_result.get_status()

            action_result.add_data(response)
        else:

            question_data = self._parse_manual_question(query_text, action_result, group_name=group_name or None)
            if not question_data:
                return action_result.get_status()

            self.save_progress(json.dumps(question_data))
            response = self._ask_question(question_data, action_result, timeout_seconds=timeout_seconds)
            if action_result.get_status() == phantom.APP_ERROR:
                return action_result.get_status()
            action_result.add_data(response)

        summary["timeout_seconds"] = timeout_seconds

        result_sets = response.get("data", {}).get("result_sets")
        if result_sets:
            row_count = result_sets[0].get("row_count")
        else:
            row_count = 0

        summary['number_of_rows'] = row_count

        return action_result.set_status(phantom.APP_SUCCESS)

    def _parameterize_query(self, query, action_result):
        """ Creates a data structure to send a parameterized sensor query to Tanium """
        sensors = [select["sensor"] for select in query["selects"]]
        self.save_progress("Sensors:\n" + json.dumps(sensors))
        # Set param index counter
        param_idx = 0
        total_params = 0
        param_list = query["parameter_values"]
        sensor_data = []

        for sensor in sensors:
            sensor_name = sensor["name"]
            endpoint = TANIUMREST_GET_SENSOR_BY_NAME.format(sensor_name=sensor_name)
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, verify=self._verify)
            if (phantom.is_fail(ret_val)):
                action_result.set_status(phantom.APP_ERROR, "Failed to get sensor definition from Tanium")
                return

            response_data = response.get("data")
            if not response_data:
                action_result.set_status(phantom.APP_ERROR, "No sensor exists with name {}. \
                        Please verify that your account has sufficient permissions to access the sensors".format(sensor_name))
                return

            resp_data = self._get_response_data(response_data, action_result, "sensor")
            if resp_data is None:
                return

            self.save_progress("Parameter Definition:\n" + resp_data.get("parameter_definition", ""))
            parameter_definition = json.loads(resp_data.get("parameter_definition", ""))

            if parameter_definition:
                # Parameterized Sensor
                parameter_keys = [parameter["key"] for parameter in parameter_definition["parameters"]]
                self.save_progress("Parameter Keys:\n" + json.dumps(parameter_keys))
                total_params += len(parameter_keys)
                parameters = []

                for key in parameter_keys:
                    if param_idx >= len(param_list):
                        action_result.set_status(phantom.APP_ERROR, "For parameters which you do not want to add value, please use double quotes(\"\").\
                                    For more details refer to the documentation")
                        return

                    parameter = {
                        "key": "||%s||" % key,
                        "value": param_list[param_idx] }
                    parameters.append(parameter)
                    param_idx += 1

                sensor_dict = {
                    "source_hash": sensor["hash"],
                    "parameters": parameters }
                sensor_data.append({"sensor": sensor_dict})
            else:
                # Regular Sensor, can use as-is
                sensor_data.append({"sensor": sensor})

        if total_params and total_params != len(param_list):
            action_result.set_status(phantom.APP_ERROR, "Please provide the exact number of parameters expected by the sensor")
            return

        self.save_progress("Sensor Data:\n" + json.dumps(sensor_data))
        question_data = { "selects": sensor_data,
                          "question_text": query["question_text"]}
        if "group" in query:
            # Add in filters
            question_data["group"] = query["group"]

        return question_data

    def _parse_manual_question(self, query_text, action_result, group_name=None):
        # Prepare data struction for posting to /questions
        data = dict()

        # If a group_name was supplied, validate the group name is valid
        if group_name:
            endpoint = "{}/{}".format("/api/v2/groups/by-name", group_name)
            ret_val, response = self._make_rest_call_helper(action_result, endpoint, verify=self._verify, params=None, headers=None)

            if (phantom.is_fail(ret_val)):
                action_result.set_status(phantom.APP_ERROR, "Failed to get group. Please provide a valid group name")
                return

            response_data = response.get("data")

            if not response_data:
                action_result.set_status(phantom.APP_ERROR, "No group exists with name {}. \
                        Also, please verify that your account has sufficient permissions to access the groups".format(group_name))
                return

            resp_data = self._get_response_data(response_data, action_result, "group")

            if resp_data is None:
                return

            group_id = resp_data.get("id")
            data["context_group"] = {"id": group_id}

        # Before executing the query, run the query text against the /parse_question
        #   to ensure the query is in a valid Tanium syntax
        query_to_parse = {"text": query_text}

        ret_val, response = self._make_rest_call_helper(action_result, "/api/v2/parse_question", verify=self._verify, params=None, headers=None,
                                                        json=query_to_parse, method="post")
        self.save_progress("Parsed Question:\n" + json.dumps(response))

        if (phantom.is_fail(ret_val)):
            self.debug_print("Failed to parse question")
            return

        if len(response.get("data")) != 1:
            action_result.set_status(phantom.APP_ERROR, "Please provide a valid parsed question accepted by Tanium server")
            return

        resp_text = response.get("data")[0].get("question_text", "").lower().replace('"', '').replace("'", "")
        query_text_updated = query_text.lower().replace('"', '').replace("'", "")

        if resp_text != query_text_updated:
            action_result.set_status(phantom.APP_ERROR, "Please provide a valid parsed question accepted by Tanium server")
            return

        if response["data"][0].get("parameter_values"):
            self.save_progress("Making a parameterized query")
            parameterized_data = self._parameterize_query(response.get("data")[0], action_result)
            if not parameterized_data:
                # Something failed
                return

            data.update(parameterized_data)
        else:
            self.save_progress("Making a non-parameterized query")
            data.update(response.get("data")[0])

        return data

    def _ask_question(self, data, action_result, timeout_seconds=None):
        # Post prepared data to questions endpoint and poll for results
        # config = self.get_config()
        if timeout_seconds:
            data['expire_seconds'] = timeout_seconds
        ret_val, response = self._make_rest_call_helper(action_result, "/api/v2/questions", verify=self._verify, params=None, headers=None, json=data, method="post")

        if (phantom.is_fail(ret_val)):
            action_result.set_status(phantom.APP_ERROR, "Question post failed")
            return

        self.save_progress("Data Posted to /questions:\n" + json.dumps(data))
        self.save_progress("Response from /questions:\n" + json.dumps(response))

        question_id = response.get("data", {}).get("id")

        # Get results of Question
        endpoint = "{}/{}".format("/api/v2/result_data/question", question_id)

        response = self._question_result(timeout_seconds, int(self._percentage), endpoint, action_result)

        if response is None:
            action_result.set_status(phantom.APP_ERROR, "Failed to get results")
        else:
            action_result.set_status(phantom.APP_SUCCESS)
        return response

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_processes':
            ret_val = self._handle_list_processes(param)

        elif action_id == 'execute_action':
            ret_val = self._handle_execute_action(param)

        elif action_id == 'list_questions':
            ret_val = self._handle_list_questions(param)

        elif action_id == 'terminate_process':
            ret_val = self._handle_terminate_process(param)

        elif action_id == 'run_query':
            ret_val = self._handle_run_query(param)

        elif action_id == 'parse_question':
            ret_val = self._handle_parse_question(param)

        return ret_val

    def initialize(self):

        self._state = self.load_state()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        config = self.get_config()
        self._username = self._handle_py_ver_compat_for_input_str(self._python_version, config['username'])
        self._password = config['password']
        self._verify = config['verify_server_cert']
        self._percentage = config.get('results_percentage', 99)

        try:
            if int(self._percentage) < 0 or int(self._percentage) > 100:
                return self.set_status(phantom.APP_ERROR, "Please provide a valid integer in range of 0-100 in [Consider question results complete at] configuration parameter")
        except:
            return self.set_status(phantom.APP_ERROR, "Please provide a valid integer in range of 0-100 in [Consider question results complete at] configuration parameter")

        self._base_url = self._handle_py_ver_compat_for_input_str(self._python_version, config['base_url'])

        # removing single occurence of trailing back-slash or forward-slash
        if self._base_url.endswith('/'):
            self._base_url = self._base_url.strip('/').strip('\\')
        elif self._base_url.endswith('\\'):
            self._base_url = self._base_url.strip('\\').strip('/')

        # removing single occurence of leading back-slash or forward-slash
        if self._base_url.startswith('/'):
            self._base_url = self._base_url.strip('/').strip('\\')
        elif self._base_url.startswith('\\'):
            self._base_url = self._base_url.strip('\\').strip('/')

        self._session_id = self._state.get('session_id', '')

        return phantom.APP_SUCCESS

    def finalize(self):

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

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = TaniumRestConnector._get_phantom_base_url() + '/login'

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
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TaniumRestConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
