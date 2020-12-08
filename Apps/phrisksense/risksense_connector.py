# --
# File: risksense_connector.py
#
# Copyright (c) RiskSense, 2020
#
# This unpublished material is proprietary to RiskSense.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of RiskSense.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from risksense_consts import *

import sys
import requests
import json
from bs4 import BeautifulSoup, UnicodeDammit


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class RisksenseConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(RisksenseConnector, self).__init__()

        self._state = None
        self._client_id = None
        self._session = None
        self._config = None
        self._python_version = None
        self._base_url = None

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

    def _get_error_message(self, resp_json):
        """
        This method is used to generate the error message from the response.

        :param resp_json: JSON formatted response data
        :return: Processed error message generated using keys and values of resp_json
        """

        message_list = list()
        errors = resp_json.get("errors")

        try:
            for key, value in list(resp_json.items()):
                if key != "errors":
                    msg = "{}: {}".format(key.capitalize(), self._handle_py_ver_compat_for_input_str(value))
                    message_list.append(msg)

            if errors:
                self.debug_print("Creating message from the 'errors' key present in the response")
                error_msg_list = list()

                if isinstance(errors, list):
                    for error in errors:
                        msg = "\"[Field: {}, Code: {}, Default Message: {}]\"".format(
                                error.get("field", "Field not found"),
                                error.get("code", "Code not found"),
                                self._handle_py_ver_compat_for_input_str(error.get("defaultMessage", "Default message not found")))

                        error_msg_list.append(msg)

                    error_msg = ", ".join(error_msg_list)

                elif isinstance(errors, dict):
                    for key, value in list(errors.items()):
                        msg = "{}: {}".format(key.capitalize(), self._handle_py_ver_compat_for_input_str(value))
                        error_msg_list.append(msg)

                    error_msg = "\"[{}]\"".format(", ".join(error_msg_list))

                else:
                    error_msg = "\"[{}]\"".format(self._handle_py_ver_compat_for_input_str(errors))

                message_list.append("Errors: {}".format(error_msg))
        except:
            self.debug_print("Error occurred while creating the message from the response")
            return None

        message = ",    ".join(message_list)

        return message

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if hasattr(e, 'args'):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = RISKSENSE_UNKNOWN_ERROR_CODE_MESSAGE
                    error_msg = e.args[0]
            else:
                error_code = RISKSENSE_UNKNOWN_ERROR_CODE_MESSAGE
                error_msg = RISKSENSE_UNKNOWN_ERROR_MESSAGE
        except:
            error_code = RISKSENSE_UNKNOWN_ERROR_CODE_MESSAGE
            error_msg = RISKSENSE_UNKNOWN_ERROR_MESSAGE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = RISKSENSE_UNICODE_DAMMIT_TYPE_ERROR_MESSAGE
        except:
            error_msg = RISKSENSE_UNKNOWN_ERROR_MESSAGE

        return error_code, error_msg

    def _process_empty_response(self, response, action_result):
        """ This method is used to process empty response.
        :param response: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200 or response.status_code == 204:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Status code: {}. Empty response and no information in the header".format(response.status_code)), None)

    def _process_html_response(self, response, action_result):
        """ This method is used to process html response.
        :param response: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")

            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()

            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        error_text = self._handle_py_ver_compat_for_input_str(error_text)

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        """ This function is used to process json response.
        :param r: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error Code: {0}. Error Message: {1}".format(error_code, error_msg)), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # Error handling and message generating for different type of error responses from server
        message = self._get_error_message(resp_json)

        # Message creation if none of the handling happens in _get_error_message method for error scenario
        if not message:
            resp_text = self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}') if r.text else "Response error text not found")
            message = "Error from server. Status Code: {0} Data from server: {1}".format(r.status_code, resp_text)
        else:
            message = "{}. {}".format("Response status code: {}".format(r.status_code), message)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        """ This function is used to process API response.
        :param r: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

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
            r.status_code,
            self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}') if r.text else "Response error text not found")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, params=None, data=None, method="get"):
        """ Function that makes the REST call to the app.
        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param params: request parameters
        :param data: request body
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(self._session, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to RiskSense
        url = "{}{}".format(self._base_url, endpoint)

        self.debug_print("Making a REST call with provided request parameters")

        try:
            r = request_func(
                url,
                params=params,
                json=data,
                verify=self._config.get('verify_server_cert', False)
            )
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Error Code: {0}. Error Message: {1}".format(error_code, error_msg)), resp_json)

        return self._process_response(r, action_result)

    def requests_retry_session(self, retries, backoff_factor, status_forcelist=(500, 429), session=None):
        """
        Create and return a session object
        :param retries: Maximum number of retries to attempt
        :param backoff_factor: Backoff factor used to calculate time between retries.
        :param status_forcelist: A tuple containing the response status codes that should trigger a retry.
        :param session: Session object

        :return: Session Object
        """
        session = session or requests.Session()

        headers = {
            "x-api-key": self._config['api_key'],
            "Content-Type": "application/json"
        }
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )

        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        session.headers.update(headers)

        return session

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """ This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :return: integer value of the parameter or None in case of failure
        """

        try:
            if not float(parameter).is_integer():
                error_text = RISKSENSE_LIMIT_VALIDATION_ALLOW_ZERO_MESSAGE.format(parameter=key) if allow_zero else RISKSENSE_LIMIT_VALIDATION_MESSAGE.format(parameter=key)
                action_result.set_status(phantom.APP_ERROR, error_text)
                return None
            parameter = int(parameter)
        except:
            error_text = RISKSENSE_LIMIT_VALIDATION_ALLOW_ZERO_MESSAGE.format(parameter=key) if allow_zero else RISKSENSE_LIMIT_VALIDATION_MESSAGE.format(parameter=key)
            action_result.set_status(phantom.APP_ERROR, error_text)
            return None

        if not allow_zero and parameter <= 0:
            action_result.set_status(phantom.APP_ERROR, RISKSENSE_LIMIT_VALIDATION_MESSAGE.format(parameter=key))
            return None
        elif allow_zero and parameter < 0:
            action_result.set_status(phantom.APP_ERROR, RISKSENSE_LIMIT_VALIDATION_ALLOW_ZERO_MESSAGE.format(parameter=key))
            return None

        return parameter

    def build_filter(self, fieldname, operator, value, exclusivity, status=None):
        """ This method creates a list of dictionary containing the filtering details.
        :param fieldname: A list of fieldnames
        :param operator: A list of operators
        :param value: A list of values
        :param exclusivity: A list of true/false
        :param status: status of the response
        :return: list of dictionary containing the filtering details
        """

        filters = list()

        for i, _ in enumerate(fieldname):
            filter_dict = dict()

            filter_dict["field"] = fieldname[i]
            filter_dict["operator"] = operator[i]
            filter_dict["exclusive"] = exclusivity[i]
            filter_dict["value"] = value[i]

            filters.append(filter_dict)

        if status:
            filter_dict = dict()

            filter_dict["field"] = "generic_state"
            filter_dict["operator"] = "EXACT"
            filter_dict["exclusive"] = False
            filter_dict["value"] = status

            filters.append(filter_dict)

        return filters

    def build_sort(self, sort_by, sort_direction):
        """ This method creates a list of dictionary containing the sorting details.
        :param sort_by: A list of fieldnames that will be used for sorting
        :param sort_direction: A list of sort direction values. Valid values: ASC/DESC
        :return: list of dictionary containing the sorting details
        """

        sort = list()

        for i, _ in enumerate(sort_by):
            sort_dict = dict()

            sort_dict["field"] = sort_by[i]
            sort_dict["direction"] = sort_direction[i]

            sort.append(sort_dict)

        return sort

    def check_length(self, action_result, **kwargs):
        """ This method is used to check the length of the values that are passed in the kwargs parameter.
        :param kwargs: key-values of which the length is to be checked
        :param action_result: Action result object
        :return: returns the length of the value. returns None, if the length of the provided values does not match.
        """

        values = list(kwargs.values())
        obj_length = len(values[0])
        for val in values:
            if len(val) != obj_length:
                action_result.set_status(phantom.APP_ERROR, RISKSENSE_LENGTH_VALIDATION_ERROR_MESSAGE.format(", ".join(list(kwargs.keys()))))
                return None

        return obj_length

    def form_list(self, parameter):
        """ This method is used to form a list out of the provided comma-separated string parameter.
        :param parameter: comma-separated string parameter
        :return: returns a list.
        """
        parameter_list = list()

        if parameter:
            parameter_list = [x.strip() for x in parameter.split(',')]
            parameter_list = list(filter(None, parameter_list))

        return parameter_list

    def load_list(self, parameter, action_result):
        """ This method is used to parse the JSON(list) string into a JSON formatted list.
        :param parameter: JSON string
        :param action_result: Action result object
        :return: returns a list.
        """
        parameter_list = list()

        try:
            if parameter:
                parameter_list = json.loads(parameter)
                if not isinstance(parameter_list, list):
                    action_result.set_status(phantom.APP_ERROR, "Please provide value parameter in JSON list format")
                    return None
        except:
            action_result.set_status(phantom.APP_ERROR, "Could not load JSON from value parameter")
            return None

        return parameter_list

    def build_data(self, param, action_result, projection=RISKSENSE_PROJECTION_DETAIL):
        """ This method is used to create the data dictionary which will be used in the list actions.
        :param param: parameters of an action
        :param action_result: Action result object
        :param projection: projection of the response
        :return: returns a data dictionary.
        """

        data = dict()
        status = param.get("status")

        if status and status not in ["Closed", "Open"]:
            action_result.set_status(phantom.APP_ERROR, RISKSENSE_INVALID_STATUS_PARAM_MESSAGE)
            return None

        fieldname = self.form_list(self._handle_py_ver_compat_for_input_str(param.get("fieldname")))
        operator = self.form_list(self._handle_py_ver_compat_for_input_str(param.get("operator")))
        exclusivity = self.form_list(self._handle_py_ver_compat_for_input_str(param.get("exclusivity")))
        sort_by = self.form_list(self._handle_py_ver_compat_for_input_str(param.get("sort_by")))
        sort_direction = self.form_list(self._handle_py_ver_compat_for_input_str(param.get("sort_direction")))

        exclusivity = list(map(lambda a: RISKSENSE_EXCLUSIVITY_DICTIONARY.get(a.lower()), exclusivity))

        if None in exclusivity:
            action_result.set_status(phantom.APP_ERROR, RISKSENSE_INVALID_EXCLUSIVITY_PARAM_MESSAGE)
            return None

        value = self.load_list(param.get("value"), action_result)
        if value is None:
            return None

        if self.get_action_identifier() != "tag_asset":
            page = self._validate_integers(action_result, param.get("page", RISKSENSE_DEFAULT_PAGE_INDEX), RISKSENSE_ACTION_PAGE_KEY, allow_zero=True)
            if page is None:
                return None

            data.update({"page": page, "projection": projection})

        filter_length = self.check_length(action_result, fieldname=fieldname, operator=operator, value=value, exclusivity=exclusivity)
        if filter_length is None:
            return None

        sort_length = self.check_length(action_result, sort_by=sort_by, sort_direction=sort_direction)
        if sort_length is None:
            return None

        if filter_length:
            filter_data = self.build_filter(fieldname, operator, value, exclusivity, status)
            if filter_data:
                data.update({"filters": filter_data})
        if sort_length:
            sort_data = self.build_sort(sort_by, sort_direction)
            if sort_data:
                data.update({"sort": sort_data})

        return data

    def _paginator(self, endpoint, action_result, limit=None, data=dict(), data_subject=None, method="get"):
        """ This function is used to fetch all the results using pagination logic.

        :param action_result: object of ActionResult class
        :param limit: maximum number of results to be fetched
        :param data: data to be passed while calling the API
        :param data_subject: the type of results that will be fetched
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)

        :return: successfully fetched results, results in error section of the API
        """

        items_list = list()
        params = dict()
        temp_point = dict()
        errors = list()
        page_size = min(limit, RISKSENSE_DEFAULT_MAX_RESULTS) if limit and data.get("page", 0) == 0 else RISKSENSE_DEFAULT_MAX_RESULTS

        temp_point["size"] = page_size
        temp_point["page"] = 0

        if method == "get":
            params = temp_point
        else:
            temp_point.update(data)
            data = temp_point

        while True:

            ret_val, items = self._make_rest_call(endpoint, action_result, params=params, data=data, method=method)

            if phantom.is_fail(ret_val):
                return None, None

            interim_items = items.get("_embedded", {}).get(data_subject, [])
            interim_errors = items.get("errors", [])

            if not interim_errors and not interim_items:
                break

            errors.extend(interim_errors)

            items_list.extend(interim_items)

            if limit and len(items_list) >= limit:
                return items_list[:limit], errors
            elif len(interim_items) + len(interim_errors) < page_size:
                break

            temp_point["page"] += 1

        return items_list, errors

    def get_client_id(self, action_result):
        """
        Fetches and returns the client ID of the provided client name
        :param action_result: object of Action Result or BaseConnector

        :return: client ID of the provided client name
        """

        clients, _ = self._paginator(RISKSENSE_LIST_CLIENTS_ENDPOINT, action_result, data_subject="clients")
        if clients is None:
            return None

        if not clients:
            action_result.set_status(phantom.APP_ERROR, "No clients available")
            return None

        for client in clients:
            if client.get("name") == self._client_name:
                return client.get("id")
        else:
            action_result.set_status(phantom.APP_ERROR, "The provided client does not exist")
            return None

    def get_response_data(self, action_result, endpoint, field, value, projection=RISKSENSE_PROJECTION_DETAIL, key=None):
        """ Makes a REST call and fetches the response.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param field: field using which the filter will be created
        :param value: value of the corresponding field
        :param projection: projection of the response
        :return: response of the API call
        """

        data = dict()
        # Validatation of the value as the field here is ID for each call. If this method is being called with some other field,
        # then there should be a check for the value of field (field == "id") before performing the below validation
        value = self._validate_integers(action_result, value, key)
        if value is None:
            return None

        filter_data = self.build_filter(fieldname=[field], operator=["EXACT"], value=[value], exclusivity=[False])
        data["filters"] = filter_data
        data["size"] = RISKSENSE_DEFAULT_MAX_RESULTS
        data["projection"] = projection
        data["page"] = RISKSENSE_DEFAULT_PAGE_INDEX

        ret_val, items = self._make_rest_call(endpoint, action_result, data=data, method="post")

        if phantom.is_fail(ret_val):
            return None

        return items

    def _handle_test_connectivity(self, param):
        """ Validate the asset configuration for connectivity using supplied configuration.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Fetching the client ID")
        self._client_id = self.get_client_id(action_result)

        if not self._client_id:
            return action_result.get_status()

        self.save_progress("Fetched client ID successfully")

        self._state[self._client_name] = self._client_id

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, _ = self._make_rest_call(RISKSENSE_GET_CLIENT_ENDPOINT.format(client_id=self._client_id), action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_host_findings(self, param):
        """Fetches and returns a list of host findings in the provided client, based on the provided input parameters.
        :param param: Dictionary of input parameter(s)

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        response = dict()

        max_results = self._validate_integers(action_result, param.get("max_results", RISKSENSE_DEFAULT_MAX_RESULTS), RISKSENSE_ACTION_LIMIT_KEY)
        if max_results is None:
            return action_result.get_status()

        data = self.build_data(param, action_result)

        if data is None:
            return action_result.get_status()

        # make rest call
        host_findings, errors = self._paginator(
                            RISKSENSE_LIST_HOST_FINDINGS_ENDPOINT.format(client_id=self._client_id), action_result, limit=max_results,
                            data=data, data_subject="hostFindings", method="post"
                        )

        if host_findings is None:
            return action_result.get_status()

        if not host_findings and not errors:
            return action_result.set_status(phantom.APP_ERROR, "No host finding available for the given inputs")

        response["host_findings"] = host_findings
        response["error_host_findings"] = errors

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["number_of_host_findings"] = len(host_findings)
        summary["number_of_error_host_findings"] = len(errors)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_unique_findings(self, param):
        """Fetches and returns a list of unique host findings in the provided client, based on the provided input parameters.
        :param param: Dictionary of input parameter(s)

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        response = dict()

        max_results = self._validate_integers(action_result, param.get("max_results", RISKSENSE_DEFAULT_MAX_RESULTS), RISKSENSE_ACTION_LIMIT_KEY)
        if max_results is None:
            return action_result.get_status()

        data = self.build_data(param, action_result, projection=RISKSENSE_PROJECTION_BASIC)

        if data is None:
            return action_result.get_status()

        # make rest call
        unique_findings, errors = self._paginator(
                            RISKSENSE_LIST_UNIQUE_HOST_FINDINGS_ENDPOINT.format(client_id=self._client_id), action_result, limit=max_results,
                            data=data, data_subject="uniqueHostFindings", method="post"
                        )

        if unique_findings is None:
            return action_result.get_status()

        if not unique_findings and not errors:
            return action_result.set_status(phantom.APP_ERROR, "No unique host finding available for the given inputs")

        response["unique_host_findings"] = unique_findings
        response["error_unique_host_findings"] = errors

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["number_of_unique_host_findings"] = len(unique_findings)
        summary["number_of_error_unique_host_findings"] = len(errors)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_apps(self, param):
        """Fetches and returns a list of applications in the provided client, based on the provided input parameters.
        :param param: Dictionary of input parameter(s)

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        response = dict()

        max_results = self._validate_integers(action_result, param.get("max_results", RISKSENSE_DEFAULT_MAX_RESULTS), RISKSENSE_ACTION_LIMIT_KEY)
        if max_results is None:
            return action_result.get_status()

        data = self.build_data(param, action_result)

        if data is None:
            return action_result.get_status()

        # make rest call
        applications, errors = self._paginator(
                            RISKSENSE_LIST_APPS_ENDPOINT.format(client_id=self._client_id), action_result, limit=max_results,
                            data=data, data_subject="applications", method="post"
                        )

        if applications is None:
            return action_result.get_status()

        if not applications and not errors:
            return action_result.set_status(phantom.APP_ERROR, "No application available for the given inputs")

        response["applications"] = applications
        response["error_applications"] = errors

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["number_of_applications"] = len(applications)
        summary["number_of_error_applications"] = len(errors)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_hosts(self, param):
        """Fetches and returns a list of hosts in the provided client, based on the provided input parameters.
        :param param: Dictionary of input parameter(s)

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        response = dict()

        max_results = self._validate_integers(action_result, param.get("max_results", RISKSENSE_DEFAULT_MAX_RESULTS), RISKSENSE_ACTION_LIMIT_KEY)
        if max_results is None:
            return action_result.get_status()

        data = self.build_data(param, action_result)

        if data is None:
            return action_result.get_status()

        # make rest call
        hosts, errors = self._paginator(
                            RISKSENSE_LIST_HOSTS_ENDPOINT.format(client_id=self._client_id), action_result, limit=max_results,
                            data=data, data_subject="hosts", method="post"
                        )

        if hosts is None:
            return action_result.get_status()

        if not hosts and not errors:
            return action_result.set_status(phantom.APP_ERROR, "No host available for the given inputs")

        response["hosts"] = hosts
        response["error_hosts"] = errors

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["number_of_hosts"] = len(hosts)
        summary["number_of_error_hosts"] = len(errors)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_hosts(self, param):
        """Fetches and returns details of host(s) presents in the provided client, based on the provided input parameters.
        :param param: Dictionary of input parameter(s)

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        host_name = self._handle_py_ver_compat_for_input_str(param.get("host_name"))
        host_id = param.get("host_id")

        response = dict()
        data = dict()

        if host_id is not None:
            host_id = self._validate_integers(action_result, host_id, RISKSENSE_ACTION_HOST_ID_KEY)
            if host_id is None:
                return action_result.get_status()

            data_host = self.build_filter(fieldname=["id"], operator=["EXACT"], value=[host_id], exclusivity=[False])

        elif host_name:
            data_host = self.build_filter(fieldname=["hostName"], operator=["EXACT"], value=[host_name], exclusivity=[False])

        else:
            return action_result.set_status(phantom.APP_ERROR, RISKSENSE_INSUFFICIENT_PARAM_GET_HOSTS_MESSAGE)

        data["filters"] = data_host
        data["projection"] = RISKSENSE_PROJECTION_DETAIL
        hosts, errors = self._paginator(RISKSENSE_LIST_HOSTS_ENDPOINT.format(client_id=self._client_id), action_result, data=data, data_subject="hosts", method="post")

        if hosts is None:
            return action_result.get_status()

        if not hosts and not errors:
            return action_result.set_status(phantom.APP_ERROR, "No host available for the given input")

        response["hosts"] = hosts
        response["error_hosts"] = errors

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["number_of_hosts"] = len(hosts)
        summary["number_of_error_hosts"] = len(errors)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_host_finding(self, param):
        """Fetches and returns details of a specific host finding presents in the provided client, based on the provided input parameters.
        :param param: Dictionary of input parameter(s)

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        response = dict()

        host_finding_data = self.get_response_data(action_result, RISKSENSE_LIST_HOST_FINDINGS_ENDPOINT.format(client_id=self._client_id),
                            field="id", value=param["host_finding_id"], key=RISKSENSE_ACTION_HOST_FINDING_ID_KEY)

        if host_finding_data is None:
            return action_result.get_status()

        host_findings = host_finding_data.get("_embedded", {}).get("hostFindings", [])
        errors = host_finding_data.get("errors")

        if not host_findings and not errors:
            return action_result.set_status(phantom.APP_ERROR, "No host finding available for the given ID")

        response["host_findings"] = host_findings
        response["error_host_findings"] = errors

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["number_of_host_findings"] = len(host_findings)
        summary["number_of_error_host_findings"] = len(errors)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_app(self, param):
        """Fetches and returns details of a specific application presents in the provided client, based on the provided input parameters.
        :param param: Dictionary of input parameter(s)

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        response = dict()

        application_data = self.get_response_data(action_result, RISKSENSE_LIST_APPS_ENDPOINT.format(client_id=self._client_id),
                            field="id", value=param["app_id"], key=RISKSENSE_ACTION_APP_ID_KEY)

        if application_data is None:
            return action_result.get_status()

        applications = application_data.get("_embedded", {}).get("applications", [])
        errors = application_data.get("errors")

        if not applications and not errors:
            return action_result.set_status(phantom.APP_ERROR, "No application available for the given ID")

        response["applications"] = applications
        response["error_applications"] = errors

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["number_of_applications"] = len(applications)
        summary["number_of_error_applications"] = len(errors)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_vulnerabilities(self, param):
        """Fetches and returns a list of vulnerabilities of a host finding present in the provided client.
        :param param: Dictionary of input parameter(s)

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        response = dict()

        host_finding_data = self.get_response_data(action_result, RISKSENSE_LIST_HOST_FINDINGS_ENDPOINT.format(client_id=self._client_id),
                            field="id", value=param["host_finding_id"], key=RISKSENSE_ACTION_HOST_FINDING_ID_KEY)

        if host_finding_data is None:
            return action_result.get_status()

        host_finding = host_finding_data.get("_embedded", {}).get("hostFindings", [{}])[0]
        errors = host_finding_data.get("errors")

        if not host_finding and not errors:
            return action_result.set_status(phantom.APP_ERROR, "No host finding available for the given ID")

        vulnerability_list = host_finding.get("vulnerabilities", {}).get("vulnInfoList", [])
        vulnerability_with_v3_list = host_finding.get("vulnerabilitiesWithV3", [])

        if not vulnerability_list and not vulnerability_with_v3_list and not errors:
            return action_result.set_status(phantom.APP_ERROR, "No vulnerabilities present in the host finding")

        response["vulnerability_list"] = vulnerability_list
        response["vulnerability_with_v3_list"] = vulnerability_with_v3_list
        response["error_host_findings"] = errors

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["number_of_v2_vulnerabilities"] = len(vulnerability_list)
        summary["number_of_v3_vulnerabilities"] = len(vulnerability_with_v3_list)
        summary["number_of_error_host_findings"] = len(errors)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_tag_asset(self, param):
        """Tags the filtered assets present in the provided client.
        :param param: Dictionary of input parameter(s)

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        data = dict()
        tag_data = dict()

        tag_name = self._handle_py_ver_compat_for_input_str(param["tag_name"])
        asset_type = self._handle_py_ver_compat_for_input_str(param["entity_type"])
        create_new_tag = param.get("create_new_tag", False)

        # Data creation which will be used to filter the assets
        filter_data = self.build_data(param, action_result)
        if filter_data is None:
            return action_result.get_status()

        data["filterRequest"] = filter_data
        data["isRemove"] = False

        # Get the tag ID from the provided tag name
        tag_filter = self.build_filter(fieldname=["name"], operator=["EXACT"], value=[tag_name], exclusivity=[False])

        tag_data["filters"] = tag_filter
        tag_data["projection"] = RISKSENSE_PROJECTION_BASIC
        tags, errors = self._paginator(RISKSENSE_LIST_TAGS_ENDPOINT.format(client_id=self._client_id), action_result, data=tag_data, data_subject="tags", method="post")

        if tags is None:
            self.debug_print("Error occurred while fetching the tag")
            return action_result.get_status()

        tag_id = None

        for tag in tags:
            if str(tag.get("name")) == tag_name:
                tag_id = tag.get("id")
                break

        # Adding the tag ID to the data
        if tag_id is not None:
            data["tagId"] = tag_id

        elif create_new_tag:

            asset_data = self.search_asset_data(action_result, asset_type, filter_data)

            if asset_data is None:
                return action_result.get_status()

            new_tag = self.create_tag(action_result, param)
            if new_tag is None:
                return action_result.get_status()

            data["tagId"] = new_tag.get("id")

        else:
            return action_result.set_status(phantom.APP_ERROR, "No such tag is available")

        ret_val, response = self._make_rest_call(RISKSENSE_ASSOCIATE_TAG_ENDPOINT.format(client_id=self._client_id, asset_type=asset_type), action_result,
                                data=data, method="post")

        if phantom.is_fail(ret_val):
            self.debug_print("Error occurred while associating the tag")
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["tag_id"] = data["tagId"]

        return action_result.set_status(phantom.APP_SUCCESS, "Tag got associated successfully")

    def search_asset_data(self, action_result, asset_type, filter_data, projection=RISKSENSE_PROJECTION_BASIC):
        """Fetches and returns a list of filtered data of the asset type provided.
        :param action_result: object of Action Result
        :param projection: projection of the response
        :param asset_type: Type of the asset of which the data is to be fetched
        :param filtered_data: filter to be applied while fetching the data of provided asset type

        :return: filtered data or None (in case of failure)
        """

        filter_data["projection"] = projection

        endpoint = RISKSENSE_SEARCH_ASSET_DATA_ENDPOINT.format(client_id=self._client_id, asset_type=asset_type)
        data_subject = ("{}s").format(asset_type)

        items, errors = self._paginator(
                            endpoint, action_result,
                            data=filter_data, data_subject=data_subject, method="post"
                        )

        if items is None:
            try:
                self.debug_print("Generating custom failure message while fetching the filtered data")

                msg = action_result.get_message()
                error_message = "{}. Error response: {}".format("Error occurred while checking whether the filtered data exists, before creating the new tag", msg)
                action_result.set_status(phantom.APP_ERROR, error_message)
            except:
                self.debug_print("Error occurred while generating failure message while fetching the filtered data")
            return None

        if not items:
            action_result.set_status(phantom.APP_ERROR, "Not creating the new tag as there is no filtered data available for the given inputs")
            return None

        return items

    def create_tag(self, action_result, param):
        """Creates a new tag based on the provided input parameters.
        :param param: Dictionary of input parameter(s)

        :return: details of the newly created tag
        """

        create_data = dict()
        fields = list()

        tag_name = self._handle_py_ver_compat_for_input_str(param["tag_name"])
        propagate_to_all_findings = param.get("propagate_to_all_findings", False)
        tag_type = self._handle_py_ver_compat_for_input_str(param.get("tag_type"))
        tag_description = self._handle_py_ver_compat_for_input_str(param.get("tag_description"))
        tag_colour = self._handle_py_ver_compat_for_input_str(param.get("tag_color"))
        tag_owner_id = param.get("tag_owner_id")

        if not (tag_owner_id and tag_type and tag_colour and tag_description):
            action_result.set_status(phantom.APP_ERROR, RISKSENSE_INSUFFICIENT_PARAM_CREATE_TAG_MESSAGE)
            return None

        tag_owner_id = self._validate_integers(action_result, tag_owner_id, RISKSENSE_ACTION_TAG_OWNER_ID_KEY, allow_zero=True)
        if tag_owner_id is None:
            return None

        param_dict = {
            "TAG_TYPE": tag_type,
            "NAME": tag_name,
            "DESCRIPTION": tag_description,
            "OWNER": tag_owner_id,
            "COLOR": tag_colour,
            "LOCKED": False,
            "PROPAGATE_TO_ALL_FINDINGS": propagate_to_all_findings
        }

        for key, value in list(param_dict.items()):
            field_dict = dict()
            field_dict["uid"] = key
            field_dict["value"] = value
            fields.append(field_dict)

        create_data["fields"] = fields

        ret_val, response = self._make_rest_call(RISKSENSE_CREATE_TAG_ENDPOINT.format(client_id=self._client_id), action_result,
                                data=create_data, method="post")

        if phantom.is_fail(ret_val):
            self.debug_print("Error occurred while creating the new tag")
            return None

        return response

    def _handle_list_users(self, param):
        """Fetches and returns the list of users.
        :param param: Dictionary of input parameter(s)

        :return: List of users
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        response = dict()
        max_results = self._validate_integers(action_result, param.get("max_results", RISKSENSE_DEFAULT_MAX_RESULTS), RISKSENSE_ACTION_LIMIT_KEY)

        if max_results is None:
            return action_result.get_status()

        # make rest call
        users, errors = self._paginator(RISKSENSE_LIST_USERS_ENDPOINT.format(client_id=self._client_id), action_result, limit=max_results, data_subject="users", method="post")

        if users is None:
            return action_result.get_status()

        if not users and not errors:
            return action_result.set_status(phantom.APP_ERROR, "No user available")

        response["users"] = users
        response["error_users"] = errors

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["number_of_users"] = len(users)
        summary["number_of_error_users"] = len(errors)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_tags(self, param):
        """Fetches and returns the list of tags.
        :param param: Dictionary of input parameter(s)

        :return: List of tags
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        response = dict()
        max_results = self._validate_integers(action_result, param.get("max_results", RISKSENSE_DEFAULT_MAX_RESULTS), RISKSENSE_ACTION_LIMIT_KEY)

        if max_results is None:
            return action_result.get_status()

        # make rest call
        tags, errors = self._paginator(RISKSENSE_LIST_TAGS_ENDPOINT.format(client_id=self._client_id), action_result, limit=max_results, data_subject="tags", method="post")

        if tags is None:
            return action_result.get_status()

        if not tags and not errors:
            return action_result.set_status(phantom.APP_ERROR, "No tag available")

        response["tags"] = tags
        response["error_tags"] = errors

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["number_of_tags"] = len(tags)
        summary["number_of_error_tags"] = len(errors)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_filter_attributes(self, param):
        """Fetches and returns a list of filter attributes for the provided asset_type.
        :param param: Dictionary of input parameter(s)

        :return: List of filter attributes
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        asset_type = self._handle_py_ver_compat_for_input_str(param["asset_type"])

        # make rest call
        ret_val, response = self._make_rest_call(RISKSENSE_LIST_FILTER_ATTRIBUTES_ENDPOINT.format(client_id=self._client_id, asset_type=asset_type), action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for resp in response:
            # Add the response into the data section
            action_result.add_data(resp)

        summary = action_result.update_summary({})
        summary["asset_filter_attributes"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.
        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Get the action that we are supposed to execute for this App Run
        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        self.debug_print("action_id", action)

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'list_filter_attributes': self._handle_list_filter_attributes,
            'list_tags': self._handle_list_tags,
            'list_users': self._handle_list_users,
            'list_hosts': self._handle_list_hosts,
            'list_host_findings': self._handle_list_host_findings,
            'list_apps': self._handle_list_apps,
            'list_unique_findings': self._handle_list_unique_findings,
            'get_hosts': self._handle_get_hosts,
            'get_host_finding': self._handle_get_host_finding,
            'get_app': self._handle_get_app,
            'list_vulnerabilities': self._handle_list_vulnerabilities,
            'tag_asset': self._handle_tag_asset
        }

        if action in list(action_mapping.keys()):
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        if self._state is None:
            self._state = dict()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        # get the asset config
        self._config = self.get_config()

        self._base_url = self._handle_py_ver_compat_for_input_str(self._config['base_url']).strip("/")
        self._client_name = self._handle_py_ver_compat_for_input_str(self._config['client_name'])
        number_of_retries = self._validate_integers(self, self._config.get('number_of_retries', RISKSENSE_DEFAULT_NUM_RETRIES), RISKSENSE_CONFIG_NUM_RETRIES_KEY)

        if number_of_retries is None:
            return self.get_status()

        try:
            backoff_factor = float(self._config.get('backoff_factor', RISKSENSE_DEFAULT_BACKOFF_FACTOR))
            if backoff_factor <= 0.0:
                return self.set_status(phantom.APP_ERROR, RISKSENSE_BACKOFF_FACTOR_VALIDATION_MESSAGE)
        except:
            return self.set_status(phantom.APP_ERROR, RISKSENSE_BACKOFF_FACTOR_VALIDATION_MESSAGE)

        # get the session object
        try:
            self._session = self.requests_retry_session(retries=number_of_retries, backoff_factor=backoff_factor)
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while creating the session object")

        if self._state.get(self._client_name):
            self._client_id = self._state[self._client_name]
        else:
            self._client_id = self.get_client_id(self)
            if not self._client_id:
                self.save_progress("Failed to fetch the client ID")
                return self.get_status()
            self._state[self._client_name] = self._client_id

        return phantom.APP_SUCCESS

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.
        :return: status (success/failure)
        """

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
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
            login_url = RisksenseConnector._get_phantom_base_url() + '/login'

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

        connector = RisksenseConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
