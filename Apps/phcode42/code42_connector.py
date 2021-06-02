# File: code42_connector.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import json
import ipaddress
from datetime import datetime
from dateutil import parser
import requests
from bs4 import BeautifulSoup
from code42_consts import *
from sys import version_info as python_version

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult


class RetVal(tuple):

    def __new__(cls, val1, val2):

        return tuple.__new__(RetVal, (val1, val2))


class Code42Connector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(Code42Connector, self).__init__()

        self._state = None
        self._username = None
        self._password = None
        self._server_url = None
        self._forensic_search_url = None
        self._auth_token = None

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
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
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _process_empty_response(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code in [200, 202]:
            return RetVal(phantom.APP_SUCCESS, response)

        if response.status_code == 204:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Status Code: {0}. Empty response and no information in the header".format(response.status_code)),
                      None)

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        # Check if the given response is of type Internal Error and response contains a reason
        if status_code == 500 and response.reason:
            message = "Status Code: {0}. Data from server:{1}". \
                format(status_code, json.loads(response).get("description"))
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text.encode('utf-8')
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception as e:
            self.debug_print(e)
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')
        self.debug_print(message)

        # Check if the given URL is correct and connects to the server
        if status_code == 404:
            message = "Status Code: {0}. Data from server:{1}".\
                format(status_code, "Unable to connect to server")

        # Sometimes API returns complete HTML page in the response, which can be very long
        # and difficult to understand. So if the message is very large return common error
        # message
        if len(message) > 500:
            message = 'Data from server: Error connecting to the server'

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """ This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        resp_json = None
        # Try a json parse
        try:
            if response.text:
                resp_json = response.json()
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(err_msg)), None)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                     response.text.replace('{', '{{').
                                                                                     replace('}', '}}'))

        # Check if the given response if of list type for invalid credentials
        if isinstance(resp_json, list) and resp_json:
            message = "Error from server. Status Code: {0} Data from server: {1}".\
                format(response.status_code, resp_json[0].get('description', response.text.replace('{', '{{').
                                                              replace('}', '}}')))
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process the response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the API talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is an error at this point
        message = "Can't process response from the server. Status Code: {0} Data from server: {1}".\
            format(response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """ This method is to check if the provided input parameter value
            is a non-zero positive integer and returns the integer value of the parameter itself.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: integer value of the parameter or None in case of failure
        """

        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, CODE42_ERR_INVALID_INTEGER_VALUE.format(msg="", param=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, CODE42_ERR_INVALID_INTEGER_VALUE.format(msg="", param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, CODE42_ERR_INVALID_INTEGER_VALUE.format(msg="non-negative", param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, CODE42_ERR_INVALID_INTEGER_VALUE.format(msg="non-zero positive", param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _make_rest_call(self, endpoint, action_result, timeout=None, params=None, data=None, method="get"):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param timeout: wait for REST call to complete
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        headers = {}
        auth = None

        if CODE42_ENVIRONMENT_ENDPOINT in endpoint:
            headers.update({'Accept': 'application/json'})

        # add custom User-Agent String
        try:
            runtime_version = "{}.{}.{}".format(python_version.major, python_version.minor, python_version.micro)
            headers['User-Agent'] = 'python/{runtime_version} Phantom/{phantom_version} Code42/{app_version}'.format(
                runtime_version=runtime_version,
                phantom_version=self.get_product_version(),
                app_version=self.get_app_json().get('app_version')
            )
        except:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error while generating the headers"),
                          resp_json)

        if CODE42_FORENSIC_SEARCH_ENDPOINT in endpoint and self._forensic_search_url is not None:
            url = '{}{}'.format(self._forensic_search_url, endpoint)
        else:
            url = '{}{}'.format(self._server_url, endpoint)

        # Check for REST call on Access Lock endpoint
        if CODE42_ACCESS_LOCK_ENDPOINT in endpoint or CODE42_FORENSIC_SEARCH_ENDPOINT in endpoint:

            # Create a session to store cookies
            session = requests.Session()

            try:
                access_auth_url = "{server_url}{endpoint}".format(server_url=self._server_url,
                                                                  endpoint=CODE42_V3_TOKEN_AUTH_ENDPOINT)
                # Store cookies of the session in auth_response
                auth_response = session.get(url=access_auth_url, auth=(self._username, self._password))

            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".
                                                       format(err_msg)), resp_json)

            # Check for failed cases of auth_response
            if not(200 <= auth_response.status_code < 399):
                return self._process_response(auth_response, action_result)

            # newer versions of the v3 API return the auth token in a header instead of in a cookie.
            # similarly, the token is accepted in a request header (although the cookie still works for requests).
            if auth_response.content is not None:
                try:
                    v3_user_token = json.loads(auth_response.content)["data"]["v3_user_token"]
                    headers.update({"Authorization": "v3_user_token {}".format(v3_user_token)})
                except Exception as e:
                    err_msg = self._get_error_message_from_exception(e)
                    return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                           "Error generating v3 user token. Details: {0}".
                                                           format(err_msg)), resp_json)

            # Request using session
            try:
                request_func = getattr(requests.Session, method)
            except AttributeError:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                              resp_json)

            try:
                request_response = request_func(session, url, timeout=timeout, json=data, headers=headers,
                                                params=params)
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".
                                                       format(err_msg)), resp_json)
        else:
            if self._auth_token:
                # Update header with required auth token
                headers.update({'Authorization': 'token {}'.format(self._auth_token)})

            else:
                auth = (self._username, self._password)

            try:
                request_func = getattr(requests, method)
            except AttributeError:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                              resp_json)

            try:
                request_response = request_func(url, timeout=timeout, json=data, auth=auth, headers=headers,
                                                params=params)
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                           "Error Connecting to server. Details: {0}".format(err_msg)),
                                  resp_json)

        return self._process_response(request_response, action_result)

    def _generate_token(self, action_result):
        """ Generate a new access token.

        :param action_result: object of ActionResult class
        :return: status success/failure
        """

        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=CODE42_AUTH_TOKEN_ENDPOINT,
                                                  timeout=CODE42_TIMEOUT, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Check for empty list when requesting with HTTP URL
        if isinstance(resp_json.get('data', {}), dict):
            return action_result.set_status(phantom.APP_ERROR, "Error while generating token")

        # Save the two parts of token
        token_part_one = resp_json[CODE42_JSON_DATA][0]
        token_part_two = resp_json[CODE42_JSON_DATA][1]

        self._auth_token = '{}-{}'.format(token_part_one, token_part_two)

        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        """ Testing of given credentials and obtaining authorization/admin consent for all other actions.

        :param param: (not used in this method)
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(CODE42_CONNECTION_MSG)

        ret_val = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(CODE42_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(CODE42_TOKEN_SUCCESS_MSG)
        self.save_progress(CODE42_TEST_CONNECTIVITY_PASSED_MSG)
        return action_result.set_status(phantom.APP_SUCCESS)

    def is_valid_identifier(self, input_value, action_result, isUserUid=False):
        """ This function is used to check whether for a given input value, appropriate user_id is available.

        :param input_value: Input parameter
        :param action_result: object of ActionResult class
        :return: phantom.APP_SUCCESS/phantom.APP_ERROR, ID of the User
        """

        # For pagination, start from first page
        page_num = CODE42_PAGINATION
        while True:

            # Use page number as a param
            params = {'pgNum': page_num}
            # Make REST call
            ret_val, response = self._make_rest_call(endpoint=CODE42_USERS_ENDPOINT, action_result=action_result,
                                                     params=params)

            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR, None

            # Check for empty list
            if not response.get('data', {}).get('users', []):
                break

            # Iterate through all the users
            for user in response['data']['users']:
                if user['username'].lower() == input_value.lower():
                    if isUserUid:
                        user_id = user['userUid']
                    else:
                        user_id = user['userId']
                    return phantom.APP_SUCCESS, user_id

            # Increment page number
            page_num += CODE42_PAGINATION

        return phantom.APP_ERROR, None

    def is_valid_organization(self, input_value, action_result):
        """ This function is used to check whether for a given input value, appropriate org_id is available.

        :param input_value: Input parameter
        :param action_result: object of ActionResult class
        :return: phantom.APP_SUCCESS/phantom.APP_ERROR, ID of the Organization
        """

        page_number = CODE42_PAGINATION
        while True:
            params = {'pgNum': page_number}

            request_status, request_response = self._make_rest_call(endpoint=CODE42_LIST_ORGANIZATIONS_ENDPOINT,
                                                                    action_result=action_result, params=params)

            if phantom.is_fail(request_status):
                return action_result.get_status()

            if not request_response.get('data', {}).get('orgs', []):
                break

            # Iterate through all the organizations
            for org in request_response['data']['orgs']:
                if org['orgName'].lower() == input_value.lower():
                    org_id = org['orgId']
                    return phantom.APP_SUCCESS, org_id

            page_number += CODE42_PAGINATION

        return phantom.APP_ERROR, None

    def _verify_param(self, input_value, action_result, type):
        """ This function is used to check that the input for ID is a positive integer or a valid string.
        For e.g. if user passes 5 it will passed as an integer, but if user passes random
        string it will be passed as an string.

        :param input_value: Input parameter
        :param action_result: object of ActionResult class
        :param type: 1 is used to for users and 2 is used for orgs
        :return: ID of the User/Org
        """

        if input_value.isdigit() and int(input_value) != 0:
            return input_value
        elif type == 2:
            return None
        else:
            try:
                float(input_value)
                return None
            except ValueError:
                self.debug_print(input_value)

        if type == CODE42_PAGINATION:
            ret_val, user_id = self.is_valid_identifier(input_value, action_result)
            if phantom.is_fail(ret_val):
                return None
            return user_id
        else:
            ret_val, org_id = self.is_valid_organization(input_value, action_result)
            if phantom.is_fail(ret_val):
                return None
            return org_id

    def _check_status(self, endpoint, id, action_result):
        """ This function is used to check the status of a given user or device.

        :param endpoint: endpoint for user/device
        :param id: ID of the user or device
        :param action_result: object of ActionResult class
        :return: status: status of the user or device
        """

        endpoint = "{}/{}".format(endpoint, id)

        request_status, request_response = self._make_rest_call(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(request_status):
            return action_result.get_status(), None

        if CODE42_ACCESS_LOCK_ENDPOINT in endpoint:
            status = request_response.get('data', {}).get('isLockEnabled')
            if status:
                return phantom.APP_SUCCESS, str(status)
            return phantom.APP_SUCCESS, None

        status = request_response.get('data', {}).get('status', "")
        return phantom.APP_SUCCESS, status

    def _handle_list_users(self, param):
        """ This function is used to list all the users.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        # For pagination, start from first page
        page_num = CODE42_PAGINATION
        while True:

            # Use page number as a param
            params = {'pgNum': page_num}
            # Make REST call
            ret_val, response = self._make_rest_call(endpoint=CODE42_USERS_ENDPOINT, action_result=action_result,
                                                     params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # Check for empty list
            if not response.get('data', {}).get('users', []):
                break

            # Iterate through all the users
            for user in response['data']['users']:
                action_result.add_data(user)

            # Increment page number
            page_num += CODE42_PAGINATION

        summary = action_result.update_summary({})
        summary['total_users'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_user(self, param):
        """ This function is used to
            retrieve a specific user's info.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        user = param.get(CODE42_JSON_USER)

        # if parameter is a number, use userId endpoint
        try:
            user_id = int(user)
            endpoint = CODE42_GET_USER_INFO_ENDPOINT.format(userId=user_id)
            ret_val, response = self._make_rest_call(endpoint=endpoint, action_result=action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            action_result.add_data(response.get('data', {}))
        # if parameter is a string, use a query-based search
        except ValueError:
            # For pagination, start from first page
            page_num = CODE42_PAGINATION
            flag = 0
            while True:

                # Use page number as a param
                params = {'pgNum': page_num, 'q': user}
                # Make REST call
                ret_val, response = self._make_rest_call(endpoint=CODE42_USERS_ENDPOINT, action_result=action_result,
                                                        params=params)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                # Check for empty list
                if not response.get('data', {}).get('users'):
                    break

                # Iterate through all the users
                for user_data in response['data']['users']:
                    # match parameter against username
                    if user_data.get('username', '') == user:
                        flag = 1
                        action_result.add_data(user_data)
                        break
                if flag:
                    break
                # Increment page number
                page_num += CODE42_PAGINATION

        summary = action_result.update_summary({})
        summary['total_users'] = action_result.get_data_size()

        if action_result.get_data_size() == 0:
            return action_result.set_status(phantom.APP_ERROR, CODE42_USER_NOT_FOUND_MSG.format(user_name=user))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_activate_user(self, param):
        """ This function is used to activate a user.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        user = param[CODE42_JSON_USER]

        user_id = self._verify_param(user, action_result, type=CODE42_PAGINATION)

        if not user_id:
            self.debug_print(CODE42_INVALID_USER_ID_MSG)
            return action_result.set_status(phantom.APP_ERROR, status_message=CODE42_INVALID_USER_ID_MSG)

        # Endpoint for REST call
        endpoint = CODE42_USER_DEACTIVATION_ENDPOINT.format(userId=user_id)

        status, response = self._check_status(CODE42_USERS_ENDPOINT, user_id, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if "Active" in response:
            if "Blocked" in response:
                return action_result.set_status(phantom.APP_SUCCESS, status_message="{}. {}"
                                                .format(CODE42_USER_ALREADY_ACTIVATED_MSG, "User status is Blocked"))
            return action_result.set_status(phantom.APP_SUCCESS, status_message="{}. {}"
                                            .format(CODE42_USER_ALREADY_ACTIVATED_MSG, "User status is Unblocked"))

        unblock_user = param.get(CODE42_JSON_UNBLOCK_USER, False)

        params = {'unblockUser': unblock_user}

        # Make REST call
        ret_val, _ = self._make_rest_call(endpoint=endpoint, action_result=action_result, method="delete",
                                          params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        message = CODE42_USER_ACTIVATION_USERNAME_SUCCESS_MSG.format(user=user)

        if user.isdigit():
            message = CODE42_USER_ACTIVATION_ID_SUCCESS_MSG.format(user=user_id)

        return action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_deactivate_user(self, param):
        """ This function is used to deactivate a user.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        user = param[CODE42_JSON_USER]

        user_id = self._verify_param(user, action_result, type=CODE42_PAGINATION)

        if not user_id:
            self.debug_print(CODE42_INVALID_USER_ID_MSG)
            return action_result.set_status(phantom.APP_ERROR, status_message=CODE42_INVALID_USER_ID_MSG)

        # Endpoint for REST call
        endpoint = CODE42_USER_DEACTIVATION_ENDPOINT.format(userId=user_id)

        status, response = self._check_status(CODE42_USERS_ENDPOINT, user_id, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if "Deactivated" in response:
            if "Blocked" in response:
                return action_result.set_status(phantom.APP_SUCCESS, status_message="{}. {}"
                                                .format(CODE42_USER_ALREADY_DEACTIVATED_MSG, "User status is Blocked"))
            return action_result.set_status(phantom.APP_SUCCESS, status_message="{}. {}"
                                            .format(CODE42_USER_ALREADY_DEACTIVATED_MSG, "User status is Unblocked"))

        block_user = param.get(CODE42_JSON_BLOCK_USER, False)

        data = {
            "blockUser": block_user
        }

        # Make REST call
        ret_val, _ = self._make_rest_call(endpoint=endpoint, action_result=action_result, method="put", data=data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        message = CODE42_USER_DEACTIVATION_USERNAME_SUCCESS_MSG.format(user=user)

        if user.isdigit():
            message = CODE42_USER_DEACTIVATION_ID_SUCCESS_MSG.format(user=user_id)

        return action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_devices(self, param):
        """ This function is used to list all the devices.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        # For pagination, start from first page
        page_num = CODE42_PAGINATION
        while True:

            # Use page number as a param
            params = {'pgNum': page_num}
            # Make REST call
            ret_val, response = self._make_rest_call(endpoint=CODE42_DEVICES_ENDPOINT, action_result=action_result,
                                                     params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # Check for empty list
            if not response.get('data', {}).get('computers', []):
                break

            # Iterate through all the users
            for user in response.get('data', {}).get('computers', []):
                action_result.add_data(user)

            # Increment page number
            page_num += CODE42_PAGINATION

        summary = action_result.update_summary({})
        summary['total_devices'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_device(self, param):
        """ This function is used to unblock the device.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        device_id = param[CODE42_JSON_DEVICE_ID]
        ret_val, device_id = self._validate_integer(action_result, device_id, CODE42_JSON_DEVICE_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        endpoint = CODE42_BLOCK_DEVICE_ENDPOINT.format(device_id=device_id)

        status, response = self._check_status(CODE42_DEVICES_ENDPOINT, device_id, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if "Blocked" not in response:
            return action_result.set_status(phantom.APP_SUCCESS, status_message=CODE42_DEVICE_ALREADY_UNBLOCKED_MSG)

        ret_val = self._handle_device_actions(action_result=action_result, endpoint=endpoint, method='delete')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        message = CODE42_DEVICE_UNBLOCKED_SUCCESS_MSG.format(device_id=device_id)

        return action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_block_device(self, param):
        """ This function is used to block the device.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        device_id = param[CODE42_JSON_DEVICE_ID]
        ret_val, device_id = self._validate_integer(action_result, device_id, CODE42_JSON_DEVICE_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        endpoint = CODE42_BLOCK_DEVICE_ENDPOINT.format(device_id=device_id)

        status, response = self._check_status(CODE42_DEVICES_ENDPOINT, device_id, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if "Blocked" in response:
            return action_result.set_status(phantom.APP_SUCCESS, status_message=CODE42_DEVICE_ALREADY_BLOCKED_MSG)

        ret_val = self._handle_device_actions(action_result=action_result, endpoint=endpoint, method='put')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        message = CODE42_DEVICE_BLOCKED_SUCCESS_MSG.format(device_id=device_id)

        return action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_deactivate_device(self, param):
        """ This function is used to deactivate the device.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        device_id = param[CODE42_JSON_DEVICE_ID]
        ret_val, device_id = self._validate_integer(action_result, device_id, CODE42_JSON_DEVICE_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        endpoint = CODE42_DEACTIVATE_DEVICE_ENDPOINT.format(device_id=device_id)

        status, response = self._check_status(CODE42_DEVICES_ENDPOINT, device_id, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if "Deactivated" in response:
            return action_result.set_status(phantom.APP_SUCCESS, status_message=CODE42_DEVICE_ALREADY_DEACTIVATED_MSG)

        ret_val = self._handle_device_actions(action_result=action_result, endpoint=endpoint, method="put")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        status_message = CODE42_DEVICE_DEACTIVATED_SUCCESS_MSG.format(device_id=device_id)
        return action_result.set_status(phantom.APP_SUCCESS, status_message=status_message)

    def _handle_activate_device(self, param):
        """ This function is used to activate the device.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        device_id = param[CODE42_JSON_DEVICE_ID]
        ret_val, device_id = self._validate_integer(action_result, device_id, CODE42_JSON_DEVICE_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        endpoint = CODE42_DEACTIVATE_DEVICE_ENDPOINT.format(device_id=device_id)

        status, response = self._check_status(CODE42_DEVICES_ENDPOINT, device_id, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if "Active" in response:
            return action_result.set_status(phantom.APP_SUCCESS, status_message=CODE42_DEVICE_ALREADY_ACTIVATED_MSG)

        ret_val = self._handle_device_actions(action_result=action_result, endpoint=endpoint, method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        status_message = CODE42_DEVICE_ACTIVATED_SUCCESS_MSG.format(device_id=device_id)
        return action_result.set_status(phantom.APP_SUCCESS, status_message=status_message)

    def _handle_deauthorize_device(self, param):
        """ This function is used to handle the deauthorize device action.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        device_id = param[CODE42_JSON_DEVICE_ID]
        ret_val, device_id = self._validate_integer(action_result, device_id, CODE42_JSON_DEVICE_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        endpoint = CODE42_DEAUTHORIZE_DEVICE_ENDPOINT.format(device_id=device_id)

        status, response = self._check_status(CODE42_DEVICES_ENDPOINT, device_id, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if "Deauthorized" in response or "Deactivated" in response or "Blocked" in response:
            return action_result.set_status(phantom.APP_SUCCESS, status_message=CODE42_DEVICE_ALREADY_DEAUTHORIZED_MSG)

        ret_val = self._handle_device_actions(action_result=action_result, endpoint=endpoint, method='put')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        status_message = CODE42_DEVICE_DEAUTHORIZED_SUCCESS_MSG.format(device_id=device_id)
        return action_result.set_status(phantom.APP_SUCCESS, status_message=status_message)

    def _handle_device_actions(self, action_result, endpoint, method):
        """ This function is used to handle the common part of the actions related to the device.

        :param action_result: Object of ActionResult class
        :param endpoint: API endpoint to call
        :param method: Method for the make_rest_call
        :return: status success/failure
        """

        ret_val, _ = self._make_rest_call(endpoint=endpoint, action_result=action_result, method=method)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _handle_list_organizations(self, param):
        """ This function is used to list all organizations.

        :param param: Dictionary of input parameters
        :return: status (success/failure)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        page_number = CODE42_PAGINATION
        while True:
            params = {'pgNum': page_number}

            request_status, request_response = self._make_rest_call(endpoint=CODE42_LIST_ORGANIZATIONS_ENDPOINT,
                                                                    action_result=action_result, params=params)

            if phantom.is_fail(request_status):
                return action_result.get_status()

            if not request_response.get('data', {}).get('orgs', []):
                break

            for organization in request_response['data']['orgs']:
                action_result.add_data(organization)

            page_number += CODE42_PAGINATION

        summary = action_result.update_summary({})
        summary['total_organizations'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_change_organization(self, param):
        """ This function is used to handle the change organization action.

        :param param: Dictionary of input parameters
        :return: status (success/failure)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        organization = param[CODE42_JSON_ORG]
        user = param[CODE42_JSON_USER]

        # find the organization id using the given value
        _, organization_id_from_name = self.is_valid_organization(organization, action_result)

        # take a given value as a organization id
        organization_id = self._verify_param(organization, action_result, type=2)

        # if both organization_id and organization_id_from_name not exist it's return error
        if not organization_id and not organization_id_from_name:
            self.debug_print(CODE42_INVALID_ORG_ID_MSG)
            return action_result.set_status(phantom.APP_ERROR, status_message=CODE42_INVALID_ORG_ID_MSG)

        user_id = self._verify_param(user, action_result, type=CODE42_PAGINATION)

        if not user_id:
            self.debug_print(CODE42_INVALID_USER_ID_MSG)
            return action_result.set_status(phantom.APP_ERROR, status_message=CODE42_INVALID_USER_ID_MSG)

        request_org_status, response_org_status = self._make_rest_call(endpoint="{}/{}".
                                                                       format(CODE42_USERS_ENDPOINT, user_id),
                                                                       action_result=action_result)

        if phantom.is_fail(request_org_status):
            return action_result.get_status()

        user_org_id = response_org_status.get('data', {}).get('orgId')

        # if user already in the given organization, it's return error
        if (organization_id and user_org_id == int(organization_id)) or organization_id_from_name and user_org_id == int(organization_id_from_name):
            return action_result.set_status(phantom.APP_SUCCESS, status_message=CODE42_ORG_ALREADY_SET_MSG)

        request_data = {
            "userId": user_id
        }

        is_org_id = True
        if organization_id:
            request_data["parentOrgId"] = organization_id
        else:
            is_org_id = False
            request_data["parentOrgId"] = organization_id_from_name

        request_status, _ = self._make_rest_call(endpoint=CODE42_CHANGE_ORGANIZATION_ENDPOINT,
                                                 action_result=action_result, data=request_data, method='post')

        if phantom.is_fail(request_status):
            if is_org_id and organization_id_from_name:
                is_org_id = False
                request_data["parentOrgId"] = organization_id_from_name
                request_status, _ = self._make_rest_call(endpoint=CODE42_CHANGE_ORGANIZATION_ENDPOINT,
                                                    action_result=action_result, data=request_data, method='post')
                if phantom.is_fail(request_status):
                    return action_result.get_status()
            else:
                return action_result.get_status()

        status_message = CODE42_CHANGE_ORGANIZATION_USERNAME_ORGNAME_SUCCESS_MSG.format(user=user, org=organization)

        if user.isdigit() and is_org_id:
            status_message = CODE42_CHANGE_ORGANIZATION_USERID_ORGID_SUCCESS_MSG.\
                format(user=user_id, org=request_data["parentOrgId"])
        elif user.isdigit():
            status_message = CODE42_CHANGE_ORGANIZATION_USERID_ORGNAME_SUCCESS_MSG. \
                format(user=user_id, org=organization)
        elif is_org_id:
            status_message = CODE42_CHANGE_ORGANIZATION_USERNAME_ORGID_SUCCESS_MSG. \
                format(user=user, org=request_data["parentOrgId"])
        return action_result.set_status(phantom.APP_SUCCESS, status_message=status_message)

    def _handle_lock_device(self, param):
        """ This function is used to handle lock on a device.

        :param param: Dictionary of input parameters
        :return: status (success/failure)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        # Input parameter device_id
        device_id = param[CODE42_JSON_DEVICE_ID]
        ret_val, device_id = self._validate_integer(action_result, device_id, CODE42_JSON_DEVICE_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Get details for the given device_id
        endpoint_device = "{}/{}".format(CODE42_DEVICES_ENDPOINT, device_id)

        request_status, request_response_device = self._make_rest_call(endpoint=endpoint_device,
                                                                       action_result=action_result)

        if phantom.is_fail(request_status):
            return action_result.get_status()

        # Map the given device_id with its corresponding guid
        device_guid = request_response_device.get('data', {}).get('guid')

        endpoint = "{}/{}".format(CODE42_ACCESS_LOCK_ENDPOINT, device_guid)

        status, response = self._check_status(CODE42_ACCESS_LOCK_ENDPOINT, device_guid, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if response:
            return action_result.set_status(phantom.APP_SUCCESS, status_message=CODE42_LOCK_ALREADY_ENABLED_MSG)

        request_status, request_response = self._make_rest_call(endpoint=endpoint, action_result=action_result,
                                                                method='post')

        if phantom.is_fail(request_status):
            return action_result.get_status()

        action_result.add_data(request_response)

        status_message = CODE42_LOCK_SUCCESS_MSG.format(device_id=device_id)
        return action_result.set_status(phantom.APP_SUCCESS, status_message=status_message)

    def _handle_unlock_device(self, param):
        """ This function is used to handle unlock on a device.

        :param param: Dictionary of input parameters
        :return: status (success/failure)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        # Input parameter device_id
        device_id = param[CODE42_JSON_DEVICE_ID]
        ret_val, device_id = self._validate_integer(action_result, device_id, CODE42_JSON_DEVICE_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Get details for the given device_id
        endpoint_device = "{}/{}".format(CODE42_DEVICES_ENDPOINT, device_id)

        request_status, request_response_device = self._make_rest_call(endpoint=endpoint_device,
                                                                       action_result=action_result)

        if phantom.is_fail(request_status):
            return action_result.get_status()

        # Map the given device_id with its corresponding guid
        device_guid = request_response_device.get('data', {}).get('guid')

        endpoint = "{}/{}".format(CODE42_ACCESS_LOCK_ENDPOINT, device_guid)

        status, response = self._check_status(CODE42_ACCESS_LOCK_ENDPOINT, device_guid, action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, status_message=CODE42_LOCK_ALREADY_DISABLED_MSG)

        request_status, request_response = self._make_rest_call(endpoint=endpoint, action_result=action_result,
                                                                method='patch')

        if phantom.is_fail(request_status):
            return action_result.get_status()

        action_result.add_data(request_response)

        summary = action_result.update_summary({})
        summary['passphrase'] = request_response['data']['lockPassphrase']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _paginator(self, action_result, filter_dict, endpoint, limit):
        next_token = ""
        list_items = []

        while True:
            filter_dict['pgToken'] = next_token

            request_status, request_response = self._make_rest_call(endpoint=endpoint,
                                                                    method="post", action_result=action_result,
                                                                    data=filter_dict)

            if phantom.is_fail(request_status):
                return action_result.get_status(), None

            if not request_response.get('fileEvents', []):
                break

            list_items.extend(request_response.get('fileEvents', []))

            if limit and len(list_items) >= limit:
                return phantom.APP_SUCCESS, list_items[:limit]

            next_token = request_response.get("nextPgToken", "")
            if not next_token:
                break
        return phantom.APP_SUCCESS, list_items

    def _handle_hunt_file(self, param):
        """ This function is used to hunt the file.

        :param param: Dictionary of input parameters
        :return: status (success/failure)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param[CODE42_JSON_FILE_HASH]
        limit = param.get(MAX_RESULTS_KEY, CODE42_DEFAULT_PAGE_SIZE)
        ret_val, limit = self._validate_integer(action_result, limit, MAX_RESULTS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        url_determined = self._determine_forensic_search_url(action_result=action_result)

        if phantom.is_fail(url_determined):
            return action_result.get_status()

        filter_dict = {
            "groups": [
                {
                    "filters": [
                        {
                            "operator": "IS",
                            "term": "md5Checksum",
                            "value": file_hash
                        }
                    ]
                }
            ]
        }

        ret_val, list_items = self._paginator(action_result, filter_dict, CODE42_FORENSIC_SEARCH_ENDPOINT, limit)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for item in list_items:
            action_result.add_data(item)

        summary = action_result.update_summary({})
        summary['total_events'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _determine_forensic_search_url(self, action_result):
        """ This function is used to handle the authorization for the forensic search action.

        :param action_result: Object of ActionResult class
        :return: status(success/failure)
        """

        server_env_status, server_env_response = self._make_rest_call(endpoint=CODE42_ENVIRONMENT_ENDPOINT,
                                                                      action_result=action_result)

        if phantom.is_fail(server_env_status):
            return action_result.get_status()

        sts_url = server_env_response.get('stsBaseUrl')

        if not sts_url:
            return action_result.set_status(phantom.APP_ERROR,
                                            status_message='Forensic Search is unavailable in your Code42 environment')
        try:
            self._forensic_search_url = 'https://forensicsearch-{}'.format(sts_url.lower().split('https://sts-')[1])
        except:
            return action_result.set_status(phantom.APP_ERROR,
                                            status_message='Could not determine forensic search api url')

        return phantom.APP_SUCCESS

    def _handle_run_query(self, param): # noqa
        """ This function is used to handle the run query action.

        :param param: Dictionary of input parameters
        :return: status(success/failure)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        start_time = param.get(CODE42_JSON_START_TIME, '')
        end_time = param.get(CODE42_JSON_END_TIME, '')
        file_event = param.get(CODE42_JSON_FILE_EVENT)
        file_hash = param.get(CODE42_JSON_FILE_HASH)
        file_name = param.get(CODE42_JSON_FILE_NAME)
        file_path = param.get(CODE42_JSON_FILE_PATH)
        hostname = param.get(CODE42_JSON_HOST_NAME)
        username = param.get(CODE42_CONFIG_USERNAME)
        private_ip = param.get(CODE42_JSON_PRIVATE_IP)
        public_ip = param.get(CODE42_JSON_PUBLIC_IP)
        query = param.get(CODE42_JSON_QUERY)
        limit = param.get(MAX_RESULTS_KEY, CODE42_DEFAULT_PAGE_SIZE)
        ret_val, limit = self._validate_integer(action_result, limit, MAX_RESULTS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # If query parameter is present, ignore other parameters
        if query:
            try:
                filter_dict = json.loads(query)
                if 'pgNum' in filter_dict:
                    del filter_dict['pgNum']
                if 'pgSize' in filter_dict:
                    del filter_dict['pgSize']
            except:
                return action_result.set_status(phantom.APP_ERROR, status_message="Invalid JSON in parameter 'query'")
        else:

            # If query is not provided, start_time and end_time are mandatory
            if start_time == '' or end_time == '':
                return action_result.set_status(phantom.APP_ERROR, status_message=CODE42_START_TIME_END_TIME_REQUIRED)

            # Verify start_time
            try:
                # API requires seconds in float, so convert start_time into the float
                start_time = float(start_time)
                start_time = datetime.utcfromtimestamp(start_time).isoformat()
                if start_time[-3] != '.':
                    start_time = '{0}.00'.format(start_time)
                start_time = "{0}Z".format(start_time)
            except:
                return action_result.set_status(phantom.APP_ERROR, status_message=CODE42_INVALID_START_TIME_MSG)

            # Verify end_time
            try:
                # API requires seconds in float, so convert end_time into the float
                end_time = float(end_time)
                end_time = datetime.utcfromtimestamp(end_time).isoformat()
                if end_time[-3] != '.':
                    end_time = '{0}.00'.format(end_time)
                end_time = "{0}Z".format(end_time)
            except:
                return action_result.set_status(phantom.APP_ERROR, status_message=CODE42_INVALID_END_TIME_MSG)

            if start_time >= end_time:
                return action_result.set_status(phantom.APP_ERROR, status_message=CODE42_INVALID_TIME_RANGE)

            filters_list = list()

            filters_list.append({
                "operator": "ON_OR_AFTER",
                "term": "eventTimestamp",
                "value": start_time
            })

            filters_list.append({
                "operator": "ON_OR_BEFORE",
                "term": "eventTimestamp",
                "value": end_time
            })

            if file_event:
                if file_event in FILE_EVENT_LIST:
                    event_mapping = {
                        "New file": "CREATED",
                        "Modified": "MODIFIED",
                        "No longer observed": "DELETED"
                    }

                    filters_list.append({
                        "operator": "IS",
                        "term": "eventType",
                        "value": event_mapping[file_event]
                    })
                else:
                    return action_result.set_status(phantom.APP_ERROR, status_message=CODE42_FILE_EVENT_INVALID)

            if file_hash:
                filters_list.append({
                    "operator": "IS",
                    "term": "md5Checksum",
                    "value": file_hash
                })

            if file_name:
                filters_list.append({
                    "operator": "IS",
                    "term": "fileName",
                    "value": file_name
                })

            if file_path:
                filters_list.append({
                    "operator": "IS",
                    "term": "filePath",
                    "value": file_path
                })

            if hostname:
                filters_list.append({
                    "operator": "IS",
                    "term": "osHostName",
                    "value": hostname
                })

            if username:
                filters_list.append({
                    "operator": "IS",
                    "term": "deviceUserName",
                    "value": username
                })

            if private_ip:
                filters_list.append({
                    "operator": "IS",
                    "term": "privateIpAddresses",
                    "value": private_ip
                })

            if public_ip:
                filters_list.append({
                    "operator": "IS",
                    "term": "publicIpAddress",
                    "value": public_ip
                })

            filter_dict = {
                "groups": [
                    {
                        "filters": filters_list
                    }
                ]
            }

        url_determined = self._determine_forensic_search_url(action_result=action_result)

        if phantom.is_fail(url_determined):
            return action_result.get_status()

        ret_val, list_items = self._paginator(action_result, filter_dict, CODE42_FORENSIC_SEARCH_ENDPOINT, limit)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for item in list_items:
            action_result.add_data(item)

        summary = action_result.update_summary({})
        summary['total_events'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_device(self, param):
        """ This function is used to query for information about a device.

        :param param: Dictionary of input parameters
        :return: status(success/failure)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        # get specific device
        device_id = param.get(CODE42_JSON_DEVICE_ID)
        if device_id:
            ret_val, device_id = self._validate_integer(action_result, device_id, CODE42_JSON_DEVICE_ID)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            endpoint = "{}/{}".format(CODE42_DEVICES_ENDPOINT, device_id)

            request_status, request_response = self._make_rest_call(endpoint=endpoint, action_result=action_result)

            if phantom.is_fail(request_status):
                return action_result.get_status()

            # add device data to action result
            action_result.add_data(request_response.get('data', {}))

            status = request_response.get('data', {}).get('status', "Device status not found")
            return action_result.set_status(phantom.APP_SUCCESS, status)

        # query for a device
        elif param.get(CODE42_JSON_QUERY):
            query = param.get(CODE42_JSON_QUERY)

            # For pagination, start from first page
            page_num = CODE42_PAGINATION
            device_info_list = []
            while True:

                # Use page number as a param
                params = {
                    'pgNum': page_num,
                    'pgSize': CODE42_DEFAULT_PAGE_SIZE,
                    'q': query,
                    'incBackupUsage': True
                }
                # Make REST call
                ret_val, response = self._make_rest_call(endpoint=CODE42_DEVICES_ENDPOINT, action_result=action_result,
                                                        params=params)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                # Check for empty list
                if not response.get('data', {}).get('computers', []):
                    break

                # Iterate through all the device
                for device in response.get('data', {}).get('computers', []):
                    device_info_list.append(device)

                # Increment page number
                page_num += CODE42_PAGINATION

            if param.get('most_recent_only', False):
                if isinstance(device_info_list, list) and len(device_info_list) > 1:
                    most_recent_device = max(
                        device_info_list,
                        key=lambda x: parser.parse(x.get('lastConnected', ''))
                    )
                    # add the most recent device to the result data and return
                    action_result.add_data(most_recent_device)
                    summary = action_result.update_summary({})
                    summary['total_devices'] = 1
                    return action_result.set_status(phantom.APP_SUCCESS)

            action_result.update_data(device_info_list)

            summary = action_result.update_summary({})
            summary['total_devices'] = action_result.get_data_size()

            return action_result.set_status(phantom.APP_SUCCESS)
        # error
        else:
            return action_result.set_status(phantom.APP_ERROR, "Either device_id or query parameter must be supplied")

    def _handle_push_restore(self, param):
        """ This function is used to push a restore on a device.

        :param param: Dictionary of input parameters
        :return: status(success/failure)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        src_device_guid = param['src_device_guid']
        accepting_device_guid = param['accepting_device_guid']
        target_node_guid = param['target_node_guid']

        files = param.get('files', '')
        files = [x.strip() for x in files.split(',')]
        files = list(filter(None, files))

        dirs = param.get('directories', '')
        dirs = [x.strip() for x in dirs.split(',')]
        dirs = list(filter(None, dirs))

        if not (files or dirs):
            return action_result.set_status(phantom.APP_ERROR, CODE42_RESTORE_NO_PATHS_SUPPLIED)

        # nothing supplied, default will be C:
        if not dirs:
            dirs = ['C:\\']

        # API expects certain format for each file path
        # {"type":"file", "path":"/home/joe/Desktop/PushRestoreTestAPI","selected":true}
        file_path_json_list = []
        for path in files:
            stripped_path = path.strip()
            if not len(stripped_path):
                continue

            file_path_json_list.append({
                'type': 'file',
                'path': stripped_path,
                'selected': True
            })

        for path in dirs:
            stripped_path = path.strip()
            if not len(stripped_path):
                continue

            file_path_json_list.append({
                'type': 'directory',
                'path': stripped_path,
                'selected': True
            })

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        # get DataKeyToken
        key_token_request_data = {
            'computerGuid': src_device_guid
        }
        ret_val, response = self._make_rest_call(endpoint=CODE42_DATA_KEY_TOKEN_ENDPOINT,
                                                action_result=action_result,
                                                data=key_token_request_data,
                                                method='post')

        if phantom.is_fail(ret_val):
            self.append_to_message(CODE42_DEVICE_TOKEN_GENERATION_FAILED)
            return action_result.get_status()

        data_key_token = response.get('data', {}).get('dataKeyToken')
        self.save_progress('datakeytoken: {}'.format(data_key_token))

        # create Restore Session
        restore_session_data = {
            'computerGuid': src_device_guid,
            'dataKeyToken': data_key_token
        }
        ret_val, response = self._make_rest_call(endpoint=CODE42_WEB_RESTORE_SESSION_ENDPOINT,
                                                action_result=action_result,
                                                data=restore_session_data,
                                                method='post')

        if phantom.is_fail(ret_val):
            self.append_to_message(CODE42_RESTORE_SESSION_CREATION_FAILED)
            return action_result.get_status()

        # grab the session id
        restore_session_id = response.get('data', {}).get('webRestoreSessionId')
        self.save_progress('restore_session_id: {}'.format(restore_session_id))

        # push restore job
        push_restore_data = {
            "webRestoreSessionId": restore_session_id,
            "sourceGuid": src_device_guid,
            "targetNodeGuid": target_node_guid,
            "acceptingGuid": accepting_device_guid,
            "restorePath": param['restore_path'],
            "pathSet": file_path_json_list,
            "numBytes": 1,
            "numFiles": 1,
            "showDeleted": True,
            "restoreFullPath": True,
        }
        ret_val, response = self._make_rest_call(endpoint=CODE42_PUSH_RESTORE_JOB_ENDPOINT,
                                                action_result=action_result,
                                                data=push_restore_data,
                                                method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        push_restore_response = response.get('data', {})
        push_restore_response[CODE42_JSON_WEB_RESTORE_SESSION_ID] = restore_session_id

        action_result.add_data(push_restore_response)

        # job creation success, add Restore ID to summary
        summary = action_result.update_summary({})
        summary[CODE42_JSON_RESTORE_ID] = push_restore_response.get('restoreId')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_check_restore_status(self, param):
        """ This function is used to check the status of a restore job.

        :param param: Dictionary of input parameters
        :return: status(success/failure)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # get restore id
        restore_id = param[CODE42_JSON_RESTORE_ID]

        # Generate new auth token before making REST call
        ret_val_token = self._generate_token(action_result=action_result)

        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        endpoint = CODE42_CHECK_RESTORE_STATUS_ENDPOINT.format(restore_id=restore_id)

        ret_val, response = self._make_rest_call(endpoint=endpoint,
                                                action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response.get('data'):
            action_result.add_data(response.get('data'))
        else:
            # add to action result data
            action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Retrieved restore info successfully")

    def _handle_get_organization_info(self, param):
        """
        Retrieve tenantUid for a given Cod42 Console User
        Example cURL:
        curl -X GET 'https://console.us.code42.com/c42api/v3/customer/my'
        --header 'Authorization: v3_user_token '$tkn' | python -m json.tool | grep tenantUid
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = "{}{}".format(self._server_url, CODE42_V3_TOKEN_AUTH_ENDPOINT)

        try:
            r = requests.get(url, auth=(self._username, self._password))
            v3_user_token = r.json().get('data', {}).get('v3_user_token')

            headers = {"Authorization": "v3_user_token {}".format(v3_user_token)}

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, CODE42_CONNECTION_FAILED)

        try:
            url2 = "{}{}".format(self._server_url, CODE42_ORGANIZATION_INFO_ENDPOINT)
            r = requests.get(url2, headers=headers).json()

            action_result.add_data(r['data'])
            return action_result.set_status(phantom.APP_SUCCESS, "Retrieved organization info successfully")

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Exception while retrieving Organization Info: {}".format(err_msg))

    def _handle_add_departing_employee(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        departing_employee_url = param['departing_employee_url'].strip('/')
        departing_user = param['departing_user']
        tenant_id = param['tenant_id']
        departure_date = param.get('departure_date')
        departure_notes = param.get('departure_notes', '')
        cloud_username = []
        if param.get('cloud_usernames'):
            cloud_username = param.get('cloud_usernames')
            cloud_username = [x.strip() for x in cloud_username.split(',')]
            cloud_username = list(filter(None, cloud_username))

        url = "{}{}".format(self._server_url, CODE42_V3_TOKEN_AUTH_ENDPOINT)

        try:
            r = requests.get(url, auth=(self._username, self._password))
            v3_user_token = r.json()['data']['v3_user_token']

        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, CODE42_CONNECTION_FAILED)

        headers = {
            'Authorization': 'v3_user_token {}'.format(v3_user_token),
            'Content-type': 'application/json'
        }

        ret_val_token = self._generate_token(action_result=action_result)
        if phantom.is_fail(ret_val_token):
            return action_result.get_status()

        ret_val, user_id = self.is_valid_identifier(departing_user, action_result, True)
        if phantom.is_fail(ret_val):
            self.debug_print(CODE42_INVALID_DEPARTING_USER_MSG)
            return action_result.set_status(phantom.APP_ERROR, CODE42_INVALID_DEPARTING_USER_MSG)

        # create detection profile
        url = "{}{}".format(departing_employee_url, CODE42_CREATE_DETECTION_LIST_PROFILE_ENDPOINT)
        body = {
            'tenantId': tenant_id,
            'userName': departing_user,
            'notes': departure_notes,
            'cloudUsernames': cloud_username
        }

        message = ""
        try:
            # create user profile for detection list
            res = requests.post(url, json=body, headers=headers)
            r = res.json()
            if 'pop-bulletin' in r and 'User already exists' in r['pop-bulletin']['reason']:
                if departure_notes or cloud_username:
                    body = {
                        "tenantId": tenant_id,
                        "username": departing_user
                    }
                    url = "{}{}".format(departing_employee_url, CODE42_GET_PROFILE_BY_USERNAME)
                    r = requests.post(url, json=body, headers=headers).json()
                    if 'pop-bulletin' in r:
                        return action_result.set_status(phantom.APP_ERROR, "Code42 Server Error: {}".format(str(r)))

                    # adding cloudusername in the profile
                    if departing_user not in cloud_username:
                        cloud_username.append(departing_user)
                    if len(cloud_username) > 1 and not set(r['cloudUsernames']) == set(cloud_username):
                        body = {
                            "tenantId": tenant_id,
                            "userId": r['userId'],
                            "cloudUsernames": cloud_username
                        }
                        url = "{}{}".format(departing_employee_url, CODE42_UPDATE_CLOUD_USERNAMES)
                        r = requests.post(url, json=body, headers=headers).json()
                        if 'pop-bulletin' in r:
                            return action_result.set_status(phantom.APP_ERROR, "Code42 Server Error: {}".format(str(r)))
                        else:
                            message += "Cloud Usernames added. "

                    # updating notes
                    if departure_notes and (r.get('notes') != departure_notes):
                        body = {
                            "tenantId": tenant_id,
                            "userId": r['userId'],
                            "notes": departure_notes
                        }
                        url = "{}{}".format(departing_employee_url, CODE42_UPDATE_NOTES)
                        r = requests.post(url, json=body, headers=headers).json()
                        if 'pop-bulletin' in r:
                            if message:
                                status_message = "{} Code42 Server Error: {}".format(message, str(r))
                            else:
                                status_message = "Code42 Server Error: {}".format(str(r))
                            return action_result.set_status(phantom.APP_ERROR, status_message)
                        else:
                            message += "Notes added/updated. "
            elif 'pop-bulletin' in r:
                return action_result.set_status(phantom.APP_ERROR, "Code42 Server Error: {}".format(str(r)))
            elif 200 <= r.status_code < 399:
                message += "Detection list profile created. "
            else:
                message = "Error from server. Status Code: {0} Data from server: {1}".format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))
                return action_result.set_status(phantom.APP_ERROR, message)

            body = {
                'tenantId': tenant_id,
                'userId': user_id,
                'departureDate': departure_date
            }

            # adding departing employee
            url = "{}{}".format(departing_employee_url, CODE42_DEPARTING_EMPLOYEE_V2_ENDPOINT)
            r = requests.post(url, json=body, headers=headers).json()

            if 'pop-bulletin' in r:
                if message:
                    status_message = "{} Code42 Server Error: {}".format(message, str(r))
                else:
                    status_message = "Code42 Server Error: {}".format(str(r))
                return action_result.set_status(phantom.APP_ERROR, status_message)

            if 'createdAt' in r:
                # SUCCESS
                action_result.add_data(r)
                summary = action_result.update_summary({})
                departing_message = "Departing Employee Addition was Successful - Created Time: {}".format(r['createdAt'])
                if message:
                    summary['message'] = "{} {}".format(message, departing_message)
                else:
                    summary['message'] = departing_message
                return action_result.set_status(phantom.APP_SUCCESS)

            else:
                return action_result.set_status(phantom.APP_ERROR, "{} Unexpected Response: {}".format(message, r))

        except Exception:
            err_msg = "Unexpected API response "
            return action_result.set_status(phantom.APP_ERROR, "{} Exception while making POST request: Status Code : {}. {}".format(message, r.status_code, err_msg))

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'list_users': self._handle_list_users,
            'get_user': self._handle_get_user,
            'list_devices': self._handle_list_devices,
            'unblock_device': self._handle_unblock_device,
            'block_device': self._handle_block_device,
            'activate_user': self._handle_activate_user,
            'deactivate_user': self._handle_deactivate_user,
            'deactivate_device': self._handle_deactivate_device,
            'activate_device': self._handle_activate_device,
            'deauthorize_device': self._handle_deauthorize_device,
            'list_organizations': self._handle_list_organizations,
            'change_organization': self._handle_change_organization,
            'lock_device': self._handle_lock_device,
            'unlock_device': self._handle_unlock_device,
            'get_device': self._handle_get_device,
            'push_restore': self._handle_push_restore,
            'check_restore_status': self._handle_check_restore_status,
            'hunt_file': self._handle_hunt_file,
            'run_query': self._handle_run_query,
            'get_organization_info': self._handle_get_organization_info,
            'add_departing_employee': self._handle_add_departing_employee
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in list(action_mapping.keys()):
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS.
        """

        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        try:
            self._username = config[CODE42_CONFIG_USERNAME].encode('utf-8')
            self._server_url = config[CODE42_CONFIG_SERVER_URL].strip('/')
        except:
            self.debug_print('Error while encoding username or server URL')
            return self.set_status(phantom.APP_ERROR, "Error while encoding username or server URL")

        self._password = config[CODE42_CONFIG_PASSWORD]
        self.set_validator('ip', self._is_ip)

        self.set_validator('ipv6', self._is_ip)

        return phantom.APP_SUCCESS

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address
        # If interface is present in the IP, it will be separated by the %
        if '%' in input_ip_address:
            ip_address_input = input_ip_address.split('%')[0]

        try:
            ipaddress.ip_address(ip_address_input)
        except:
            return False

        return True

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


if __name__ == '__main__':

    import sys
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
            login_url = BaseConnector._get_phantom_base_url() + "login"
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: {}".format(str(e)))
            exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = Code42Connector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
