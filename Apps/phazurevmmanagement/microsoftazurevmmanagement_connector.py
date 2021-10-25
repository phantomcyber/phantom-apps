# File: microsoftazurevmmanagement_connector.py
#
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from django.http import HttpResponse
from microsoftazurevmmanagement_consts import *
from bs4 import BeautifulSoup

import requests
import json
import time
import pwd
import grp
import os
import sys
import re
import ipaddress


def _handle_login_redirect(request, key):
    """ This function is used to redirect login request to microsoft login page.

    :param request: Data given to REST endpoint
    :param key: Key to search in state file
    :return: response authorization_url/admin_consent_url
    """

    asset_id = request.GET.get('asset_id')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL', content_type="text/plain", status=400)
    state = _load_app_state(asset_id)
    if not state:
        return HttpResponse('ERROR: Invalid asset_id', content_type="text/plain", status=400)
    url = state.get(key)
    if not url:
        return HttpResponse('App state is invalid, {key} not found.'.format(key=key), content_type="text/plain", status=400)
    response = HttpResponse(status=302)
    response['Location'] = url
    return response


def _load_app_state(asset_id, app_connector=None):
    """ This function is used to load the current state file.

    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: state: Current state file as a dictionary
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.dirname(os.path.abspath(__file__))
    state_file = '{0}/{1}_state.json'.format(app_dir, asset_id)
    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    state = {}
    try:
        with open(real_state_file_path, 'r') as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)
    except Exception as e:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Exception: {0}'.format(str(e)))

    if app_connector:
        app_connector.debug_print('Loaded state: ', state)

    return state


def _save_app_state(state, asset_id, app_connector):
    """ This function is used to save current state in file.

    :param state: Dictionary which contains data to write in state file
    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: status: phantom.APP_SUCCESS
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.split(__file__)[0]
    state_file = '{0}/{1}_state.json'.format(app_dir, asset_id)

    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == app_dir:
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    if app_connector:
        app_connector.debug_print('Saving state: ', state)

    try:
        with open(real_state_file_path, 'w+') as state_file_obj:
            state_file_obj.write(json.dumps(state))
    except Exception as e:
        print('Unable to save state file: {0}'.format(str(e)))

    return phantom.APP_SUCCESS


def _handle_login_response(request):
    """ This function is used to get the login response of authorization request from microsoft login page.

    :param request: Data given to REST endpoint
    :return: HttpResponse. The response displayed on authorization URL page
    """

    asset_id = request.GET.get('state')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL\n{}'.format(json.dumps(request.GET)), content_type="text/plain", status=400)

    # Check for error in URL
    error = request.GET.get('error')
    error_description = request.GET.get('error_description')

    # If there is an error in response
    if error:
        message = 'Error: {0}'.format(error)
        if error_description:
            message = '{0} Details: {1}'.format(message, error_description)
        return HttpResponse('Server returned {0}'.format(message), content_type="text/plain", status=400)

    code = request.GET.get('code')
    admin_consent = request.GET.get('admin_consent')

    # If none of the code or admin_consent is available
    if not (code or admin_consent):
        return HttpResponse('Error while authenticating\n{0}'.format(json.dumps(request.GET)), content_type="text/plain", status=400)

    state = _load_app_state(asset_id)

    # If value of admin_consent is available
    if admin_consent:
        if admin_consent == 'True':
            admin_consent = True
        else:
            admin_consent = False

        state['admin_consent'] = admin_consent
        _save_app_state(state, asset_id, None)

        # If admin_consent is True
        if admin_consent:
            return HttpResponse('Admin Consent received. Please close this window.', content_type="text/plain")
        return HttpResponse('Admin Consent declined. Please close this window and try again later.', content_type="text/plain", status=400)

    # If value of admin_consent is not available, value of code is available
    state['code'] = code
    _save_app_state(state, asset_id, None)

    return HttpResponse('Code received. Please close this window, the action will continue to get new token.', content_type="text/plain")


def _handle_rest_request(request, path_parts):
    """ Handle requests for authorization.

    :param request: Data given to REST endpoint
    :param path_parts: parts of the URL passed
    :return: dictionary containing response parameters
    """

    if len(path_parts) < 2:
        return HttpResponse('error: True, message: Invalid REST endpoint request', content_type="text/plain", status=400)

    call_type = path_parts[1]

    # To handle admin_consent request in get_admin_consent action
    if call_type == 'admin_consent':
        return _handle_login_redirect(request, 'admin_consent_url')

    # To handle authorize request in test connectivity action
    if call_type == 'start_oauth':
        return _handle_login_redirect(request, 'admin_consent_url')

    # To handle response from microsoft login page
    if call_type == 'result':
        return_val = _handle_login_response(request)
        asset_id = request.GET.get('state')
        if asset_id and asset_id.isalnum():
            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, asset_id, TC_FILE)
            real_auth_status_file_path = os.path.abspath(auth_status_file_path)
            if not os.path.dirname(real_auth_status_file_path) == app_dir:
                return HttpResponse("Error: Invalid asset_id", content_type="text/plain", status=400)
            open(auth_status_file_path, 'w').close()
            try:
                uid = pwd.getpwnam('apache').pw_uid
                gid = grp.getgrnam('phantom').gr_gid
                os.chown(auth_status_file_path, uid, gid)
                os.chmod(auth_status_file_path, 0o600)
            except:
                pass

        return return_val
    return HttpResponse('error: Invalid endpoint', content_type="text/plain", status=404)


def _get_dir_name_from_app_name(app_name):
    """ Get name of the directory for the app.

    :param app_name: Name of the application for which directory name is required
    :return: app_name: Name of the directory for the application
    """

    app_name = ''.join([x for x in app_name if x.isalnum()])
    app_name = app_name.lower()
    if not app_name:
        app_name = 'app_for_phantom'
    return app_name


class RetVal(tuple):

    def __new__(cls, val1, val2):

        return tuple.__new__(RetVal, (val1, val2))


class MicrosoftAzureVmManagementConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(MicrosoftAzureVmManagementConnector, self).__init__()

        self._state = None
        self._tenant = None
        self._subscription = None
        self._client_id = None
        self._client_secret = None
        self._admin_access = True
        self._admin_consent = True
        self._access_token = None
        self._refresh_token = None

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and returns True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        try:
            ipaddress.ip_address(input_ip_address)
        except ValueError:
            return False

        return True

    def _process_empty_response(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200 or response.status_code == 202:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = MS_AZURE_ERR_MSG.format(status_code=status_code, err_msg=error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        if status_code == 400:
            message = MS_AZURE_ERR_MSG.format(status_code=status_code, err_msg=MS_AZURE_HTML_ERROR)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """ This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(error_msg)), None)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # Show only error message if available
        if resp_json.get('error') and isinstance(resp_json.get('error', {}), dict):
            resp_code = resp_json.get('error', {}).get('code')
            resp_msg = resp_json.get('error', {}).get('message')
            if resp_code and resp_msg:
                message = "{0}. {1}. Response code from server: {2}".format(MS_AZURE_SERVER_ERR_MSG,
                                                                            MS_AZURE_ERR_MSG.format(status_code=response.status_code, err_msg=resp_msg),
                                                                            resp_code)
            elif resp_msg:
                message = "{0}. {1}".format(MS_AZURE_SERVER_ERR_MSG, MS_AZURE_ERR_MSG.format(status_code=response.status_code, err_msg=resp_msg))
        elif resp_json.get('error'):
            message = "{0}. {1}".format(MS_AZURE_SERVER_ERR_MSG,
                                        MS_AZURE_ERR_MSG.format(status_code=response.status_code, err_msg=resp_json['error']))
        else:
            message = "{0}. {1}".format(MS_AZURE_SERVER_ERR_MSG,
                                        MS_AZURE_ERR_MSG.format(status_code=response.status_code,
                                                                err_msg=response.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process html response.

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

        if 'text/javascript' in response.headers.get('Content-Type', ''):
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

        # everything else is actually an error at this point
        message = "Can't process response from server. {0}".format(
            MS_AZURE_ERR_MSG.format(status_code=response.status_code, err_msg=response.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_error_message_from_exception(self, e):
        """ This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_msg = MS_AZURE_UNKNOWN_ERR_MSG
        error_code = MS_AZURE_ERR_CODE_UNAVAILABLE
        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = MS_AZURE_ERR_CODE_UNAVAILABLE
                    error_msg = e.args[0]
            else:
                error_code = MS_AZURE_ERR_CODE_UNAVAILABLE
                error_msg = MS_AZURE_UNKNOWN_ERR_MSG
        except:
            error_code = MS_AZURE_ERR_CODE_UNAVAILABLE
            error_msg = MS_AZURE_UNKNOWN_ERR_MSG

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _get_asset_name(self, action_result):
        """ Get name of the asset using Phantom URL.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), asset name
        """

        asset_id = self.get_asset_id()
        rest_endpoint = MS_AZURE_PHANTOM_ASSET_INFO_URL.format(asset_id=asset_id)
        url = '{}{}'.format(MS_AZURE_PHANTOM_BASE_URL.format(phantom_base_url=self._get_phantom_base_url()), rest_endpoint)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)

        if phantom.is_fail(ret_val):
            return ret_val, None

        asset_name = resp_json.get('name')
        if not asset_name:
            return action_result.set_status(phantom.APP_ERROR, 'Asset Name for id: {0} not found.'.format(asset_id)), None
        return phantom.APP_SUCCESS, asset_name

    def _get_phantom_base_url_vmazure(self, action_result):
        """ Get base url of phantom.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        base url of phantom
        """

        url = '{}{}'.format(MS_AZURE_PHANTOM_BASE_URL.format(phantom_base_url=self._get_phantom_base_url()), MS_AZURE_PHANTOM_SYS_INFO_URL)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)
        if phantom.is_fail(ret_val):
            return ret_val, None

        phantom_base_url = resp_json.get('base_url').strip("/")
        if not phantom_base_url:
            return action_result.set_status(phantom.APP_ERROR, MS_AZURE_BASE_URL_NOT_FOUND_MSG), None
        return phantom.APP_SUCCESS, phantom_base_url

    def _get_app_rest_url(self, action_result):
        """ Get URL for making rest calls.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        URL to make rest calls
        """

        ret_val, phantom_base_url = self._get_phantom_base_url_vmazure(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        ret_val, asset_name = self._get_asset_name(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        self.save_progress('Using Phantom base URL as: {0}'.format(phantom_base_url))
        app_json = self.get_app_json()
        app_name = app_json['name']

        app_dir_name = _get_dir_name_from_app_name(app_name)
        url_to_app_rest = '{0}/rest/handler/{1}_{2}/{3}'.format(phantom_base_url, app_dir_name, app_json['appid'],
                                                                asset_name)
        return phantom.APP_SUCCESS, url_to_app_rest

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
        except requests.exceptions.InvalidSchema:
            error_message = 'Error connecting to server. No connection adapters were found for {}'.format(endpoint)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.InvalidURL:
            error_message = 'Error connecting to server. Invalid URL {}'.format(endpoint)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.ConnectionError:
            error_message = 'Error Details: Connection Refused from the Server {}'.format(endpoint)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}"
                                                   .format(error_msg)), resp_json)

        return self._process_response(r, action_result)

    def _make_rest_call_helper(self, endpoint, action_result, verify=True, headers=None, params=None, data=None, json=None, method="get"):
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

        url = "{0}{1}".format(MS_BASE_URL.format(subscriptionId=self._subscription), endpoint)
        if headers is None:
            headers = {}

        if not self._access_token:
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        headers.update({
                'Authorization': 'Bearer {0}'.format(self._access_token),
                'Accept': 'application/json',
                'Content-Type': 'application/json'})

        ret_val, resp_json = self._make_rest_call(url, action_result, verify, headers, params, data, json, method)

        # If token is expired, generate a new token
        msg = action_result.get_message()

        if msg and any(message in msg for message in MS_AZURE_INVALID_TOKEN_MESSAGES):
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            headers.update({ 'Authorization': 'Bearer {0}'.format(self._access_token)})

            ret_val, resp_json = self._make_rest_call(url, action_result, verify, headers, params, data, json, method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _make_redirect_call(self, endpoint, action_result, verify=True, headers=None, params=None, data=None, json=None, method="get"):
        """ Function that handles instances where a redirect may be required.
        Default timeout for following the redirect location is 60 seconds.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), response, result_location
        """

        resp_json = None
        url = "{0}{1}".format(MS_BASE_URL.format(subscriptionId=self._subscription), endpoint)
        if headers is None:
            headers = {}

        if not self._access_token:
            ret_val = self._get_token(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        headers.update({
                'Authorization': 'Bearer {0}'.format(self._access_token),
                'Accept': 'application/json',
                'Content-Type': 'application/json'})

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json, None

        try:
            r = request_func(url, json=json, data=data, headers=headers, verify=verify, params=params)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_msg)), resp_json, None

        if r.text and any(message in r.text for message in MS_AZURE_INVALID_TOKEN_MESSAGES):
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), resp_json, None
            headers.update({ 'Authorization': 'Bearer {0}'.format(self._access_token)})
            try:
                r = request_func(url, json=json, data=data, headers=headers, verify=verify, params=params)
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_msg)), resp_json, None

        # Azure returns a status code 202 for Run Command if there is an Asynchronous Operation running
        if r.status_code == 202:
            # Headers for the response store the AsyncOperation url which is used to track the operation status.
            # The Location field stores the results of the command when it is finished running
            request_func = getattr(requests, "get")
            operation_status = r.headers.get('Azure-AsyncOperation')
            location_url = r.headers.get('Location')
            if operation_status:
                status = "InProgress"
                count = 0
                # It can take some time for the results to be ready.
                # A default count of 60 seconds is provided to check results.
                while count < 20 or (status and status == "InProgress"):
                    time.sleep(3)
                    try:
                        res = request_func(operation_status, headers=headers, verify=verify)
                        resp_json = res.json()
                    except Exception as e:
                        error_msg = self._get_error_message_from_exception(e)
                        return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_msg)), resp_json, None
                    if any(message in res.text for message in MS_AZURE_INVALID_TOKEN_MESSAGES):
                        ret_val = self._get_token(action_result)
                        if phantom.is_fail(ret_val):
                            return action_result.get_status(), resp_json, None
                        headers.update({ 'Authorization': 'Bearer {0}'.format(self._access_token)})
                    status = resp_json.get('status')
                    count += 1
                try:
                    r = request_func(location_url, headers=headers, verify=verify)
                except Exception as e:
                    error_msg = self._get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_msg)), resp_json, None
                if r.text and any(message in r.text for message in MS_AZURE_INVALID_TOKEN_MESSAGES):
                    ret_val = self._get_token(action_result)
                    if phantom.is_fail(ret_val):
                        return action_result.get_status(), resp_json, None
                    headers.update({ 'Authorization': 'Bearer {0}'.format(self._access_token)})
                    try:
                        r = request_func(location_url, headers=headers, verify=verify)
                    except Exception as e:
                        error_msg = self._get_error_message_from_exception(e)
                        return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_msg)), resp_json, None
                ret_val, response = self._process_response(r, action_result)
                return ret_val, response, location_url
        elif r.status_code == 200:
            ret_val, response = self._process_response(r, action_result)
            return ret_val, response, None
        else:
            message = "Can't process response from server. {0}".format(
                MS_AZURE_ERR_MSG.format(status_code=r.status_code,
                err_msg=r.text.replace('{', '{{').replace('}', '}}')))

        return action_result.set_status(phantom.APP_ERROR, message), resp_json, None

    def _get_admin_access(self, action_result, app_rest_url, app_state):
        """ This function is used to get admin access for given credentials.

        :param action_result: Object of action result
        :param app_rest_url: REST URL created for app
        :return: status success/failure
        """

        # Create the url authorization, this is the one pointing to the oauth server side
        admin_consent_url = "https://login.microsoftonline.com/{0}/adminconsent".format(self._tenant)
        admin_consent_url += "?client_id={0}".format(self._client_id)
        admin_consent_url += "&redirect_uri={0}".format(app_state['redirect_uri'])
        admin_consent_url += "&state={0}".format(self.get_asset_id())

        app_state['admin_consent_url'] = admin_consent_url

        # The URL that the user should open in a different tab.
        # This is pointing to a REST endpoint that points to the app
        url_to_show = "{0}/start_oauth?asset_id={1}&".format(app_rest_url, self.get_asset_id())

        # Save the state, will be used by the request handler
        _save_app_state(app_state, self.get_asset_id(), self)

        self.save_progress(MS_AUTHORIZE_USER_MSG)
        self.save_progress(url_to_show)

        time.sleep(5)

        completed = False

        app_dir = os.path.dirname(os.path.abspath(__file__))
        auth_status_file_path = "{0}/{1}_{2}".format(app_dir, self.get_asset_id(), TC_FILE)

        self.save_progress('Waiting for authorization to complete')

        for i in range(0, 40):

            self.send_progress('{0}'.format('.' * (i % 10)))

            if os.path.isfile(auth_status_file_path):
                completed = True
                os.unlink(auth_status_file_path)
                break

            time.sleep(MS_TC_STATUS_SLEEP)

        if not completed:
            self.save_progress("Authentication process does not seem to be completed. Timing out")
            return self.set_status(phantom.APP_ERROR)

        self.send_progress("")

        # Load the state again, since the http request handlers would have saved the result of the admin consent
        app_state_temp = _load_app_state(self.get_asset_id(), self)

        if not app_state_temp:
            self.save_progress("Authorization not received or not given")
            self.save_progress("Test Connectivity Failed")
            return self.set_status(phantom.APP_ERROR)

        app_state = app_state_temp

        # The authentication seems to be done, let's see if it was successfull
        app_state['admin_consent'] = app_state.get('admin_consent', False)

        return self.set_status(phantom.APP_SUCCESS)

    def _handle_test_connectivity(self, param):
        """ This function is used to test the connectivity of an asset with given credentials.

        :param param: (not used in this method)
        :return: status success/failure
        """

        # Progress
        app_state = {}
        action_result = self.add_action_result(ActionResult(param))

        # if condition would be true only  for interactive OAuth
        if not self._admin_consent:
            self.save_progress("Getting App REST endpoint URL")
            # Get the URL to the app's REST endpoint, this is the url that the TC dialog
            # box will ask the user to connect to
            ret_val, app_rest_url = self._get_app_rest_url(action_result)

            if phantom.is_fail(ret_val):
                self.save_progress(MS_REST_URL_NOT_AVAILABLE_MSG.format(error=self.get_status()))
                return self.set_status(phantom.APP_ERROR)

            # create the url that the oauth server should re-direct to after the auth is completed
            # (success and failure), this is added to the state so that the request handler will access
            # it later on
            redirect_uri = "{0}/result".format(app_rest_url)
            app_state['redirect_uri'] = redirect_uri

            self.save_progress(MS_OAUTH_URL_MSG)
            self.save_progress(redirect_uri)

            if self._admin_access:
                result = self._get_admin_access(action_result, app_rest_url, app_state)
                if phantom.is_fail(result):
                    return self.get_status()

            admin_consent_url = "https://login.microsoftonline.com/{0}/oauth2/v2.0/authorize".format(self._tenant)
            admin_consent_url += "?client_id={0}".format(self._client_id)
            admin_consent_url += "&redirect_uri={0}".format(redirect_uri)
            admin_consent_url += "&state={0}".format(self.get_asset_id())
            admin_consent_url += "&scope={0}".format(MS_AZURE_CODE_GENERATION_SCOPE)
            admin_consent_url += "&response_type=code"

            app_state['admin_consent_url'] = admin_consent_url

            # The URL that the user should open in a different tab.
            # This is pointing to a REST endpoint that points to the app
            url_to_show = "{0}/start_oauth?asset_id={1}&".format(app_rest_url, self.get_asset_id())

            # Save the state, will be used by the request handler
            _save_app_state(app_state, self.get_asset_id(), self)

            self.save_progress(MS_AUTHORIZE_USER_MSG)
            self.save_progress(url_to_show)

            time.sleep(5)

            completed = False

            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = "{0}/{1}_{2}".format(app_dir, self.get_asset_id(), TC_FILE)

            self.save_progress('Waiting for authorization to complete')

            for i in range(0, 40):

                self.send_progress('{0}'.format('.' * (i % 10)))

                if os.path.isfile(auth_status_file_path):
                    completed = True
                    os.unlink(auth_status_file_path)
                    break

                time.sleep(MS_TC_STATUS_SLEEP)

            if not completed:
                self.save_progress("Authentication process does not seem to be completed. Timing out")
                return self.set_status(phantom.APP_ERROR)

            self.send_progress("")

            # Load the state again, since the http request handlers would have saved the result of the admin consent
            self._state = _load_app_state(self.get_asset_id(), self)

            if not self._state:
                self.save_progress("Authorization not received or not given")
                self.save_progress("Test Connectivity Failed")
                return self.set_status(phantom.APP_ERROR)

            # The authentication seems to be done, let's see if it was successfull
            self._state['admin_consent'] = self._state.get('admin_consent', False)

        self.save_progress(MS_GENERATING_ACCESS_TOKEN_MSG)
        ret_val = self._get_token(action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress("Getting list of all VMs to verify token")

        ret_val, response = self._make_rest_call_helper(VM_LIST_VMS_ALL_ENDPOINT, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("API to get VMs failed")
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR)
        else:
            self.save_progress("Retrieved list of VMs")

        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_system_info(self, param):
        """ This function is used to handle the get system info action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        vm_name = param.get('vm_name')

        # make rest call
        endpoint = VM_GET_SYSTEM_INFO_ENDPOINT.format(resourceGroupName=resource_group_name, vmName=vm_name)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "The system info was successfully retrieved")

    def _handle_list_vms(self, param):
        """ This function is used to handle the list vms action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')

        if resource_group_name:
            endpoint = VM_LIST_VMS_RESOURCE_GROUP_ENDPOINT.format(resourceGroupName=resource_group_name)
        else:
            endpoint = VM_LIST_VMS_ALL_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        values = response.get('value', [])
        for vm in values:
            action_result.add_data(vm)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_vms'] = len(values)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_snapshot_vm(self, param):
        """ This function is used to handle the snapshot vm action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        snapshot_name = param.get('snapshot_name')
        location = param['location']

        create_option = param['create_option']
        source_resource_id = param.get('source_resource_id', None)
        source_uri = param.get('source_uri', None)

        # make rest call
        endpoint = VM_SNAPSHOT_VM_ENDPOINT.format(resourceGroupName=resource_group_name, snapshotName=snapshot_name)

        body = {
            "name": snapshot_name,
            "location": location,
            "properties": {
                "creationData": {
                    "createOption": create_option
                }
            }
        }

        if source_resource_id:
            body['properties']['creationData'].update({ 'sourceResourceId': source_resource_id })
        if source_uri:
            body['properties']['creationData'].update({ 'sourceUri': source_uri })

        ret_val, response = self._make_rest_call_helper(endpoint, action_result, json=body, method='put')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = "Successfully created snapshot"
        summary['provisioning_state'] = response.get('properties', {}).get('provisioningState', 'Unavailable')

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_start_vm(self, param):
        """ This function is used to handle the start vm action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        vm_name = param.get('vm_name')

        # make rest call
        endpoint = VM_ACTION_ENDPOINT.format(resourceGroupName=resource_group_name, vmName=vm_name, action="/start")
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = "Successfully started VM"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_stop_vm(self, param):
        """ This function is used to handle the stop vm action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        vm_name = param.get('vm_name')

        # make rest call
        endpoint = VM_ACTION_ENDPOINT.format(resourceGroupName=resource_group_name, vmName=vm_name, action="/powerOff")
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = "Successfully stopped VM"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_deallocate_vm(self, param):
        """ This function is used to handle the deallocate vm action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        vm_name = param.get('vm_name')

        # make rest call
        endpoint = VM_ACTION_ENDPOINT.format(resourceGroupName=resource_group_name, vmName=vm_name, action="/deallocate")
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = "Successfully deallocated VM"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_tags(self, param):
        """ This function is used to handle the list tags action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._make_rest_call_helper(VM_LIST_TAGS_ENDPOINT, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into thetag
        values = response.get('value', [])
        for tag in values:
            action_result.add_data(tag)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_tags'] = len(values)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def create_tag_name(self, action_result, tag_name):
        """ This function is used to create tag name.

        :param action_result: Object of action result
        :param tag_name: Name of the tag
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        endpoint = VM_CREATE_TAG_ENDPOINT.format(tagName=tag_name, tagValue='')
        return self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, method='put')

    def _handle_create_tag(self, param):
        """ This function is used to handle the create tag action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        tag_name = param.get('tag_name')
        tag_value = param.get('tag_value')

        # If not tag_value, then create tag_name
        if not tag_value:
            ret_val, response = self.create_tag_name(action_result, tag_name)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # Add the response into the data section
            action_result.add_data(response)
        else:
            # Check if you're creating a new name=value pair, or updating the value of an already existing tag name
            value = VM_CREATE_TAG_VALUE_PART.format(tagValue=tag_value)
            endpoint = VM_CREATE_TAG_ENDPOINT.format(tagName=tag_name, tagValue=value)
            ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, method='put')

            if phantom.is_fail(ret_val):
                msg = action_result.get_message()
                if 'PredefinedTagNameNotFound' in msg:
                    # Need to create the tag name first
                    ret_val, response = self.create_tag_name(action_result, tag_name)

                    if phantom.is_fail(ret_val):
                        return action_result.get_status()

                    # Add the response into the data section
                    action_result.add_extra_data(response)
                else:
                    return action_result.get_status()

            # Now that the tag name has been created, try updating it's value
            ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, method='put')

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # Add the response into the data section
            action_result.add_extra_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = "Successfully created tag"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_resource_groups(self, param):
        """ This function is used to handle the list resource groups action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._make_rest_call_helper(VM_RESOURCE_GROUP_ENDPOINT, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        values = response.get('value', [])
        for rg in values:
            action_result.add_data(rg)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_resource_groups'] = len(values)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_snapshots(self, param):
        """ This function is used to handle the list snapshots action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')

        if resource_group_name:
            resource_part = VM_RESOURCE_GROUP_VALUE_PART.format(resourceGroupName=resource_group_name)
            endpoint = VM_LIST_SNAPSHOTS_ENDPOINT.format(resourceValue=resource_part)
        else:
            endpoint = VM_LIST_SNAPSHOTS_ENDPOINT.format(resourceValue='')

        # make rest call
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        values = response.get('value', [])
        for s in values:
            action_result.add_data(s)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_snapshots'] = len(values)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_security_groups(self, param):
        """ This function is used to handle the list security groups action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        group_type = param.get('group_type')

        if group_type == 'network':
            endpoint = VM_SECURITY_GROUP_ENDPOINT.format(resourceGroupName=resource_group_name, groupType='networkSecurityGroups', groupName='')
        elif group_type == 'application':
            endpoint = VM_SECURITY_GROUP_ENDPOINT.format(resourceGroupName=resource_group_name, groupType='applicationSecurityGroups', groupName='')
        else:
            return action_result.set_status(phantom.APP_ERROR, MS_AZURE_GROUP_TYPE_ERR_MSG)

        # make rest call
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        values = response.get('value', [])
        for s in values:
            action_result.add_data(s)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_security_groups'] = len(values)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_network_security_group(self, param):
        """ This function is used to handle the add network security group action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        group_name = param.get('group_name')
        location = param.get('location')
        tags = param.get('tags')
        default_security_rules = param.get('default_security_rules')
        provisioning_state = param.get('provisioning_state')
        resource_guid = param.get('resource_guid')
        security_rules = param.get('security_rules')

        endpoint = VM_SECURITY_GROUP_ENDPOINT.format(resourceGroupName=resource_group_name, groupType='networkSecurityGroups', groupName='/{}'.format(group_name))
        body = {
            "location": location,
            "properties": {},
            "tags": {}
        }

        try:
            if tags:
                sg_tags = json.loads(tags)
                body['tags'].update(sg_tags)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, MS_AZURE_INVALID_JSON.format(err_msg=error_msg, param='tags'))
        if default_security_rules:
            body['properties'].update({'defaultSecurityRules': default_security_rules})
        if provisioning_state:
            body['properties'].update({'provisioningState': provisioning_state})
        if resource_guid:
            body['properties'].update({'resourceGuid': resource_guid})
        try:
            if security_rules:
                security_rules = json.loads(security_rules)
                body['properties'].update({'securityRules': security_rules})
        except:
            body['properties'].update({'securityRules': security_rules})
        # make rest call
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, json=body, method='put')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = "Successfully added or updated security group"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_application_security_group(self, param):
        """ This function is used to handle the add application security group action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        group_name = param.get('group_name')
        location = param.get('location')
        tags = param.get('tags')

        endpoint = VM_SECURITY_GROUP_ENDPOINT.format(resourceGroupName=resource_group_name, groupType='applicationSecurityGroups', groupName='/{}'.format(group_name))
        body = {
            "location": location,
            "tags": {}
        }

        try:
            if tags:
                sg_tags = json.loads(tags)
                body['tags'].update(sg_tags)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, MS_AZURE_INVALID_JSON.format(err_msg=error_msg, param='tags'))

        # make rest call
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, json=body, method='put')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = "Successfully added or updated security group"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_virtual_networks(self, param):
        """ This function is used to handle the list virtual networks action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')

        if resource_group_name:
            endpoint = VM_LIST_VIRTUAL_NETWORKS_ENDPOINT.format(resourceGroup='/resourceGroups/{}'.format(resource_group_name))
        else:
            endpoint = VM_LIST_VIRTUAL_NETWORKS_ENDPOINT.format(resourceGroup='')

        # make rest call
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        values = response.get('value', [])
        for s in values:
            action_result.add_data(s)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_virtual_networks'] = len(values)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_subnets(self, param):
        """ This function is used to handle the list subnets action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        virtual_network_name = param.get('virtual_network_name')

        # make rest call
        endpoint = VM_LIST_SUBNETS_ENDPOINT.format(resourceGroupName=resource_group_name, virtualNetworkName=virtual_network_name)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        values = response.get('value', [])
        for s in values:
            action_result.add_data(s)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_subnets'] = len(values)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_vm(self, param):
        """ This function is used to handle the delete vm action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        vm_name = param.get('vm_name')

        # make rest call
        endpoint = VM_GET_SYSTEM_INFO_ENDPOINT.format(resourceGroupName=resource_group_name, vmName=vm_name)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, method='delete')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = "Successfully deleted the vm"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_check_address_availability(self, param):
        """ This function is used to handle the check address availability action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        virtual_network_name = param.get('virtual_network_name')
        ip_address = param.get('ip_address')

        # make rest call
        endpoint = VM_CHECK_IP_AVAIL.format(resourceGroup=resource_group_name, virtualNetwork=virtual_network_name, ip=ip_address)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        for item in response.get('availableIPAddresses', []):
            action_result.add_data({ 'availableAddress': item })

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_ips_available'] = len(response.get('availableIPAddresses', []))
        summary['available'] = response.get('available')

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_generalize_vm(self, param):
        """ This function is used to handle the generalize vm action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        vm_name = param.get('vm_name')

        # make rest call
        endpoint = VM_ACTION_ENDPOINT.format(resourceGroupName=resource_group_name, vmName=vm_name, action='generalize')
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, method='post')

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})

        if 'OperationNotAllowed' in action_result.get_message() and 'Please power off' in action_result.get_message():
            summary['status'] = "Virtual machine must be powered off. Please power off the vm before generalizing it."

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        summary['status'] = "Successfully generalized the vm"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_redeploy_vm(self, param):
        """ This function is used to handle the redeploy vm action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        vm_name = param.get('vm_name')

        # make rest call
        endpoint = VM_ACTION_ENDPOINT.format(resourceGroupName=resource_group_name, vmName=vm_name, action='redeploy')
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, method='post')

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})

        if 'was not found' in action_result.get_message():
            summary['status'] = "Virtual machine not found under resource"

        if 'could not be found' in action_result.get_message():
            summary['status'] = "Resource group could not be found"

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        summary['status'] = "Successfully redeployed the vm"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_command(self, param):
        """ This function is used to handle the run command action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        resource_group_name = param.get('resource_group_name')
        vm_name = param.get('vm_name')
        script = param.get('script')
        script_parameters = param.get('script_parameters')

        # If script or parameters were provided, ensure they are both wrapped inside a list to be accepted by Azure
        if script:
            try:
                script_json = json.loads(script)
            except ValueError:
                # If param['script'] is not JSON then treat it as a regular string
                script = [script]
            else:
                if not isinstance(script_json, list):
                    script = [script_json]
                else:
                    script = script_json
        if script_parameters:
            try:
                script_param_json = json.loads(script_parameters)
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, "'script_parameters' input is not a JSON dictionary")
            else:
                if not isinstance(script_param_json, list):
                    script_parameters = [script_param_json]
                else:
                    script_parameters = script_param_json

        data = {"commandId": param['command_id'], "script": script, "parameters": script_parameters}

        # make rest call
        endpoint = VM_RUN_COMMAND_ENDPOINT.format(resourceGroupName=resource_group_name, vmName=vm_name)
        ret_val, response, results_url = self._make_redirect_call(endpoint, action_result, params=None, headers=None, json=data, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add a cleaner response into the data section
        if isinstance(response, list):
            data = {'results_url': results_url, 'results': [item for item in response]}
            for index, result in enumerate(data['results']):
                if result.get('message'):
                    try:
                        message_json = json.loads(result.get('message'))
                    except Exception as e:
                        err_msg = self._get_error_message_from_exception(e)
                        self.debug_print("No json data in results message: {}".format(err_msg))
                    else:
                        data['results'][index]['message'] = message_json
            action_result.add_data(data)
        else:
            data = {'results_url': results_url, 'results': response}
            action_result.add_data(data)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['status'] = "Successfully executed command"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_results(self, param):
        """ This function is used to handle the get run command results action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)

        """
        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        results_url = param['results_url']
        # Capture information from param results_url and ensure that the subscription id matches the asset
        pattern = re.compile(r'https:\/\/[^\/]+\/subscriptions\/([^\/]+)(.+)')
        try:
            subscription_id, endpoint = re.search(pattern, results_url).groups()
        except AttributeError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid value in the 'results_url' action parameter")

        if subscription_id != self._subscription:
            return action_result.set_status(phantom.APP_ERROR,
                "Cannot retrieve 'run command' results from a different Azure Subscription than the configured Subscription on this asset")

        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=None, headers=None, method='get')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add a cleaner response into the data section
        if isinstance(response, list):
            data = {'results_url': results_url, 'results': [item for item in response]}
            for index, result in enumerate(data['results']):
                if result.get('message'):
                    try:
                        message_json = json.loads(result.get('message'))
                    except Exception as e:
                        err_msg = self._get_error_message_from_exception(e)
                        self.debug_print("No json data in results message: {}".format(err_msg))
                    else:
                        data['results'][index]['message'] = message_json
            action_result.add_data(data)
        else:
            data = {'results_url': results_url, 'results': response}
            action_result.add_data(data)

        summary = action_result.update_summary({})
        summary['status'] = "Successfully fetched result"

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_token(self, action_result, from_action=False):
        """ This function is used to get a token via REST Call.

        :param action_result: Object of action result
        :param from_action: Boolean object of from_action
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'grant_type': 'client_credentials'
        }

        req_url = SERVER_TOKEN_URL.format(self._tenant)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        if self._admin_consent:
            # add the resource that is to be accessed for the non-interactive OAuth
            data['resource'] = 'https://management.azure.com/'
        else:
            if from_action or self._state.get('token', {}).get('refresh_token', None) is not None:
                data['refresh_token'] = self._state.get('token').get('refresh_token')
                data['grant_type'] = 'refresh_token'
            elif self._state.get('code'):
                data['redirect_uri'] = self._state.get('redirect_uri')
                data['code'] = self._state.get('code')
                data['grant_type'] = 'authorization_code'
            else:
                return action_result.set_status(phantom.APP_ERROR, "Unexpected details retrieved from the state file. Please run test connectivity first")

        ret_val, resp_json = self._make_rest_call(req_url, action_result, headers=headers, data=data, method='post')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state[MS_AZURE_TOKEN_STRING] = resp_json
        self._access_token = resp_json.get(MS_AZURE_ACCESS_TOKEN_STRING)

        if not self._admin_consent:
            # refresh token is only received of interactive OAuth
            self._refresh_token = resp_json.get(MS_AZURE_REFRESH_TOKEN_STRING)

        self.save_state(self._state)
        _save_app_state(self._state, self.get_asset_id(), self)

        self._state = self.load_state()

        # Scenario -
        #
        # If the corresponding state file doesn't have correct owner, owner group or permissions,
        # the newly generated token is not being saved to state file and automatic workflow for token has been stopped.
        # So we have to check that token from response and token which are saved to state file after successful generation of new token are same or not.

        if self._access_token != self._state.get(MS_AZURE_TOKEN_STRING, {}).get(MS_AZURE_ACCESS_TOKEN_STRING):
            return action_result.set_status(phantom.APP_ERROR, MS_AZURE_INVALID_PERMISSION_ERR)

        return (phantom.APP_SUCCESS)

    def _handle_generate_token(self, param):
        """ This function is used to handle the generate token action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._get_token(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state['admin_consent'] = True

        return action_result.set_status(phantom.APP_SUCCESS, "Token generated")

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_system_info':
            ret_val = self._handle_get_system_info(param)

        elif action_id == 'list_vms':
            ret_val = self._handle_list_vms(param)

        elif action_id == 'snapshot_vm':
            ret_val = self._handle_snapshot_vm(param)

        elif action_id == 'start_vm':
            ret_val = self._handle_start_vm(param)

        elif action_id == 'stop_vm':
            ret_val = self._handle_stop_vm(param)

        elif action_id == 'deallocate_vm':
            ret_val = self._handle_deallocate_vm(param)

        elif action_id == 'list_tags':
            ret_val = self._handle_list_tags(param)

        elif action_id == 'create_tag':
            ret_val = self._handle_create_tag(param)

        elif action_id == 'list_resource_groups':
            ret_val = self._handle_list_resource_groups(param)

        elif action_id == 'list_snapshots':
            ret_val = self._handle_list_snapshots(param)

        elif action_id == 'list_security_groups':
            ret_val = self._handle_list_security_groups(param)

        elif action_id == 'add_network_security_group':
            ret_val = self._handle_add_network_security_group(param)

        elif action_id == 'add_application_security_group':
            ret_val = self._handle_add_application_security_group(param)

        elif action_id == 'list_virtual_networks':
            ret_val = self._handle_list_virtual_networks(param)

        elif action_id == 'list_subnets':
            ret_val = self._handle_list_subnets(param)

        elif action_id == 'delete_vm':
            ret_val = self._handle_delete_vm(param)

        elif action_id == 'check_address_availability':
            ret_val = self._handle_check_address_availability(param)

        elif action_id == 'generalize_vm':
            ret_val = self._handle_generalize_vm(param)

        elif action_id == 'redeploy_vm':
            ret_val = self._handle_redeploy_vm(param)

        elif action_id == 'run_command':
            ret_val = self._handle_run_command(param)

        elif action_id == 'get_results':
            ret_val = self._handle_get_results(param)

        elif action_id == 'generate_token':
            ret_val = self._handle_generate_token(param)

        return ret_val

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Reseting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            return self.set_status(phantom.APP_ERROR, MS_AZURE_STATE_FILE_CORRUPT_ERROR)

        # get the asset config
        config = self.get_config()

        self._tenant = config[MS_AZURE_CONFIG_TENANT]
        self._subscription = config[MS_AZURE_CONFIG_SUBSCRIPTION]
        self._client_id = config[MS_AZURE_CONFIG_CLIENT_ID]
        self._client_secret = config[MS_AZURE_CONFIG_CLIENT_SECRET]
        self._admin_access = config.get(MS_AZURE_CONFIG_ADMIN_ACCESS)
        self._admin_consent = config.get(MS_AZURE_CONFIG_ADMIN_CONSENT)
        self._access_token = self._state.get(MS_AZURE_TOKEN_STRING, {}).get(MS_AZURE_ACCESS_TOKEN_STRING)
        self._refresh_token = self._state.get(MS_AZURE_TOKEN_STRING, {}).get(MS_AZURE_REFRESH_TOKEN_STRING)

        self.set_validator('ipv6', self._is_ip)

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
        _save_app_state(self._state, self.get_asset_id(), self)
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

    if (args.username and args.password):
        try:
            login_url = BaseConnector._get_phantom_base_url() + 'login'
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']
            data = {'username': args.username, 'password': args.password, 'csrfmiddlewaretoken': csrftoken}
            headers = {'Cookie': 'csrftoken={0}'.format(csrftoken), 'Referer': login_url}

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']

        except Exception as e:
            print("Unable to get session id from the platform. Error: {0}".format(str(e)))
            exit(1)

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MicrosoftAzureVmManagementConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
