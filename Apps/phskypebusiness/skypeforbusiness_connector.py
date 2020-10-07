# File: skypeforbusiness_connector.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import json
import os
import time
import uuid
import pwd
import grp
import requests
import base64
import sys
from bs4 import UnicodeDammit, BeautifulSoup
from django.http import HttpResponse

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from skypeforbusiness_consts import *

try:
    from urlparse import urlparse
    import urllib
except:
    from urllib.parse import urlparse
    import urllib.parse as urllib


def _handle_login_redirect(request, key):
    """ This function is used to redirect login request to Microsoft login page.

    :param request: Data given to REST endpoint
    :param key: Key to search in state file
    :return: response authorization_url/admin_consent_url
    """

    # Get asset ID
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


def _handle_login_response(request):
    """ This function is used to get the login response of authorization request from Microsoft login page.

    :param request: Data given to REST endpoint
    :return: HttpResponse. The response displayed on authorization URL page
    """

    # Get asset ID
    asset_id = request.GET.get('state')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL\n{}'.format(json.dumps(request.GET)), content_type="text/plain", status=400)

    # Check for error and description in URL
    error = request.GET.get('error')
    error_description = request.GET.get('error_description')

    # If there is an error in response
    if error:
        message = 'Error: {0}'.format(error)
        if error_description:
            message = '{0} Details: {1}'.format(message, error_description)
        return HttpResponse('Server returned {0}'.format(message), content_type="text/plain", status=400)

    # Code used for generating token
    code = request.GET.get('code')

    # If code is not available
    if not code:
        return HttpResponse('Error while authenticating\n{0}'.format(json.dumps(request.GET)), content_type="text/plain", status=400)

    state = _load_app_state(asset_id)
    state['code'] = code
    _save_app_state(state, asset_id, None)

    return HttpResponse('Code received. Please close this window, the action will continue to get new token.', content_type="text/plain")


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
    real_state_file_path = os.path.realpath(state_file)
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

    real_state_file_path = os.path.realpath(state_file)
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


def _handle_rest_request(request, path_parts):
    """ Handle requests for authorization.

    :param request: Data given to REST endpoint
    :param path_parts: parts of the URL passed
    :return: dictionary containing response parameters
    """

    if len(path_parts) < 2:
        return HttpResponse('error: True, message: Invalid REST endpoint request', content_type="text/plain", status=400)

    call_type = path_parts[1]

    # Check if start_oauth is found in URL path and redirect for login on Microsoft page
    if call_type == 'start_oauth':
        return _handle_login_redirect(request, 'authorization_url')

    # To handle response from microsoft login page
    if call_type == 'result':
        return_val = _handle_login_response(request)
        asset_id = request.GET.get('state')
        if asset_id and asset_id.isalnum():
            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, asset_id, SKYPE4B_TC_FILE)
            real_auth_status_file_path = os.path.realpath(auth_status_file_path)
            if not os.path.dirname(real_auth_status_file_path) == app_dir:
                return HttpResponse("Error: Invalid asset_id", content_type="text/plain", status=400)
            open(auth_status_file_path, 'w').close()
            try:
                uid = pwd.getpwnam('apache').pw_uid
                gid = grp.getgrnam('phantom').gr_gid
                os.chown(auth_status_file_path, uid, gid)
                os.chmod(auth_status_file_path, '0664')
            except:
                pass

        return return_val
    return HttpResponse('error: Invalid endpoint', content_type="text/plain", status=400)


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
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SkypeForBusinessConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SkypeForBusinessConnector, self).__init__()

        self._state = None
        self._client_id = None
        self._client_secret = None
        self._tenant = SKYPE4B_DEFAULT_TENANT
        self._access_token = None
        self._refresh_token = None

    @staticmethod
    def _process_empty_response(response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Exception codes for success scenarios where no response body is obtained
        exception_codes = [200, 201, 204]
        if response.status_code in exception_codes:
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
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, self._handle_py_ver_compat_for_input_str(error_text))

        message = message.replace('{', '{{').replace('}', '}}')

        # For scenario when access is denied due to invalid token, html response is simplified
        if status_code == 403:
            error_text = 'Forbidden: Access is denied.'
            message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)
            message = '{}Run Test connectivity after few minutes.'.format(message)

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
            error_code, error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Code: {0}. Error: {1}"
                                                   .format(error_code, error_msg)), None)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = None
        # Check whether the response contains error and error description fields
        if resp_json.get('error') and resp_json.get('error_description'):
            message = "Error from server. Status Code: {0} Data from server: \"error\": {1}, " \
                      "\"error_description\": {2}".format(response.status_code, resp_json['error'],
                                                          resp_json['error_description'])

        if not message:
            message = "Error from server. Status Code: {0} Data from server: {1}"\
                .format(response.status_code, self._handle_py_ver_compat_for_input_str(response.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, request_response, action_result):
        """ This function is used to process html response.

        :param request_response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': request_response.status_code})
            action_result.add_debug_data({'r_text': request_response.text})
            action_result.add_debug_data({'r_headers': request_response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in request_response.headers.get('Content-Type', ''):
            return self._process_json_response(request_response, action_result)

        # if response is available in javascript
        if 'text/javascript' in request_response.headers.get('Content-Type', ''):
            return self._process_json_response(request_response, action_result)

        # Process an HTML response, Do this no matter what the API talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in request_response.headers.get('Content-Type', ''):
            return self._process_html_response(request_response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not request_response.text:
            return self._process_empty_response(request_response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".\
            format(request_response.status_code, self._handle_py_ver_compat_for_input_str(request_response.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param python_version: Python major version
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
        """ This method is used to get appropriate error message from the exception.
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
                error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
        except:
            error_code = "Error code unavailable"
            error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = "Error occurred while connecting to the GitHub server. Please check the asset configuration and|or the action parameters."
        except:
            error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."

        return error_code, error_msg

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, verify=True, method="get"):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param verify: verify server certificate (Default True)
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            request_response = request_func(endpoint, data=data, headers=headers, verify=verify, params=params)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Code: {0}. Details: {1}".
                                                   format(error_code, error_msg)), resp_json)

        return self._process_response(request_response, action_result)

    def _get_asset_name(self, action_result):
        """ Get name of the asset using Phantom URL.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), asset name
        """

        # Get ID of the asset
        asset_id = self.get_asset_id()
        rest_endpoint = SKYPE4B_PHANTOM_ASSET_INFO_URL.format(asset_id=asset_id)
        url = '{0}{1}'.format(SKYPE4B_PHANTOM_BASE_URL.format(phantom_base_url=self._get_phantom_base_url()), rest_endpoint)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)

        if phantom.is_fail(ret_val):
            return ret_val, None

        # Get name of the asset
        asset_name = resp_json.get('name')
        if not asset_name:
            return action_result.set_status(phantom.APP_ERROR, 'Asset Name for id: {0} not found.'.format(asset_id),
                                            None)
        return phantom.APP_SUCCESS, asset_name

    def _get_phantom_base_url_skype(self, action_result):
        """ Get base URL of phantom.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        base URL of phantom
        """

        url = '{0}{1}'.format(SKYPE4B_PHANTOM_BASE_URL.format(phantom_base_url=self._get_phantom_base_url()), SKYPE4B_PHANTOM_SYS_INFO_URL)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        phantom_base_url = resp_json.get('base_url')
        if not phantom_base_url:
            return action_result.set_status(phantom.APP_ERROR, SKYPE4B_BASE_URL_NOT_FOUND_MSG), None
        return phantom.APP_SUCCESS, phantom_base_url

    def _get_app_rest_url(self, action_result):
        """ Get URL for making rest calls.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        URL to make rest calls
        """

        # Get base URL of Phantom
        ret_val, phantom_base_url = self._get_phantom_base_url_skype(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Get name of the asset
        ret_val, asset_name = self._get_asset_name(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Display the phantom base URL for user
        self.save_progress('Using Phantom base URL as: {0}'.format(phantom_base_url))
        app_json = self.get_app_json()
        app_name = app_json['name']

        # Get name of the directory
        app_dir_name = _get_dir_name_from_app_name(app_name)
        url_to_app_rest = '{0}/rest/handler/{1}_{2}/{3}'.format(phantom_base_url, app_dir_name, app_json['appid'],
                                                                asset_name)
        return phantom.APP_SUCCESS, url_to_app_rest

    def _wait(self, action_result):
        """ This function is used to hold the action till user login for 105 seconds.

        :param action_result: Object of ActionResult class
        :return: status (success/failed)
        """

        app_dir = os.path.dirname(os.path.abspath(__file__))

        # file to check whether the request has been granted or not
        auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, self.get_asset_id(), SKYPE4B_TC_FILE)
        time_out = False

        # wait-time of while request is being granted for 105 seconds
        for _ in range(0, 35):
            self.send_progress('Waiting...')
            self._state = _load_app_state(self.get_asset_id(), self)
            if os.path.isfile(auth_status_file_path):
                time_out = True
                os.unlink(auth_status_file_path)
                break
            time.sleep(SKYPE4B_TC_STATUS_SLEEP)

        if not time_out:
            return action_result.set_status(phantom.APP_ERROR, status_message='Timeout. Please try again later.')
        self.send_progress('Authenticated')
        return phantom.APP_SUCCESS

    def _generate_new_access_token(self, action_result, data):
        """ This function is used to generate new access token using the code obtained on authorization.

        :param action_result: object of ActionResult class
        :param data: Data to send in REST call
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS
        """

        req_url = '{}{}'.format(SKYPE4B_LOGIN_BASE_URL, SKYPE4B_SERVER_TOKEN_URL.format(tenant_id=self._tenant))

        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=req_url,
                                                  data=urllib.urlencode(data), method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Access token and Refresh token retrieved in the response are saved
        self._state[SKYPE4B_TOKEN_STRING] = resp_json
        self._access_token = resp_json[SKYPE4B_ACCESS_TOKEN]
        self._refresh_token = resp_json[SKYPE4B_REFRESH_TOKEN]

        _save_app_state(self._state, self.get_asset_id(), self)
        return phantom.APP_SUCCESS

    def _get_final_hub_url_resource(self, action_result, redirect_uri, app_rest_url):
        """ This function is used to get the final hub URL to use during the API calls.

        :param action_result: Object of ActionResult class
        :param redirect_uri: Redirect URI to pass in request
        :param app_rest_url: APP URL for making REST calls
        :return: status (phantom.APP_SUCCESS/phantom.APP_ERROR), final hub URL resource for API calls
        """

        # Get the initial hub_url to start authentication process
        ret_val, response = self._make_rest_call(SKYPE4B_FIRST_HUB_URL_ENDPOINT, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Set the first hub from the response
        first_hub_url = response['_links']['user']['href']
        asset_id = self.get_asset_id()
        hub_url = None
        # Variable to check for final hub
        is_final_hub = False

        self.save_progress(SKYPE4B_OAUTH_URL_MSG)
        self.save_progress(redirect_uri)

        # Iterate till you get final hub_url
        while True:
            # If not hub URL is present, take first hub as the hub URL
            if not hub_url:
                hub_url = first_hub_url

            hub_url_resource = urlparse(hub_url)

            hub_url_resource = '{0}://{1}'.format(hub_url_resource[0], hub_url_resource[1])

            # Authorization URL used to make request for getting code which is used to generate access token
            # Pass hub_resource in resource parameter
            authorization_url = SKYPE4B_AUTHORIZE_URL.format(tenant_id=self._tenant, client_id=self._client_id,
                                                             redirect_uri=redirect_uri, state=asset_id,
                                                             response_type='code', resource=hub_url_resource)
            authorization_url = '{}{}'.format(SKYPE4B_LOGIN_BASE_URL, authorization_url)

            self._state['authorization_url'] = authorization_url

            # URL which would be shown to the user
            url_for_authorize_request = '{0}/start_oauth?asset_id={1}'.format(app_rest_url, asset_id)
            _save_app_state(self._state, asset_id, self)

            self.save_progress(SKYPE4B_AUTHORIZE_USER_MSG)
            self.save_progress(url_for_authorize_request)

            # Total wait time is of 120 seconds.

            # Wait time of 15 seconds
            time.sleep(SKYPE4B_AUTHORIZE_WAIT_TIME)

            # Wait time of 105 seconds while user logins to Microsoft
            status = self._wait(action_result=action_result)

            if phantom.is_fail(status):
                return action_result.get_status(), None

            self._state = _load_app_state(asset_id, self)

            # Request body for generating token
            access_token_data = {
                'client_id': self._client_id,
                'client_secret': self._client_secret,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri,
                'code': self._state['code']
            }

            # Generate the access_token using code we received
            access_token_status = self._generate_new_access_token(action_result=action_result, data=access_token_data)

            if phantom.is_fail(access_token_status):
                return action_result.get_status(), None

            self.save_progress('Access token generated')

            # If it is not a final hub, get next hub_url
            if not is_final_hub:
                hur_url_status, hub_url, is_final_hub = self._get_next_hub_url(action_result=action_result,
                                                                               current_hub_url=hub_url_resource)

                if phantom.is_fail(hur_url_status):
                    return action_result.get_status(), None
                continue
            break

        return phantom.APP_SUCCESS, hub_url_resource

    def _get_next_hub_url(self, action_result, current_hub_url):
        """ This function is used to get the next hub URL.

        :param action_result: Object of ActionResult class
        :param current_hub_url: Current hub URL
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), Next hub URL, If it is a final URL or not (True/False)
        """

        # To autodiscover the hubs present for making API calls
        auto_discovery_url = '{0}{1}'.format(current_hub_url, SKYPE4B_AUTODISCOVERY_ENDPOINT)
        request_headers = dict()

        request_headers['Authorization'] = 'Bearer {0}'.format(self._access_token)
        ret_val, response = self._make_rest_call(auto_discovery_url, action_result=action_result,
                                                 headers=request_headers)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None, None

        # If it is a final hub URL, return the URL with success
        if response['_links'].get('applications'):
            return phantom.APP_SUCCESS, response['_links']['applications']['href'], phantom.APP_SUCCESS

        # If not final hub, continue with the redirect URL in the loop
        return phantom.APP_SUCCESS, response['_links']['redirect']['href'], phantom.APP_ERROR

    def _get_api_endpoints(self, action_result):
        """ This function is used to get the API endpoints by calling the applications endpoint.

        :param action_result: Object of ActionResult class
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), API endpoints in JSON format
        """

        self._access_token = self._state.get(SKYPE4B_TOKEN_STRING, {}).get(SKYPE4B_ACCESS_TOKEN)
        self._refresh_token = self._state.get(SKYPE4B_TOKEN_STRING, {}).get(SKYPE4B_REFRESH_TOKEN)
        url = self._state.get('final_hub_url_resource', "")

        if not self._refresh_token:
            return action_result.set_status(phantom.APP_ERROR, status_message=SKYPE4B_TOKEN_NOT_AVAILABLE_MSG), None

        if not url:
            return action_result.set_status(phantom.APP_ERROR, status_message=SKYPE4B_RUN_TEST_CONN_MSG), None

        token_data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'grant_type': SKYPE4B_REFRESH_TOKEN,
            'redirect_uri': self._state['redirect_uri'],
            'refresh_token': self._refresh_token
        }
        status = self._generate_new_access_token(action_result=action_result, data=token_data)
        if phantom.is_fail(status):
            return action_result.get_status(), None

        url = "{0}{1}".format(url, SKYPE4B_APPLICATIONS_ENDPOINT)

        request_headers = {
            'Authorization': 'Bearer {0}'.format(self._access_token),
            "Content-Type": SKYPE4B_HEADERS_APP_JSON
        }

        request_data = {
            "UserAgent": "phantom_agent",
            "Culture": "en-US",
            "EndpointId": str(uuid.uuid4())
        }

        request_status, request_response = self._make_rest_call(url, action_result=action_result, method='post',
                                                                data=json.dumps(request_data), headers=request_headers)

        if phantom.is_fail(request_status):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, request_response

    def _make_me_available(self, action_result, make_me_available_url):
        """ This function is used to call the makeMeAvailable endpoint, which is required to perform other actions.

        :param action_result: Object of ActionResult class
        :param make_me_available_url: URL for makeMeAvailable
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        request_headers = {
            'Authorization': 'Bearer {0}'.format(self._access_token),
            'Content-Type': SKYPE4B_HEADERS_APP_JSON
        }

        request_status, _ = self._make_rest_call(make_me_available_url, method='post', data=json.dumps({}),
                                                 headers=request_headers, action_result=action_result)

        if phantom.is_fail(request_status):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        """ This function is used to handle the test connectivity.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")
        self._state = {}
        # Get initial REST URL
        ret_val, app_rest_url = self._get_app_rest_url(action_result)
        if phantom.is_fail(ret_val):
            self.save_progress(SKYPE4B_REST_URL_NOT_AVAILABLE_MSG.format(error=action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, status_message=SKYPE4B_TEST_CONNECTIVITY_FAILED_MSG)

        # Creating Redirect URI similar to the one saved by user in his app
        redirect_uri = '{0}/result'.format(app_rest_url)
        self._state['redirect_uri'] = redirect_uri

        # Get the final hub URL for access to applications
        hub_url_status, hub_url_resource = self._get_final_hub_url_resource(action_result=action_result,
                                                                            redirect_uri=redirect_uri,
                                                                            app_rest_url=app_rest_url)

        if phantom.is_fail(hub_url_status):
            self.save_progress(SKYPE4B_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        # Save the final hub URL for all API calls for the given asset
        self._state['final_hub_url_resource'] = hub_url_resource
        _save_app_state(self._state, self.get_asset_id(), self)

        # Empty message to override last message of waiting
        self.send_progress('')

        self._state = _load_app_state(self.get_asset_id(), self)

        # Get API endpoints from the final hub URL for other API calls
        api_endpoint_status, api_endpoints_response = self._get_api_endpoints(action_result=action_result)

        if phantom.is_fail(api_endpoint_status):
            self.save_progress(SKYPE4B_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        # Endpoint to retrieve presence of user
        make_me_available_endpoint = api_endpoints_response['_embedded']['me']['_links'].get('makeMeAvailable', {})\
            .get('href')

        # Call makeMeAvailable if make_me_available endpoint is present
        if make_me_available_endpoint:
            self.save_progress('Making user available')
            make_me_available_url = "{0}{1}".format(self._state['final_hub_url_resource'], make_me_available_endpoint)
            make_me_available_status = self._make_me_available(action_result=action_result,
                                                               make_me_available_url=make_me_available_url)

            if phantom.is_fail(make_me_available_status):
                self.save_progress(SKYPE4B_TEST_CONNECTIVITY_FAILED_MSG)
                return action_result.get_status()

        # Get URL for current user
        self_endpoint = api_endpoints_response['_embedded']['me']['_links']['self']['href']
        self_url = "{0}{1}".format(self._state['final_hub_url_resource'], self_endpoint)

        request_headers = {
            'Authorization': 'Bearer {0}'.format(self._access_token),
            'Content-Type': SKYPE4B_HEADERS_APP_JSON
        }

        self.save_progress('Getting user data')
        request_status, _ = self._make_rest_call(self_url, headers=request_headers, action_result=action_result)

        if phantom.is_fail(request_status):
            self.save_progress(SKYPE4B_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(SKYPE4B_TEST_CONNECTIVITY_PASSED_MSG)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _verify_contact(self, action_result, endpoint, contact_verify):
        """ This function is used to verify if the given contact is present in contact list.

        :param action_result: Object of ActionResult class
        :param endpoint: endpoint for listing contacts
        :param contact_verify: contact to be verified
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR) with appropriate message
        """

        request_headers = {
            'Authorization': 'Bearer {0}'.format(self._access_token),
            'Content-Type': SKYPE4B_HEADERS_APP_JSON
        }

        url = "{0}{1}".format(self._state['final_hub_url_resource'], endpoint)
        request_status, request_response = self._make_rest_call(url, action_result=action_result,
                                                                headers=request_headers)

        if phantom.is_fail(request_status):
            return action_result.get_status()

        # Check if the given contact is present in user's contact list
        for contact in request_response.get("_embedded", {}).get("contact", []):
            if contact.get("uri", "").lower() == contact_verify.lower():
                return phantom.APP_SUCCESS

        return action_result.set_status(phantom.APP_ERROR, "Contact not found")

    def _handle_send_message(self, param):
        """ This function is used to handle the send message.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        contact_email = self._handle_py_ver_compat_for_input_str(param[SKYPE4B_JSON_CONTACT])
        message = param[SKYPE4B_JSON_MESSAGE]

        if not contact_email.startswith('sip:'):
            contact_email = "sip:{}".format(contact_email)

        if self._python_version == 2:
            try:
                encoded_message = message.encode('base64', 'strict')
            except:
                encoded_message = base64.b64encode(UnicodeDammit(message).unicode_markup.encode("utf-8"))
        else:
            encoded_message = base64.b64encode(UnicodeDammit(message).unicode_markup.encode("utf-8"))
            encoded_message = UnicodeDammit(encoded_message).unicode_markup

        # Get list of endpoints
        status, endpoint_data = self._get_api_endpoints(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Get contact endpoint for verifying contact
        endpoint_contact = endpoint_data.get("_embedded", {}).get("people", {}).get("_links", {}).get("myContacts", {})\
            .get("href")

        # Verify if contact_email is present in contact_email list
        contact_status = self._verify_contact(action_result, endpoint_contact, contact_email)

        if phantom.is_fail(contact_status):
            return action_result.get_status()

        # Set specific endpoint for sending message
        endpoint = endpoint_data.get("_embedded", {}).get("communication", {}).get("_links", {})\
            .get("startMessaging", {}).get("href")

        request_headers = {
            'Authorization': 'Bearer {0}'.format(self._access_token),
            "Content-Type": SKYPE4B_HEADERS_APP_JSON
        }

        url = "{0}{1}".format(self._state['final_hub_url_resource'], endpoint)

        data = {
            "OperationId": str(uuid.uuid4()),
            "to": contact_email,
            "_links": {
                "message": {
                    "href": "data:text/plain;base64,{MESSAGE}".format(MESSAGE=encoded_message)
                }
            }
        }
        request_status, request_response = self._make_rest_call(url, action_result=action_result,
                                                                headers=request_headers, method='post',
                                                                data=json.dumps(data))

        if phantom.is_fail(request_status):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Message sent")

    def _handle_list_groups(self, param):
        """ This function is used to handle the list groups.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get list of endpoints
        status, endpoint_data = self._get_api_endpoints(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Set specific endpoint for listing groups
        endpoint = endpoint_data.get("_embedded", {}).get("people", {}).get("_links", {}).get("myGroups", {})\
            .get("href")

        request_headers = {
            'Authorization': 'Bearer {0}'.format(self._access_token),
            "Content-Type": SKYPE4B_HEADERS_APP_JSON
        }

        url = "{0}{1}".format(self._state['final_hub_url_resource'], endpoint)
        request_status, request_response = self._make_rest_call(url, action_result=action_result,
                                                                headers=request_headers)

        if phantom.is_fail(request_status):
            return action_result.get_status()

        for group in request_response.get("_embedded", {}).get("group", []):
            action_result.add_data(group)

        for group in request_response.get("_embedded", {}).get("distributionGroup", []):
            action_result.add_data(group)

        action_result.add_data(request_response.get("_embedded", {}).get("pinnedGroup", {}))
        action_result.add_data(request_response.get("_embedded", {}).get("defaultGroup", {}))
        action_result.add_data(request_response.get("_embedded", {}).get("delegatesGroup", {}))

        summary = action_result.update_summary({})
        summary['total_groups'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_contacts(self, param):
        """ This function is used to handle the list contacts.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get list of endpoints
        status, endpoint_data = self._get_api_endpoints(action_result)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Set specific endpoint for listing contacts
        endpoint = endpoint_data.get("_embedded", {}).get("people", {}).get("_links", {}).get("myContacts", {})\
            .get("href")

        request_headers = {
            'Authorization': 'Bearer {0}'.format(self._access_token),
            "Content-Type": SKYPE4B_HEADERS_APP_JSON
        }

        url = "{0}{1}".format(self._state['final_hub_url_resource'], endpoint)
        request_status, request_response = self._make_rest_call(url, action_result=action_result,
                                                                headers=request_headers)

        if phantom.is_fail(request_status):
            return action_result.get_status()

        for contact in request_response.get("_embedded", {}).get("contact", []):
            action_result.add_data(contact)

        summary = action_result.update_summary({})
        summary['total_contacts'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'send_message': self._handle_send_message,
            'list_groups': self._handle_list_groups,
            'list_contacts': self._handle_list_contacts
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
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR.
        """

        self._state = self.load_state()
        if not self._state:
            self._state = {}
        # get the asset config
        config = self.get_config()

        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version")

        self._client_id = self._handle_py_ver_compat_for_input_str(config[SKYPE4B_CONFIG_CLIENT_ID])
        self._client_secret = config[SKYPE4B_CONFIG_CLIENT_SECRET]
        self._tenant = config.get(SKYPE4B_CONFIG_TENANT, SKYPE4B_DEFAULT_TENANT)
        self._access_token = self._state.get(SKYPE4B_TOKEN_STRING, {}).get(SKYPE4B_ACCESS_TOKEN)
        self._refresh_token = self._state.get(SKYPE4B_TOKEN_STRING, {}).get(SKYPE4B_REFRESH_TOKEN)

        return phantom.APP_SUCCESS

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """

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
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={0}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: {0}".format(str(e)))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SkypeForBusinessConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
