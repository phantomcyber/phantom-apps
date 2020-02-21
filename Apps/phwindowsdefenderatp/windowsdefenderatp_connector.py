# File: windowsdefenderatp_connector.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom App imports
import json
import os
import time
import urllib
import ipaddress
import pwd
import grp
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from django.http import HttpResponse

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from windowsdefenderatp_consts import *


def _handle_login_redirect(request, key):
    """ This function is used to redirect login request to Microsoft login page.

    :param request: Data given to REST endpoint
    :param key: Key to search in state file
    :return: response authorization_url/admin_consent_url
    """

    asset_id = request.GET.get('asset_id')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL')
    state = _load_app_state(asset_id)
    url = state.get(key)
    if not url:
        return HttpResponse('App state is invalid, {key} not found.'.format(key=key))
    response = HttpResponse(status=302)
    response['Location'] = url
    return response


def _load_app_state(asset_id, app_connector=None):
    """ This function is used to load the current state file.

    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: state: Current state file as a dictionary
    """

    dirpath = os.path.split(__file__)[0]
    state_file = '{0}/{1}_state.json'.format(dirpath, asset_id)
    state = {}
    try:
        with open(state_file, 'r') as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)
    except Exception as e:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Exception: {0}'.format(str(e)))

    if app_connector:
        app_connector.debug_print('Loaded state: ', state)
    return state


def _save_app_state(state, asset_id, app_connector):
    """ This functions is used to save current state in file.

    :param state: Dictionary which contains data to write in state file
    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: status: phantom.APP_SUCCESS
    """

    dirpath = os.path.split(__file__)[0]
    state_file = '{0}/{1}_state.json'.format(dirpath, asset_id)

    if app_connector:
        app_connector.debug_print('Saving state: ', state)

    try:
        with open(state_file, 'w+') as state_file_obj:
            state_file_obj.write(json.dumps(state))
    except Exception as e:
        print 'Unable to save state file: {0}'.format(str(e))

    return phantom.APP_SUCCESS


def _handle_login_response(request):
    """ This function is used to get the login response of authorization request from Microsoft login page.

    :param request: Data given to REST endpoint
    :return: HttpResponse. The response displayed on authorization URL page
    """

    asset_id = request.GET.get('state')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL\n{}'.format(json.dumps(request.GET)))

    # Check for error in URL
    error = request.GET.get('error')
    error_description = request.GET.get('error_description')

    # If there is an error in response
    if error:
        message = 'Error: {0}'.format(error)
        if error_description:
            message = '{0} Details: {1}'.format(message, error_description)
        return HttpResponse('Server returned {0}'.format(message))

    code = request.GET.get('code')

    # If code is not available
    if not code:
        return HttpResponse('Error while authenticating\n{0}'.format(json.dumps(request.GET)))

    state = _load_app_state(asset_id)
    state['code'] = code
    _save_app_state(state, asset_id, None)

    return HttpResponse('Code received. Please close this window, the action will continue to get new token.')


def _handle_rest_request(request, path_parts):
    """ Handle requests for authorization.

    :param request: Data given to REST endpoint
    :param path_parts: parts of the URL passed
    :return: dictionary containing response parameters
    """

    if len(path_parts) < 2:
        return HttpResponse('error: True, message: Invalid REST endpoint request')

    call_type = path_parts[1]

    # To handle authorize request in test connectivity action
    if call_type == 'start_oauth':
        return _handle_login_redirect(request, 'authorization_url')

    # To handle response from microsoft login page
    if call_type == 'result':
        return_val = _handle_login_response(request)
        asset_id = request.GET.get('state')
        if asset_id:
            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, asset_id, DEFENDERATP_TC_FILE)
            open(auth_status_file_path, 'w').close()
            try:
                uid = pwd.getpwnam('apache').pw_uid
                gid = grp.getgrnam('phantom').gr_gid
                os.chown(auth_status_file_path, uid, gid)
                os.chmod(auth_status_file_path, '0664')
            except:
                pass

        return return_val
    return HttpResponse('error: Invalid endpoint')


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


class WindowsDefenderAtpConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(WindowsDefenderAtpConnector, self).__init__()

        self._state = None
        self._tenant = None
        self._client_id = None
        self._access_token = None
        self._refresh_token = None
        self._client_secret = None

    def _process_empty_response(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Status Code: {0}. Error: Empty response and no information in the header".format(response.status_code)),
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
            error_text = soup.text.encode('utf-8')
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        if not error_text:
            error_text = "Unknown error occurred. Please check the asset configuration and|or the action parameters."

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, UnicodeDammit(error_text).unicode_markup.encode('utf-8'))

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """ This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        try:
            # Process a json response
            resp_json = response.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}"
                                                   .format(str(e))), None)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = None

        # Check whether the response contains error and error description fields
        # This condition will be used in test_connectivity
        if not isinstance(resp_json.get('error'), dict) and resp_json.get('error_description'):
            err = "Error:{0}, Error Description:{1}".format(
                    UnicodeDammit(resp_json.get('error')).unicode_markup.encode('utf-8'), UnicodeDammit(resp_json.get('error_description')).unicode_markup.encode('utf-8'))
            err += " Please check your asset configuration parameters and run the test connectivity."
            message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code, err)

        # For other actions
        if isinstance(resp_json.get('error'), dict) and resp_json.get('error', {}).get('code'):
            message = "Error from server. Status Code: {0} Error Code: {1} Data from server: {2}".format(
                response.status_code, resp_json.get('error', {}).get('code'), UnicodeDammit(resp_json.get('error', {}).get('message')).unicode_markup.encode('utf-8'))

        if not message:
            message = "Error from server. Status Code: {0} Data from server: {1}"\
                .format(response.status_code, UnicodeDammit(response.text.replace('{', '{{').replace('}', '}}')).unicode_markup.encode('utf-8'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the response_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        if 'text/javascript' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            response.status_code, UnicodeDammit(response.text.replace('{', '{{').replace('}', '}}')).unicode_markup.encode('utf-8'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _update_request(self, action_result, endpoint, headers=None, params=None, data=None, method='get'):
        """ This function is used to update the headers with access_token before making REST call.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        if headers is None:
            headers = {}

        token_data = {
            'client_id': self._client_id,
            'grant_type': DEFENDERATP_REFRESH_TOKEN_STRING,
            'refresh_token': self._refresh_token,
            'client_secret': self._client_secret,
            'resource': DEFENDERATP_RESOURCE_URL
        }

        if not self._access_token:
            if not self._refresh_token:
                # If none of the access_token and refresh_token is available
                return action_result.set_status(phantom.APP_ERROR, status_message=DEFENDERATP_TOKEN_NOT_AVAILABLE_MSG),\
                       None

            # If refresh_token is available and access_token is not available, generate new access_token
            status = self._generate_new_access_token(action_result=action_result, data=token_data)

            if phantom.is_fail(status):
                return action_result.get_status(), None

        headers.update({'Authorization': 'Bearer {0}'.format(self._access_token),
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'})

        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=endpoint, headers=headers,
                                                  params=params, data=data, method=method)

        # If token is expired, generate new token
        if DEFENDERATP_TOKEN_EXPIRED in action_result.get_message():
            status = self._generate_new_access_token(action_result=action_result, data=token_data)

            if phantom.is_fail(status):
                return action_result.get_status(), None

            headers.update({'Authorization': 'Bearer {0}'.format(self._access_token)})

            ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=endpoint, headers=headers,
                                                      params=params, data=data, method=method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", verify=True):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
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
            response = request_func(endpoint, data=data, headers=headers, verify=verify, params=params)
        except Exception as e:
            if e.message:
                if isinstance(e.message, basestring):
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('UTF-8')
                else:
                    try:
                        error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                    except:
                        error_msg = "Unknown error occurred. Please check the asset configuration and|or the action parameters."
            else:
                error_msg = "Unknown error occurred. Please check the asset configuration and|or the action parameters."

            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}"
                                                   .format(error_msg)), resp_json)

        return self._process_response(response, action_result)

    def _get_asset_name(self, action_result):
        """ Get name of the asset using Phantom URL.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), asset name
        """

        asset_id = self.get_asset_id()
        rest_endpoint = DEFENDERATP_PHANTOM_ASSET_INFO_URL.format(asset_id=asset_id)
        url = '{}{}'.format(DEFENDERATP_PHANTOM_BASE_URL.format(phantom_base_url=self.get_phantom_base_url()), rest_endpoint)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)

        if phantom.is_fail(ret_val):
            return ret_val, None

        asset_name = resp_json.get('name')
        if not asset_name:
            return action_result.set_status(phantom.APP_ERROR, 'Asset Name for id: {0} not found.'.format(asset_id),
                                            None)
        return phantom.APP_SUCCESS, asset_name

    def _get_phantom_base_url_defenderatp(self, action_result):
        """ Get base url of phantom.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        base url of phantom
        """

        url = '{}{}'.format(DEFENDERATP_PHANTOM_BASE_URL.format(phantom_base_url=self.get_phantom_base_url()), DEFENDERATP_PHANTOM_SYS_INFO_URL)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)
        if phantom.is_fail(ret_val):
            return ret_val, None

        phantom_base_url = resp_json.get('base_url')
        if not phantom_base_url:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_BASE_URL_NOT_FOUND_MSG), None
        return phantom.APP_SUCCESS, phantom_base_url

    def _get_app_rest_url(self, action_result):
        """ Get URL for making rest calls.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        URL to make rest calls
        """

        ret_val, phantom_base_url = self._get_phantom_base_url_defenderatp(action_result)
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

    def _generate_new_access_token(self, action_result, data):
        """ This function is used to generate new access token using the code obtained on authorization.

        :param action_result: object of ActionResult class
        :param data: Data to send in REST call
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS
        """

        req_url = '{}{}'.format(DEFENDERATP_LOGIN_BASE_URL, DEFENDERATP_SERVER_TOKEN_URL.format(tenant_id=self._tenant))

        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=req_url,
                                                  data=urllib.urlencode(data), method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state[DEFENDERATP_TOKEN_STRING] = resp_json
        self._access_token = resp_json[DEFENDERATP_ACCESS_TOKEN_STRING]
        self._refresh_token = resp_json[DEFENDERATP_REFRESH_TOKEN_STRING]

        self.save_state(self._state)
        _save_app_state(self._state, self.get_asset_id(), self)

        self._state = self.load_state()

        # Scenario -
        #
        # If the corresponding state file doesn't have correct owner, owner group or permissions,
        # the newely generated token is not being saved to state file and automatic workflow for token has been stopped.
        # So we have to check that token from response and token which are saved to state file after successful generation of new token are same or not.

        if self._access_token != self._state.get(DEFENDERATP_TOKEN_STRING, {}).get(DEFENDERATP_ACCESS_TOKEN_STRING):
            message = "Error occurred while saving the newly generated access token (in place of the expired token) in the state file."
            message += " Please check the owner, owner group, and the permissions of the state file. The Phantom "
            message += "user should have the correct access rights and ownership for the corresponding state file (refer to readme file for more information)."
            return action_result.set_status(phantom.APP_ERROR, message)

        return phantom.APP_SUCCESS

    def _wait(self, action_result):
        """ This function is used to hold the action till user login for 105 seconds.

        :param action_result: Object of ActionResult class
        :return: status (success/failed)
        """

        app_dir = os.path.dirname(os.path.abspath(__file__))
        # file to check whether the request has been granted or not
        auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, self.get_asset_id(), DEFENDERATP_TC_FILE)
        time_out = False

        # wait-time while request is being granted for 105 seconds
        for _ in range(0, 35):
            self.send_progress('Waiting...')
            self._state = _load_app_state(self.get_asset_id(), self)
            if os.path.isfile(auth_status_file_path):
                time_out = True
                os.unlink(auth_status_file_path)
                break
            time.sleep(DEFENDERATP_TC_STATUS_SLEEP)

        if not time_out:
            self.send_progress('')
            return action_result.set_status(phantom.APP_ERROR, "Timeout. Please try again later.")
        self.send_progress('Authenticated')
        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        """ Testing of given credentials and obtaining authorization for all other actions.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(DEFENDERATP_MAKING_CONNECTION_MSG)
        self._state = {}

        # Get initial REST URL
        ret_val, app_rest_url = self._get_app_rest_url(action_result)
        if phantom.is_fail(ret_val):
            self.save_progress(DEFENDERATP_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        # Append /result to create redirect_uri
        redirect_uri = '{0}/result'.format(app_rest_url)
        self._state['redirect_uri'] = redirect_uri

        self.save_progress(DEFENDERATP_OAUTH_URL_MSG)
        self.save_progress(redirect_uri)

        # Authorization URL used to make request for getting code which is used to generate access token
        authorization_url = DEFENDERATP_AUTHORIZE_URL.format(tenant_id=self._tenant, client_id=self._client_id,
                                                             redirect_uri=redirect_uri, state=self.get_asset_id(),
                                                             response_type='code', resource=DEFENDERATP_RESOURCE_URL)
        authorization_url = '{}{}'.format(DEFENDERATP_LOGIN_BASE_URL, authorization_url)

        self._state['authorization_url'] = authorization_url

        # URL which would be shown to the user
        url_for_authorize_request = '{0}/start_oauth?asset_id={1}&'.format(app_rest_url, self.get_asset_id())
        _save_app_state(self._state, self.get_asset_id(), self)

        self.save_progress(DEFENDERATP_AUTHORIZE_USER_MSG)
        self.save_progress(url_for_authorize_request)

        # Wait time for authorization
        time.sleep(DEFENDERATP_AUTHORIZE_WAIT_TIME)

        # Wait for some while user login to Microsoft
        status = self._wait(action_result=action_result)

        # Empty message to override last message of waiting
        self.send_progress('')
        if phantom.is_fail(status):
            self.save_progress(DEFENDERATP_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(DEFENDERATP_CODE_RECEIVED_MSG)
        self._state = _load_app_state(self.get_asset_id(), self)

        # if code is not available in the state file
        if not self._state or not self._state.get('code'):
            return action_result.set_status(phantom.APP_ERROR, status_message=DEFENDERATP_TEST_CONNECTIVITY_FAILED_MSG)

        current_code = self._state['code']
        self.save_state(self._state)
        _save_app_state(self._state, self.get_asset_id(), self)

        self.save_progress(DEFENDERATP_GENERATING_ACCESS_TOKEN_MSG)

        data = {
            'client_id': self._client_id,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
            'code': current_code,
            'resource': DEFENDERATP_RESOURCE_URL,
            'client_secret': self._client_secret
        }
        # for first time access, new access token is generated
        ret_val = self._generate_new_access_token(action_result=action_result, data=data)

        if phantom.is_fail(ret_val):
            self.send_progress('')
            self.save_progress(DEFENDERATP_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(DEFENDERATP_ALERTS_INFO_MSG)

        url = '{}{}'.format(DEFENDERATP_MSGRAPH_API_BASE_URL, DEFENDERATP_ALERTS_ENDPOINT)
        params = {
            '$top': 1
        }
        ret_val, response = self._update_request(action_result=action_result, endpoint=url, params=params)
        if phantom.is_fail(ret_val):
            self.send_progress('')
            self.save_progress(DEFENDERATP_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(DEFENDERATP_RECEIVED_ALERT_INFO_MSG)
        self.save_progress(DEFENDERATP_TEST_CONNECTIVITY_PASSED_MSG)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _status_wait(self, action_result, action_id, timeout):
        """ This function is used to check status of action on device every 5 seconds for specified timeout period.

        :param action_result: Object of ActionResult class
        :param action_id: ID of the action executed on the device
        :param timeout: timeout period for status check
        :return: status (success/failed), response
        """
        endpoint = "{0}{1}".format(DEFENDERATP_MSGRAPH_API_BASE_URL, DEFENDERATP_MACHINEACTIONS_ENDPOINT
                                   .format(action_id=action_id))

        if timeout < 5:
            timeout = 5
        # wait-time while status updates for specified timeout period
        for _ in range(0, int(timeout / 5)):
            # This sleep-time is the time required (0-5 seconds) for the machineaction's command ID details to get reflected
            # on the Windows Defender ATP server. Hence, this sleep-time is explicitly added and added before the first fetch of status.
            time.sleep(DEFENDERATP_STATUS_CHECK_SLEEP)

            # make rest call
            ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None
            if not response['status'] == DEFENDERATP_STATUS_PROGRESS:
                return phantom.APP_SUCCESS, response

        return phantom.APP_SUCCESS, response

    def _handle_quarantine_device(self, param):
        """ This function is used to handle the quarantine device action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        type = param[DEFENDERATP_JSON_TYPE]
        comment = param[DEFENDERATP_JSON_COMMENT]
        timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_STATUS_CHECK_DEFAULT)

        try:
            timeout = int(timeout)

            if timeout <= 0:
                return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_TIMEOUT_VALIDATION_MSG)
        except:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_TIMEOUT_VALIDATION_MSG)

        if timeout > DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT:
            timeout = DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT

        endpoint = "{0}{1}".format(DEFENDERATP_MSGRAPH_API_BASE_URL, DEFENDERATP_ISOLATE_ENDPOINT
                                   .format(device_id=device_id))

        data = {
            'Comment': comment,
            'IsolationType': type
        }

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method='post',
                                                 data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get('id', ""):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

        summary = action_result.update_summary({})
        summary['event_id'] = response['id']

        action_id = response['id']
        # Wait for some while the status of the action updates
        status, response_status = self._status_wait(action_result, action_id, timeout)
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response_status)
        summary['quarantine_status'] = response_status['status']
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unquarantine_device(self, param):
        """ This function is used to handle the unquarantine device action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        comment = param[DEFENDERATP_JSON_COMMENT]
        timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_STATUS_CHECK_DEFAULT)

        try:
            timeout = int(timeout)

            if timeout <= 0:
                return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_TIMEOUT_VALIDATION_MSG)
        except:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_TIMEOUT_VALIDATION_MSG)

        if timeout > DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT:
            timeout = DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT

        endpoint = "{0}{1}".format(DEFENDERATP_MSGRAPH_API_BASE_URL, DEFENDERATP_UNISOLATE_ENDPOINT
                                   .format(device_id=device_id))

        data = {
            'Comment': comment
        }

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method='post',
                                                 data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get('id', ""):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

        summary = action_result.update_summary({})
        summary['event_id'] = response['id']

        action_id = response['id']
        # Wait for some while the status of the action updates
        status, response_status = self._status_wait(action_result, action_id, timeout)
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response_status)
        summary['unquarantine_status'] = response_status['status']
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_status(self, param):
        """ This function is used to handle the get status action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        event_id = UnicodeDammit(param[DEFENDERATP_EVENT_ID]).unicode_markup.encode('utf-8')

        endpoint = "{0}{1}".format(DEFENDERATP_MSGRAPH_API_BASE_URL, DEFENDERATP_MACHINEACTIONS_ENDPOINT
                                   .format(action_id=event_id))

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['event_status'] = response['status']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_scan_device(self, param):
        """ This function is used to handle the scan device action.

        :param param: Dictionary of input parameters
        :return: status(success/failed)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        scan_type = param[DEFENDERATP_JSON_SCAN_TYPE]
        comment = param[DEFENDERATP_JSON_COMMENT]
        timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_STATUS_CHECK_DEFAULT)

        try:
            timeout = int(timeout)

            if timeout <= 0:
                return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_TIMEOUT_VALIDATION_MSG)
        except:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_TIMEOUT_VALIDATION_MSG)

        if timeout > DEFENDERATP_SCAN_TIMEOUT_MAX_LIMIT:
            timeout = DEFENDERATP_SCAN_TIMEOUT_MAX_LIMIT

        endpoint = DEFENDERATP_SCAN_DEVICE_ENDPOINT.format(device_id=device_id)

        url = '{0}{1}'.format(DEFENDERATP_MSGRAPH_API_BASE_URL, endpoint)

        request_data = {
            "Comment": comment,
            "ScanType": scan_type
        }

        # make rest call
        ret_val, response = self._update_request(endpoint=url, action_result=action_result, method='post',
                                                 data=json.dumps(request_data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get('id', ""):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

        summary = action_result.update_summary({})
        summary['event_id'] = response['id']

        action_id = response['id']
        # Wait for some while the status of the action updates
        status, response_status = self._status_wait(action_result, action_id, timeout)
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response_status)
        summary['scan_status'] = response_status['status']
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_file(self, param):
        """ This function is used to handle the quarantine file action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        file_hash = param[DEFENDERATP_JSON_FILE_HASH]
        comment = param[DEFENDERATP_JSON_COMMENT]
        timeout = param.get(DEFENDERATP_JSON_TIMEOUT, DEFENDERATP_STATUS_CHECK_DEFAULT)

        try:
            timeout = int(timeout)

            if timeout <= 0:
                return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_TIMEOUT_VALIDATION_MSG)
        except:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_TIMEOUT_VALIDATION_MSG)

        if timeout > DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT:
            timeout = DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT

        endpoint = "{0}{1}".format(DEFENDERATP_MSGRAPH_API_BASE_URL, DEFENDERATP_FILE_QUARANTINE_ENDPOINT
                                   .format(device_id=device_id))

        data = {
            'Comment': comment,
            'Sha1': file_hash
        }

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method='post',
                                                 data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get('id', ""):
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

        summary = action_result.update_summary({})
        summary['event_id'] = response['id']

        action_id = response['id']
        # Wait for some while the status of the action updates
        status, response_status = self._status_wait(action_result, action_id, timeout)
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response_status)
        summary['quarantine_status'] = response_status['status']
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_hash(self, param):
        """ This function is used to handle the unblock hash action.

        :param param: Dictionary of input parameters
        :return: status(Success/Failed)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param[DEFENDERATP_JSON_FILE_HASH]
        comment = param[DEFENDERATP_JSON_COMMENT]

        endpoint = '{0}{1}'.format(DEFENDERATP_MSGRAPH_API_BASE_URL,
                                   DEFENDERATP_UNBLOCK_HASH_ENDPOINT.format(file_hash=file_hash))

        request_data = {
            'Comment': comment
        }

        # make rest call
        ret_val, _ = self._update_request(endpoint=endpoint, action_result=action_result, method='post',
                                          data=json.dumps(request_data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, DEFENDERATP_FILE_HASH_UNBLOCKED_SUCCESS_MSG)

    def _handle_block_hash(self, param):
        """ This function is used to handle the block hash action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param[DEFENDERATP_JSON_FILE_HASH]
        comment = param[DEFENDERATP_JSON_COMMENT]

        endpoint = "{0}{1}".format(DEFENDERATP_MSGRAPH_API_BASE_URL, DEFENDERATP_FILE_BLOCK_ENDPOINT
                                   .format(file_hash=file_hash))

        data = {
            'Comment': comment
        }

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result, method='post',
                                                 data=json.dumps(data))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, DEFENDERATP_FILE_BLOCKED_MSG)

    def _handle_list_devices(self, param):
        """ This function is used to handle the list device action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        input_type = param[DEFENDERATP_JSON_INPUT_TYPE]
        input = param.get(DEFENDERATP_JSON_INPUT)
        if input:
            input = UnicodeDammit(input).unicode_markup.encode('utf-8')

        limit = param.get(DEFENDERATP_JSON_LIMIT, DEFENDERATP_ALERT_DEFAULT_LIMIT)

        try:
            limit = int(limit)
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_LIMIT_VALIDATION_MSG)
        except:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_LIMIT_VALIDATION_MSG)

        endpoint = ""
        # Check if input type is All
        if input_type == DEFENDERATP_ALL_CONST:
            endpoint = DEFENDERATP_MACHINES_ENDPOINT

        # If input not given
        elif input_type and not input:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INPUT_REQUIRED_MSG)

        elif input and input_type:
            # Check for valid domain
            if input_type == DEFENDERATP_DOMAIN_CONST:
                try:
                    if phantom.is_domain(input):
                        endpoint = DEFENDERATP_DOMAIN_MACHINES_ENDPOINT.format(input=input)
                    else:
                        return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_PARAM_VALIDATION_FAILED_MSG
                                                        .format(DEFENDERATP_DOMAIN_CONST))
                except:
                    endpoint = DEFENDERATP_DOMAIN_MACHINES_ENDPOINT.format(input=input)
                    self.debug_print("Validation for the valid domain returned an exception. Hence, ignoring the validation and continuing the action execution.")

            # Check for valid File hash
            elif input_type == DEFENDERATP_FILE_HASH_CONST:
                try:
                    if phantom.is_sha1(input) or phantom.is_sha256(input) or phantom.is_md5(input):
                        endpoint = DEFENDERATP_FILE_MACHINES_ENDPOINT.format(input=input)
                    else:
                        return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_PARAM_VALIDATION_FAILED_MSG
                                                        .format(DEFENDERATP_FILE_HASH_CONST))
                except:
                    endpoint = DEFENDERATP_FILE_MACHINES_ENDPOINT.format(input=input)
                    self.debug_print(
                        "Validation for the valid sha1, sha256, and md5 hash returned an exception. Hence, ignoring the validation and continuing the action execution.")

        url = "{0}{1}?$top={2}".format(DEFENDERATP_MSGRAPH_API_BASE_URL, endpoint, limit)

        # make rest call
        ret_val, response = self._update_request(endpoint=url, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_ERROR, "No data found")

        for machine in response.get('value', []):
            action_result.add_data(machine)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_ERROR, "No device found")

        summary = action_result.update_summary({})
        summary['total_devices'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_alerts(self, param):
        """ This function is used to handle the list alerts action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        input_type = param.get(DEFENDERATP_JSON_INPUT_TYPE, DEFENDERATP_ALL_CONST)
        input = param.get(DEFENDERATP_JSON_INPUT, "")
        if input:
            input = UnicodeDammit(input).unicode_markup.encode('utf-8')

        limit = param.get(DEFENDERATP_JSON_LIMIT, DEFENDERATP_ALERT_DEFAULT_LIMIT)

        try:
            limit = int(limit)
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_LIMIT_VALIDATION_MSG)
        except:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_LIMIT_VALIDATION_MSG)

        endpoint = ""

        # Check if type is All
        if input_type == DEFENDERATP_ALL_CONST:
            endpoint = DEFENDERATP_ALERTS_ENDPOINT

        # Check if input is not present
        elif input_type and not input:
            return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_INPUT_REQUIRED_MSG)

        elif input and input_type:
            # Check for valid IP
            if input_type == DEFENDERATP_IP_CONST:
                try:
                    ipaddress.ip_address(unicode(input))
                except:
                    return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_PARAM_VALIDATION_FAILED_MSG
                                                    .format(DEFENDERATP_IP_CONST))
                endpoint = DEFENDERATP_IP_ALERTS_ENDPOINT.format(input=input)
            # Check for valid domain
            elif input_type == DEFENDERATP_DOMAIN_CONST:
                try:
                    if phantom.is_domain(input):
                        endpoint = DEFENDERATP_DOMAIN_ALERTS_ENDPOINT.format(input=input)
                    else:
                        return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_PARAM_VALIDATION_FAILED_MSG
                                                        .format(DEFENDERATP_DOMAIN_CONST))
                except:
                    endpoint = DEFENDERATP_DOMAIN_ALERTS_ENDPOINT.format(input=input)
                    self.debug_print("Validation for the valid domain returned an exception. Hence, ignoring the validation and continuing the action execution.")

            # Check for valid File hash
            elif input_type == DEFENDERATP_FILE_HASH_CONST:
                try:
                    if phantom.is_sha1(input) or phantom.is_sha256(input) or phantom.is_md5(input):
                        endpoint = DEFENDERATP_FILE_ALERTS_ENDPOINT.format(input=input)
                    else:
                        return action_result.set_status(phantom.APP_ERROR, DEFENDERATP_PARAM_VALIDATION_FAILED_MSG
                                                        .format(DEFENDERATP_FILE_HASH_CONST))
                except:
                    endpoint = DEFENDERATP_FILE_ALERTS_ENDPOINT.format(input=input)
                    self.debug_print(
                        "Validation for the valid sha1, sha256, and md5 hash returned an exception. Hence, ignoring the validation and continuing the action execution.")

        url = "{0}{1}?$top={2}".format(DEFENDERATP_MSGRAPH_API_BASE_URL, endpoint, limit)

        # make rest call
        ret_val, response = self._update_request(endpoint=url, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_ERROR, "No data found")

        for alert in response.get('value', []):
            action_result.add_data(alert)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_ERROR, "No alerts found")

        summary = action_result.update_summary({})
        summary['total_alerts'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_sessions(self, param):
        """ This function is used to handle the list sessions action.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_id = param[DEFENDERATP_JSON_DEVICE_ID]
        endpoint = "{0}{1}".format(DEFENDERATP_MSGRAPH_API_BASE_URL, DEFENDERATP_SESSIONS_ENDPOINT
                                   .format(device_id=device_id))

        # make rest call
        ret_val, response = self._update_request(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for session in response.get('value', []):
            action_result.add_data(session)

        if not action_result.get_data_size():
            return action_result.set_status(phantom.APP_ERROR, "No sessions found for the given device")
        summary = action_result.update_summary({})
        summary['total_sessions'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'quarantine_device': self._handle_quarantine_device,
            'unquarantine_device': self._handle_unquarantine_device,
            'get_status': self._handle_get_status,
            'scan_device': self._handle_scan_device,
            'quarantine_file': self._handle_quarantine_file,
            'list_devices': self._handle_list_devices,
            'list_alerts': self._handle_list_alerts,
            'list_sessions': self._handle_list_sessions
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
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

        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._tenant = UnicodeDammit(config[DEFENDERATP_CONFIG_TENANT_ID]).unicode_markup.encode('utf-8')
        self._client_id = UnicodeDammit(config[DEFENDERATP_CONFIG_CLIENT_ID]).unicode_markup.encode('utf-8')
        self._access_token = self._state.get(DEFENDERATP_TOKEN_STRING, {}).get(DEFENDERATP_ACCESS_TOKEN_STRING)
        self._refresh_token = self._state.get(DEFENDERATP_TOKEN_STRING, {}).get(DEFENDERATP_REFRESH_TOKEN_STRING)
        self._client_secret = UnicodeDammit(config[DEFENDERATP_CONFIG_CLIENT_SECRET]).unicode_markup.encode('utf-8')

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

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print "Accessing the Login page"
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print "Logging into Platform to get the session id"
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: {0}".format(str(e)))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = WindowsDefenderAtpConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
