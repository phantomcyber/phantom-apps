# File: slack_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
import phantom.rules as ph_rules
try:
    from urllib.parse import unquote
except:
    from urllib import unquote

# Imports local to this App
from slack_consts import *

from django.http import HttpResponse
from bs4 import BeautifulSoup
from bs4 import UnicodeDammit
import simplejson as json
import subprocess
import requests
import shlex
import time
import uuid
import os
import sh
import sys


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


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


def _save_app_state(state, asset_id, app_connector=None):
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
        if app_connector:
            app_connector.debug_print('Unable to save state file: {0}'.format(str(e)))
        print('Unable to save state file: {0}'.format(str(e)))

    return phantom.APP_SUCCESS


def handle_request(request, path):

    try:

        payload = json.loads(request.POST.get('payload'))

        if not payload:
            return HttpResponse(SLACK_ERR_PAYLOAD_NOT_FOUND, content_type="text/plain", status=400)

        callback_id = dict(payload).get('callback_id')
        if not callback_id:
            return HttpResponse(SLACK_ERR_CALLBACK_ID_NOT_FOUND, content_type="text/plain", status=400)

        try:
            callback_json = json.loads(UnicodeDammit(callback_id).unicode_markup)
        except Exception as e:
            return HttpResponse(SLACK_ERR_PARSE_JSON_FROM_CALLBACK_ID.format(error=e), content_type="text/plain", status=400)

        apps_directory = os.path.dirname(os.path.abspath(__file__))

        asset_id = dict(callback_json).get('asset_id')
        if not asset_id:
            return HttpResponse(SLACK_ERR_STATE_FILE_NOT_FOUND, content_type="text/plain", status=400)

        state_filename = "{0}_state.json".format(asset_id)
        state_path = "{0}/{1}".format(apps_directory, state_filename)
        try:
            with open(state_path, 'r') as state_file_obj:
                state_file_data = state_file_obj.read()
                state = json.loads(state_file_data)
        except Exception as e:
            return HttpResponse(SLACK_ERR_UNABLE_TO_READ_STATE_FILE.format(error=e), content_type="text/plain", status=400)

        local_data_directory = dict(state).get('local_data_path')
        if not local_data_directory:
            return HttpResponse(SLACK_ERR_STATE_DIR_NOT_FOUND, content_type="text/plain", status=400)

        my_token = dict(state).get('token', 'my token does not exist')
        their_token = dict(payload).get('token', 'their token is missing')

        if my_token != their_token:
            return HttpResponse(SLACK_ERR_AUTH_FAILED, content_type="text/plain", status=400)

        qid = dict(callback_json).get('qid')
        if not qid:
            return HttpResponse(SLACK_ERR_ANSWER_FILE_NOT_FOUND, content_type="text/plain", status=400)

        answer_filename = '{0}.json'.format(qid)
        answer_path = "{0}/{1}".format(local_data_directory, answer_filename)
        try:
            answer_file = open(answer_path, 'w')
        except Exception as e:
            return HttpResponse(SLACK_ERR_COULD_NOT_OPEN_ANSWER_FILE.format(error=e), content_type="text/plain", status=400)

        try:
            answer_file.write(json.dumps(payload))
            answer_file.close()
        except Exception as e:
            return HttpResponse(SLACK_ERR_WHILE_WRITING_ANSWER_FILE.format(error=e), content_type="text/plain", status=400)

        confirmation = dict(callback_json).get('confirmation')

    except Exception as e:
        return HttpResponse(SLACK_ERR_PROCESS_RESPONSE.format(error=e), content_type="text/plain", status=500)

    return HttpResponse(confirmation, content_type="text/plain")


# Define the App Class
class SlackConnector(phantom.BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SlackConnector, self).__init__()

        self._base_url = None
        self._state = {}
        self._slack_client = None
        self._interval = None
        self._timeout = None

    def initialize(self):

        config = self.get_config()

        self._bot_token = config[SLACK_JSON_BOT_TOKEN]
        self._base_url = SLACK_BASE_URL
        self._state = self.load_state()

        self._interval = self._validate_integers(self, config.get("response_poll_interval", 30), SLACK_RESP_POLL_INTERVAL_KEY)
        if self._interval is None:
            return self.get_status()

        self._timeout = self._validate_integers(self, config.get("timeout", 30), SLACK_TIMEOUT_KEY)
        if self._timeout is None:
            return self.get_status()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, SLACK_ERR_FETCHING_PYTHON_VERSION)

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)
        _save_app_state(self._state, self.get_asset_id(), self)

        return phantom.APP_SUCCESS

    def _get_phantom_base_url_slack(self, action_result):

        rest_url = SLACK_PHANTOM_SYS_INFO_URL.format(url=self.get_phantom_base_url())

        ret_val, resp_json = self._make_rest_call(action_result, rest_url, False)

        if phantom.is_fail(ret_val):
            return RetVal(ret_val)

        phantom_base_url = resp_json.get('base_url')

        if not phantom_base_url:
            return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_ERR_BASE_URL_NOT_FOUND))

        return RetVal(phantom.APP_SUCCESS, phantom_base_url)

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_ERR_EMPTY_RESPONSE.format(code=response.status_code)), None)

    def _process_html_response(self, response, action_result):

        # An html response, is bound to be an error
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
            error_text = SLACK_UNABLE_TO_PARSE_ERR_DETAILS

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                self._handle_py_ver_compat_for_input_str(error_text))

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_ERR_UNABLE_TO_PARSE_JSON_RESPONSE.format(error=self._get_error_message_from_exception(e))), None)

        # The 'ok' parameter in a response from slack says if the call passed or failed
        if resp_json.get('ok', '') is not False:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        action_result.add_data(resp_json)

        error = resp_json.get('error', '')
        if error == 'invalid_auth':
            error = SLACK_ERR_BOT_TOKEN_INVALID
        elif error == 'not_in_channel':
            error = SLACK_ERR_NOT_IN_CHANNEL
        elif not error:
            error = SLACK_ERR_FROM_SERVER

        return RetVal(action_result.set_status(phantom.APP_ERROR, error), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, 'add_debug_data'):
            if r is not None:
                action_result.add_debug_data({'r_status_code': r.status_code})
                action_result.add_debug_data({'r_text': r.text})
                action_result.add_debug_data({'r_headers': r.headers})
            else:
                action_result.add_debug_data({'r_text': 'r is None'})
                return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_ERR_NO_RESPONSE_FROM_SERVER), None)

        # There are just too many differences in the response to handle all of them in the same function
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not an html or json, handle if it is a successfull empty reponse
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

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
                    error_code = SLACK_ERR_CODE_UNAVAILABLE
                    error_msg = e.args[0]
            else:
                error_code = SLACK_ERR_CODE_UNAVAILABLE
                error_msg = SLACK_ERR_MESSAGE_UNKNOWN
        except:
            error_code = SLACK_ERR_CODE_UNAVAILABLE
            error_msg = SLACK_ERR_MESSAGE_UNKNOWN

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = SLACK_UNICODE_DAMMIT_TYPE_ERR_MESSAGE
        except:
            error_msg = SLACK_ERR_MESSAGE_UNKNOWN

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _make_rest_call(self, action_result, rest_url, verify, method=requests.get, headers={}, body={}):

        try:
            r = method(rest_url, verify=verify, headers=headers, data=json.dumps(body))
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "{0}. {1}".format(SLACK_ERR_REST_CALL_FAILED, self._get_error_message_from_exception(e))), None)

        try:
            resp_json = r.json()
        except:
            return RetVal(action_result.set_status(phantom.APP_ERROR, SLACK_ERR_UNABLE_TO_DECODE_JSON_RESPONSE), None)

        if 'failed' in resp_json:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "{0}. Message: {1}".format(SLACK_ERR_REST_CALL_FAILED, resp_json.get('message', 'NA'))), None)

        if 200 <= r.status_code <= 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        details = 'NA'

        if resp_json:
            details = json.dumps(resp_json).replace('{', '{{').replace('}', '}}')

        details = self._handle_py_ver_compat_for_input_str(details)

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Error from server: Status code: {0} Details: {1}".format(r.status_code, details)), None)

    def _make_slack_rest_call(self, action_result, endpoint, body, headers={}, files={}):

        body.update({'token': self._bot_token})

        # send api call to slack
        try:
            response = requests.post("{}{}".format(self._base_url, endpoint),
                    data=body,
                    headers=headers,
                    files=files)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "{}. {}".format(SLACK_ERR_SERVER_CONNECTION, self._get_error_message_from_exception(e))), None)

        return self._process_response(response, action_result)

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """Validate the provided input parameter value is a non-zero positive integer and returns the integer value of the parameter itself.

        Parameters:
            :param action_result: object of ActionResult class
            :param parameter: input parameter
            :param key: input parameter message key
            :allow_zero: whether zero should be considered as valid value or not
            :return: integer value of the parameter or None in case of failure

        Returns:
            :return: integer value of the parameter
        """
        try:
            if not float(parameter).is_integer():
                action_result.set_status(phantom.APP_ERROR, SLACK_ERR_INVALID_INT.format(key=key))
                return None

            parameter = int(parameter)
        except:
            action_result.set_status(phantom.APP_ERROR, SLACK_ERR_INVALID_INT.format(key=key))
            return None

        if parameter < 0:
            action_result.set_status(phantom.APP_ERROR, SLACK_ERR_NEGATIVE_INT.format(key=key))
            return None
        if not allow_zero and parameter == 0:
            action_result.set_status(phantom.APP_ERROR, SLACK_ERR_NEGATIVE_AND_ZERO_INT.format(key=key))
            return None

        return parameter

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
            self.debug_print(SLACK_ERR_PY_2TO3)

        return input_str

    def _test_connectivity(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        ret_val, resp_json = self._make_slack_rest_call(action_result, SLACK_AUTH_TEST, {})

        if not ret_val:
            self.save_progress(SLACK_ERR_TEST_CONN_FAILED)
            return ret_val

        action_result.add_data(resp_json)

        self.save_progress("Auth check to Slack passed. Configuring app for team, {}".format(resp_json.get('team', 'Unknown Team')))

        bot_username = resp_json.get('user')
        bot_user_id = resp_json.get('user_id')

        self.save_progress("Got username, {0}, and user ID, {1}, for the bot".format(bot_username, bot_user_id))

        self._state['bot_name'] = bot_username
        self._state['bot_id'] = bot_user_id

        self.save_progress(SLACK_SUCC_TEST_CONN_PASSED)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_channel(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        user_token = self.get_config().get('user_token')

        if not user_token:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_USER_TOKEN_NOT_PROVIDED)

        headers = {
            "Authorization": "Bearer {}".format(user_token),
            'Content-Type': 'application/json'
        }

        params = {
            'name': param['name'],
            'token': user_token,
            'validate': True
        }
        endpoint = "{}{}".format(SLACK_BASE_URL, SLACK_CHANNEL_CREATE_ENDPOINT)

        # private channel
        channel_type = param.get("channel_type", "public")
        if channel_type not in ["public", "private"]:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_INVALID_CHANNEL_TYPE)
        if channel_type == "private":
            params.update({"is_private": True})

        ret_val, resp_json = self._make_rest_call(
            action_result,
            endpoint,
            False,
            method=requests.post,
            headers=headers,
            body=params
        )

        if not ret_val:
            return ret_val

        if not resp_json.get('ok', True):
            error = resp_json.get('error', 'N/A')
            error_details = self._handle_py_ver_compat_for_input_str(resp_json.get('detail', ''))
            if error_details:
                error_message = "{}: {}\r\nDetails: {}".format(SLACK_ERR_CREATING_CHANNEL, error, error_details)
            else:
                error_message = "{}: {}".format(SLACK_ERR_CREATING_CHANNEL, error)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCC_CHANNEL_CREATED)

    def _list_channels(self, param):

        self.debug_print("param", param)
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        limit = self._validate_integers(action_result, param.get("limit", SLACK_DEFAULT_LIMIT), SLACK_LIMIT_KEY)
        if limit is None:
            return action_result.get_status()

        ret_val, resp_json = self._paginator(action_result, SLACK_LIST_CHANNEL, "channels", limit=limit)

        if not ret_val:
            return action_result.get_status()

        action_result.add_data(resp_json)

        channels = resp_json.get('channels', [])

        for chan in channels:
            name = chan.get('name', 'unknownchannel')
            chan['name'] = '#{}'.format(name)

        action_result.set_summary({"num_public_channels": len(channels)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _paginator(self, action_result, endpoint, key, body={}, limit=None):
        """Fetch results from multiple API calls using pagination for the given endpoint

        Args:
            action_result : Object of ActionResult class
            endpoint : REST endpoint that needs to be attended to the address
            limit : User specified maximum number of events to be returned

        Returns:
            results : The aggregated response
        """

        body.update({"limit": SLACK_DEFAULT_LIMIT})
        results = {}

        while True:
            ret_val, resp_json = self._make_slack_rest_call(action_result, endpoint, body)

            if not ret_val:
                return phantom.APP_ERROR, None

            key_result_value = resp_json.get(key, [])

            if not results:
                if not key_result_value:
                    return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_DATA_NOT_FOUND_IN_OUTPUT.format(key=("users" if key == "members" else key))), None
                results = resp_json
            else:
                results[key].extend(key_result_value)

            result_length = len(results[key])

            if limit and result_length >= limit:
                results[key] = results[key][:limit]
                return phantom.APP_SUCCESS, results

            # set the next cursor
            next_cursor = resp_json.get("response_metadata", {}).get("next_cursor", "")

            if not next_cursor:
                break
            else:
                body.update({"cursor": next_cursor})

        return phantom.APP_SUCCESS, results

    def _list_users(self, param):

        self.debug_print("param", param)
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        limit = self._validate_integers(action_result, param.get("limit", SLACK_DEFAULT_LIMIT), SLACK_LIMIT_KEY)
        if limit is None:
            return action_result.get_status()

        ret_val, resp_json = self._paginator(action_result, SLACK_USER_LIST, "members", limit=limit)

        if not ret_val:
            return action_result.get_status()

        action_result.add_data(resp_json)

        users = resp_json.get('members', [])

        for user in users:
            name = user.get('name', 'unknownuser')
            user['name'] = '@{}'.format(name)

        action_result.set_summary({"num_users": len(users)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_user(self, param):

        self.debug_print("param", param)
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        user_id = param['user_id']

        if not user_id.startswith('U'):
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_NOT_A_USER_ID)

        ret_val, resp_json = self._make_slack_rest_call(action_result, SLACK_USER_INFO, {'user': user_id})

        if not ret_val:
            message = action_result.get_message()
            if message:
                error_message = "{}: {}".format(SLACK_ERR_FETCHING_USER, message)
            else:
                error_message = SLACK_ERR_FETCHING_USER
            return action_result.set_status(phantom.APP_ERROR, error_message)

        action_result.add_data(resp_json)

        user = resp_json.get('user')

        if not user:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_DATA_NOT_FOUND_IN_OUTPUT.format(key="User"))

        name = user.get('name', '')
        user['name'] = '@{}'.format(name)

        return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCC_USER_DATA_RETRIEVED)

    def _invite_users(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        user_token = self.get_config().get('user_token')

        if not user_token:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_USER_TOKEN_NOT_PROVIDED)

        headers = {
            "Authorization": "Bearer {}".format(user_token),
            'Content-Type': 'application/json'
        }

        users = [x.strip() for x in param['users'].split(',')]
        users = list(filter(None, users))
        if not users:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_INVALID_USER)

        params = {
            'users': users,
            'channel': param['channel_id'],
            'token': user_token
        }

        endpoint = "{}{}".format(SLACK_BASE_URL, SLACK_INVITE_TO_CHANNEL)

        ret_val, resp_json = self._make_rest_call(
            action_result,
            endpoint,
            False,
            method=requests.post,
            headers=headers,
            body=params
        )

        if not ret_val:
            return ret_val

        if not resp_json.get('ok', True):
            error = resp_json.get('error', 'N/A')
            error_details = self._handle_py_ver_compat_for_input_str(resp_json.get('detail', ''))
            if error_details:
                error_message = "{}: {}\r\nDetails: {}".format(SLACK_ERR_INVITING_CHANNEL, error, error_details)
            else:
                error_message = "{}: {}".format(SLACK_ERR_INVITING_CHANNEL, error)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCC_INVITE_SENT)

    def _send_message(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        message = self._handle_py_ver_compat_for_input_str(param['message'])

        if '\\' in message:
            if self._python_version == 2:
                message = message.decode('string_escape')
            else:
                message = bytes(message, "utf-8").decode("unicode_escape")

        if len(message) > SLACK_MESSAGE_LIMIT:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_MESSAGE_TOO_LONG.format(limit=SLACK_MESSAGE_LIMIT))

        params = {'channel': param['destination'], 'text': message}

        if 'parent_message_ts' in param:
            # Support for replying in thread
            params['thread_ts'] = param.get('parent_message_ts')

            if 'reply_broadcast' in param:
                params['reply_broadcast'] = param.get('reply_broadcast', False)

        ret_val, resp_json = self._make_slack_rest_call(action_result, SLACK_SEND_MESSAGE, params)

        if not ret_val:
            message = action_result.get_message()
            if message:
                error_message = "{}: {}".format(SLACK_ERR_SENDING_MESSAGE, message)
            else:
                error_message = SLACK_ERR_SENDING_MESSAGE
            return action_result.set_status(phantom.APP_ERROR, error_message)

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCC_MESSAGE_SENT)

    def _add_reaction(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        emoji = self._handle_py_ver_compat_for_input_str(param['emoji'])

        params = {'channel': param['destination'], 'name': emoji, 'timestamp': param['message_ts']}

        ret_val, resp_json = self._make_slack_rest_call(action_result, SLACK_ADD_REACTION, params)

        if not ret_val:
            message = action_result.get_message()
            if message:
                error_message = "{}: {}".format(SLACK_ERR_ADDING_REACTION, message)
            else:
                error_message = SLACK_ERR_ADDING_REACTION
            return action_result.set_status(phantom.APP_ERROR, error_message)

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCC_REACTION_ADDED)

    def _upload_file(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        caption = param.get('caption', '')

        if caption:
            caption += ' -- '

        caption += 'Uploaded from Phantom'

        kwargs = {}
        params = {'channels': param['destination'], 'initial_comment': caption}

        if 'filetype' in param:
            params['filetype'] = param.get('filetype')

        if 'filename' in param:
            params['filename'] = param.get('filename')

        if 'parent_message_ts' in param:
            # Support for replying in thread
            params['thread_ts'] = param.get('parent_message_ts')

        if 'file' in param:
            vault_id = param.get('file')

            # check the vault for a file with the supplied ID
            try:
                success, message, vault_meta_info = ph_rules.vault_info(vault_id=vault_id)
                vault_meta_info = list(vault_meta_info)
                if not success or not vault_meta_info:
                    error_msg = " Error Details: {}".format(unquote(message)) if message else ''
                    return action_result.set_status(phantom.APP_ERROR, "{}.{}".format(SLACK_ERR_UNABLE_TO_FETCH_FILE.format(key="info"), error_msg))
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(SLACK_ERR_UNABLE_TO_FETCH_FILE.format(key="info"), err))

            # phantom vault file path
            file_path = vault_meta_info[0].get('path')
            if not file_path:
                return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_UNABLE_TO_FETCH_FILE.format(key="path"))

            # phantom vault file name
            file_name = vault_meta_info[0].get('name')
            if not file_name:
                return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_UNABLE_TO_FETCH_FILE.format(key="name"))

            upfile = open(file_path, 'rb')
            params['filename'] = file_name
            kwargs['files'] = {'file': upfile}
        elif 'content' in param:
            params['content'] = self._handle_py_ver_compat_for_input_str(param.get('content'))
        else:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_FILE_OR_CONTENT_NOT_PROVIDED)

        ret_val, resp_json = self._make_slack_rest_call(action_result, SLACK_UPLOAD_FILE, params, **kwargs)
        if 'files' in kwargs:
            upfile.close()

        if not ret_val:
            message = action_result.get_message()
            if message:
                error_message = "{}: {}".format(SLACK_ERR_UPLOADING_FILE, message)
            else:
                error_message = SLACK_ERR_UPLOADING_FILE
            return action_result.set_status(phantom.APP_ERROR, error_message)

        file_json = resp_json.get('file', {})

        thumbnail_dict = {}
        pop_list = []

        for key, value in list(file_json.items()):

            if key.startswith('thumb'):

                pop_list.append(key)

                name_arr = key.split('_')

                thumb_name = "{0}_{1}".format(name_arr[0], name_arr[1])

                if thumb_name not in thumbnail_dict:
                    thumbnail_dict[thumb_name] = {}

                thumb_dict = thumbnail_dict[thumb_name]

                if len(name_arr) == 2:
                    thumb_dict['img_url'] = value

                elif name_arr[2] == 'w':
                    thumb_dict['width'] = value

                elif name_arr[2] == 'h':
                    thumb_dict['height'] = value

            elif key == 'initial_comment':
                resp_json['caption'] = value
                pop_list.append(key)

            elif key in ['channels', 'ims', 'groups']:

                if 'destinations' not in resp_json:
                    resp_json['destinations'] = []

                resp_json['destinations'] += value

                pop_list.append(key)

            elif key == 'username':
                pop_list.append(key)

            elif key == 'user':
                resp_json['sender'] = value
                pop_list.append(key)

        for poppee in pop_list:
            file_json.pop(poppee)

        resp_json['thumbnails'] = thumbnail_dict

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCC_FILE_UPLOAD)

    def _stop_bot(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        pid = self._state.get('pid', '')
        if pid:

            self._state.pop('pid')

            try:
                if 'slack_bot.pyc' in sh.ps('ww', pid):  # pylint: disable=E1101
                    sh.kill(pid)  # pylint: disable=E1101
                    action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCC_SLACKBOT_STOPPED)

            except:
                action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCC_SLACKBOT_NOT_RUNNING)

        else:
            action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCC_SLACKBOT_NOT_RUNNING)

        rest_url = SLACK_PHANTOM_ASSET_INFO_URL.format(url=self.get_phantom_base_url(), asset_id=self.get_asset_id())

        ret_val, resp_json = self._make_rest_call(action_result, rest_url, False)

        if phantom.is_fail(ret_val):
            return ret_val

        asset_config = resp_json.get('configuration', {})

        ingest_config = asset_config.get('ingest', {})

        poll = ingest_config.get('poll')

        if poll is None:
            return action_result.set_status(phantom.APP_SUCCESS, SLACK_FAILED_TO_DISABLE_INGESTION
                    .format(message=action_result.get_message()))

        if not poll:
            return action_result.set_status(phantom.APP_SUCCESS, SLACK_INGESTION_NOT_ENABLED.format(message=action_result.get_message()))

        ingest_config['poll'] = False

        body = {'configuration': asset_config}

        ret_val, resp_json = self._make_rest_call(action_result, rest_url, False, method=requests.post, body=body)

        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, SLACK_INGESTION_DISABLED.format(message=action_result.get_message()))

    def _on_poll(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        ret_val, resp_json = self._make_slack_rest_call(action_result, SLACK_AUTH_TEST, {})

        if not ret_val:
            return ret_val

        bot_id = resp_json.get('user_id')

        if not bot_id:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_COULD_NOT_GET_BOT_ID)

        pid = self._state.get('pid', '')

        if pid:

            try:
                if 'slack_bot.pyc' in sh.ps('ww', pid):  # pylint: disable=E1101
                    self.save_progress("Detected SlackBot running with pid {0}".format(pid))
                    return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCC_SLACKBOT_RUNNING)
            except:
                pass

        config = self.get_config()
        bot_token = config.get('bot_token', '')
        ph_auth_token = config.get('ph_auth_token', None)

        if not ph_auth_token:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_AUTH_TOKEN_NOT_PROVIDED)

        app_version = self.get_app_json().get('app_version', '')

        try:
            ps_out = sh.grep(sh.ps('ww', 'aux'), 'slack_bot.pyc')  # pylint: disable=E1101

            if app_version not in ps_out:

                old_pid = shlex.split(str(ps_out))[1]

                self.save_progress("Found an old version of slackbot running with pid {}, going to kill it".format(old_pid))

                sh.kill(old_pid)  # pylint: disable=E1101

        except:
            pass

        try:
            if bot_token in sh.grep(sh.ps('ww', 'aux'), 'slack_bot.pyc'):  # pylint: disable=E1101
                return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_SLACKBOT_RUNNING_WITH_SAME_BOT_TOKEN)

        except:
            pass

        self.save_progress("Starting SlackBot")

        ret_val, base_url = self._get_phantom_base_url_slack(action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        slack_bot_filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'slack_bot.pyc')

        base_url += '/' if not base_url.endswith('/') else ''

        proc = subprocess.Popen(['phenv', 'python2.7', slack_bot_filename, bot_token, bot_id, base_url, app_version, ph_auth_token])

        self._state['pid'] = proc.pid

        self.save_progress("Started SlackBot with pid: {0}".format(proc.pid))

        return action_result.set_status(phantom.APP_SUCCESS, SLACK_SUCC_SLACKBOT_STARTED)

    def _ask_question(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))
        config = self.get_config()

        local_data_state_dir = self.get_state_dir().rstrip('/')
        self._state['local_data_path'] = local_data_state_dir
        # Need to make sure the configured verification token is in the app state so the request_handler can use it to verify POST requests
        if 'token' not in self._state:
            self._state['token'] = config[SLACK_JSON_VERIFICATION_TOKEN]
            self.save_state(self._state)
        elif self._state['token'] != config[SLACK_JSON_VERIFICATION_TOKEN]:
            self._state['token'] = config[SLACK_JSON_VERIFICATION_TOKEN]
            self.save_state(self._state)

        # The default permission of state file in Phantom v4.9 is 600. So when from rest handler method (handle_request) reads this state file,
        # the action fails with "permission denied" error message
        # Adding the data of state file to another temporary file to resolve this issue
        _save_app_state(self._state, self.get_asset_id(), self)

        question = param['question']
        if len(question) > SLACK_MESSAGE_LIMIT:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_QUESTION_TOO_LONG.format(limit=SLACK_MESSAGE_LIMIT))

        user = param['destination']
        if user.startswith('#') or user.startswith('C'):
            # Don't want to send question to channels because then we would not know who was answering
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_UNABLE_TO_SEND_QUESTION_TO_CHANNEL)

        qid = uuid.uuid4().hex

        answer_filename = '{0}.json'.format(qid)
        answer_path = "{0}/{1}".format(local_data_state_dir, answer_filename)

        path_json = {'qid': qid,
                     'asset_id': str(self.get_asset_id()),
                     'confirmation': param.get('confirmation', ' ')}

        callback_id = json.dumps(path_json)
        if len(callback_id) > 255:
            path_json['confirmation'] = ''
            valid_length = 255 - len(json.dumps(path_json))
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_LENGTH_LIMIT_EXCEEDED.format(asset_length=len(self.get_asset_id()), valid_length=valid_length))

        self.save_progress('Asking question with ID: {0}'.format(qid))

        answers = []
        given_answers = [x.strip() for x in param.get('responses', 'yes,no').split(',')]
        given_answers = list(filter(None, given_answers))
        for answer in given_answers:
            answer_json = {'name': answer, 'text': answer, 'value': answer, 'type': 'button'}
            answers.append(answer_json)

        answer_json = [
                        {
                          'text': question,
                          'fallback': 'Phantom cannot post questions on this channel.',
                          'callback_id': callback_id,
                          'color': '#422E61',
                          'attachment_type': 'default',
                          'actions': answers
                        }
                      ]

        params = {'channel': user, 'attachments': json.dumps(answer_json), 'as_user': True}

        ret_val, resp_json = self._make_slack_rest_call(action_result, SLACK_SEND_MESSAGE, params)
        if not ret_val:
            message = action_result.get_message()
            if message:
                error_message = "{}: {}".format(SLACK_ERR_ASKING_QUESTION, message)
            else:
                error_message = SLACK_ERR_ASKING_QUESTION
            return action_result.set_status(phantom.APP_ERROR, error_message)

        loop_count = (self._timeout * 60) / self._interval
        count = 0

        while True:

            if count >= loop_count:
                action_result.set_summary({'response_received': False, 'question_id': qid})
                return action_result.set_status(phantom.APP_SUCCESS)

            try:
                answer_file = open(answer_path, 'r')
            except:
                count += 1
                time.sleep(self._interval)
                continue

            try:
                resp_json = json.loads(answer_file.read())
                answer_file.close()
            except:
                return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_UNABLE_TO_PARSE_RESPONSE)

            break

        action_result.add_data(resp_json)
        action_result.set_summary({'response_received': True, 'question_id': qid, 'response': resp_json.get("actions", [{}])[0].get("value")})

        os.remove(answer_path)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_response(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        qid = self._handle_py_ver_compat_for_input_str(param['question_id'])
        state_dir = self.get_state_dir()
        answer_path = '{0}/{1}.json'.format(state_dir, qid)

        self.save_progress('Checking for response to question with ID: {0}'.format(qid))

        try:
            answer_file = open(answer_path, 'r')
        except:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_QUESTION_RESPONSE_NOT_AVAILABLE)

        try:
            resp_json = json.loads(answer_file.read())
            answer_file.close()
        except:
            return action_result.set_status(phantom.APP_ERROR, SLACK_ERR_UNABLE_TO_PARSE_RESPONSE)

        action_result.add_data(resp_json)
        action_result.set_summary({'response_received': True, 'response': resp_json.get("actions", [{}])[0].get("value")})

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = None

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id: {}".format(self.get_action_identifier()))

        if action_id == ACTION_ID_TEST_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action_id == ACTION_ID_LIST_CHANNELS:
            ret_val = self._list_channels(param)
        elif action_id == ACTION_ID_POST_MESSAGE:
            ret_val = self._send_message(param)
        elif action_id == ACTION_ID_ADD_REACTION:
            ret_val = self._add_reaction(param)
        elif action_id == ACTION_ID_ASK_QUESTION:
            ret_val = self._ask_question(param)
        elif action_id == ACTION_ID_GET_RESPONSE:
            ret_val = self._get_response(param)
        elif action_id == ACTION_ID_UPLOAD_FILE:
            ret_val = self._upload_file(param)
        elif action_id == ACTION_ID_LIST_USERS:
            ret_val = self._list_users(param)
        elif action_id == ACTION_ID_GET_USER:
            ret_val = self._get_user(param)
        elif action_id == ACTION_ID_STOP_BOT:
            ret_val = self._stop_bot(param)
        elif action_id == ACTION_ID_ON_POLL:
            ret_val = self._on_poll(param)
        elif action_id == ACTION_ID_CREATE_CHANNEL:
            ret_val = self._create_channel(param)
        elif action_id == ACTION_ID_INVITE_USERS:
            ret_val = self._invite_users(param)

        return ret_val


if __name__ == '__main__':

    # import pudb
    # pudb.set_trace()

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SlackConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
