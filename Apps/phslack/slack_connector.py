# File: slack_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.vault import Vault

# Imports local to this App
import slack_consts as consts

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
        print('Unable to save state file: {0}'.format(str(e)))

    return phantom.APP_SUCCESS


def handle_request(request, path):

    try:

        payload = json.loads(request.POST.get('payload'))

        if not payload:
            return HttpResponse("Found no payload field in rest post body", content_type="text/plain", status=400)

        callback_id = dict(payload).get('callback_id')
        if not callback_id:
            return HttpResponse("Found no callback_id field in payload", content_type="text/plain", status=400)

        try:
            callback_json = json.loads(UnicodeDammit(callback_id).unicode_markup)
        except Exception as e:
            return HttpResponse("Could not parse JSON from callback_id field in payload: {0}".format(e), content_type="text/plain", status=400)

        directory = dict(callback_json).get('directory')
        if not directory:
            return HttpResponse("Found no state directory in callback", content_type="text/plain", status=400)

        if len(directory.split(",")) != 2:
            return HttpResponse("Unexpected state directory found in callback", content_type="text/plain", status=400)

        apps_directory, local_data_directory = [x.strip() for x in directory.split(',')]

        state_filename = dict(callback_json).get('state')
        if not state_filename:
            return HttpResponse("Found no state filename in callback", content_type="text/plain", status=400)

        state_path = "{0}/{1}".format(apps_directory, state_filename)
        try:
            state = json.loads(open(state_path, 'r').read())
        except Exception as e:
            return HttpResponse("Could not properly read state file: {0}".format(e), content_type="text/plain", status=400)

        my_token = dict(state).get('token', 'my token does not exist')
        their_token = dict(payload).get('token', 'their token is missing')

        if my_token != their_token:
            return HttpResponse("Authorization failed. Tokens do not match.", content_type="text/plain", status=400)

        answer_filename = dict(callback_json).get('answer')
        if not answer_filename:
            return HttpResponse("Found no answer filename in callback", content_type="text/plain", status=400)

        answer_path = "{0}/{1}".format(local_data_directory, answer_filename)
        try:
            answer_file = open(answer_path, 'w')
        except Exception as e:
            return HttpResponse("Could not open answer file for writing: {0}".format(e), content_type="text/plain", status=400)

        answer_file.write(json.dumps(payload))
        answer_file.close()

        confirmation = dict(callback_json).get('confirmation')

    except Exception as e:
        return HttpResponse("There was an error processing the response: {0}".format(e), content_type="text/plain", status=500)

    return HttpResponse(confirmation, content_type="text/plain")


# Define the App Class
class SlackConnector(phantom.BaseConnector):

    ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"
    ACTION_ID_LIST_CHANNELS = "list_channels"
    ACTION_ID_POST_MESSAGE = "send_message"
    ACTION_ID_ASK_QUESTION = "ask_question"
    ACTION_ID_GET_RESPONSE = "get_response"
    ACTION_ID_UPLOAD_FILE = "upload_file"
    ACTION_ID_LIST_USERS = "list_users"
    ACTION_ID_GET_USER = "get_user"
    ACTION_ID_STOP_BOT = "stop_bot"
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_CREATE_CHANNEL = "create_channel"
    ACTION_ID_INVITE_USERS = "invite_users"

    def __init__(self):

        # Call the BaseConnectors init first
        super(SlackConnector, self).__init__()

        self._base_url = None
        self._state = {}
        self._slack_client = None
        self._interval = None
        self._timeout = None

    def initialize(self):

        self._bot_token = self.get_config()[consts.SLACK_JSON_BOT_TOKEN]
        self._base_url = consts.SLACK_BASE_URL
        self._state = self.load_state()

        config = self.get_config()

        self._interval = self._validate_integers(self, config.get("response_poll_interval", 30), consts.SLACK_RESP_POLL_INTERVAL_KEY)
        if self._interval is None:
            return self.get_status()

        self._timeout = self._validate_integers(self, config.get("timeout", 30), consts.SLACK_TIMEOUT_KEY)
        if self._timeout is None:
            return self.get_status()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version")

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)
        _save_app_state(self._state, self.get_asset_id(), self)

        return phantom.APP_SUCCESS

    def _get_phantom_base_url_slack(self, action_result):

        rest_url = consts.SLACK_PHANTOM_SYS_INFO_URL.format(url=self.get_phantom_base_url())

        ret_val, resp_json = self._make_rest_call(action_result, rest_url, False)

        if phantom.is_fail(ret_val):
            return RetVal(ret_val)

        phantom_base_url = resp_json.get('base_url')

        if not phantom_base_url:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Phantom Base URL not found in System Setting. Please specify this value in System Settings"))

        return RetVal(phantom.APP_SUCCESS, phantom_base_url)

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

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
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                self._handle_py_ver_compat_for_input_str(error_text))

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON. {}".format(self._get_error_message_from_exception(e))), None)

        # the ok parameter in a response from slack says if the call passed or failed
        if resp_json.get('ok', '') is not False:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        action_result.add_data(resp_json)

        error = resp_json.get('error', '')
        if error == 'invalid_auth':
            error = 'The configured bot token is invalid.'
        elif error == 'not_in_channel':
            error = 'The configured bot is not in the specified channel. Invite the bot to that channel to send messages there.'
        elif not error:
            error = consts.SLACK_ERR_FROM_SERVER

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
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Got no response from InsightVM instance"), None)

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
                    error_code = consts.SLACK_ERR_CODE_UNAVAILABLE
                    error_msg = e.args[0]
            else:
                error_code = consts.SLACK_ERR_CODE_UNAVAILABLE
                error_msg = consts.SLACK_ERR_MESSAGE_UNKNOWN
        except:
            error_code = consts.SLACK_ERR_CODE_UNAVAILABLE
            error_msg = consts.SLACK_ERR_MESSAGE_UNKNOWN

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = consts.SLACK_UNICODE_DAMMIT_TYPE_ERR_MESSAGE
        except:
            error_msg = consts.SLACK_ERR_MESSAGE_UNKNOWN

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _make_rest_call(self, action_result, rest_url, verify, method=requests.get, headers={}, body={}):

        try:
            r = method(rest_url, verify=verify, headers=headers, data=json.dumps(body))
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "REST call failed. {0}".format(self._get_error_message_from_exception(e))), None)

        try:
            resp_json = r.json()
        except:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to decode the response as JSON"), None)

        if 'failed' in resp_json:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "REST call failed. Message: {0}".format(resp_json.get('message', 'NA'))), None)

        if 200 <= r.status_code <= 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        details = 'NA'

        if resp_json:
            details = json.dumps(resp_json).replace('{', '{{').replace('}', '}}')

        details = self._handle_py_ver_compat_for_input_str(details)

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Error from server: status code: {0} details: {1}".format(r.status_code, details)), None)

    def _make_slack_rest_call(self, action_result, endpoint, body, headers={}, files={}):

        body.update({'token': self._bot_token})

        # send api call to slack
        try:
            response = requests.post(self._base_url + endpoint,
                    data=body,
                    headers=headers,
                    files=files)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "{}. {}".format(consts.SLACK_ERR_SERVER_CONNECTION, self._get_error_message_from_exception(e))), None)

        return self._process_response(response, action_result)

    def _validate_integers(self, action_result, parameter, key):
        """Validate the provided input parameter value is a non-zero positive integer and returns the integer value of the parameter itself.

        Parameters:
            :param action_result: object of ActionResult class
            :param parameter: input parameter

        Returns:
            :return: integer value of the parameter
        """
        try:
            if not float(parameter).is_integer():
                action_result.set_status(phantom.APP_ERROR, consts.SLACK_ERR_INVALID_INT.format(key=key))
                return None

            parameter = int(parameter)
        except:
            action_result.set_status(phantom.APP_ERROR, consts.SLACK_ERR_INVALID_INT.format(key=key))
            return None

        if parameter <= 0:
            action_result.set_status(phantom.APP_ERROR, consts.SLACK_ERR_NEGATIVE_AND_ZERO_INT.format(key=key))
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
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _test_connectivity(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        ret_val, resp_json = self._make_slack_rest_call(action_result, consts.SLACK_AUTH_TEST, {})

        if not ret_val:
            self.save_progress("Test Connectivity Failed")
            return ret_val

        action_result.add_data(resp_json)

        self.save_progress("Auth check to Slack passed. Configuring app for team, {}".format(resp_json.get('team', 'Unknown Team')))

        bot_username = resp_json.get('user')
        bot_user_id = resp_json.get('user_id')

        self.save_progress("Got username, {0}, and user ID, {1}, for the bot".format(bot_username, bot_user_id))

        self._state['bot_name'] = bot_username
        self._state['bot_id'] = bot_user_id

        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_channel(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        user_token = self.get_config().get('user_token')

        if not user_token:
            return action_result.set_status(phantom.APP_ERROR, "user_token is required for this action. Navigate to the asset's configuration and add a token now and try again.")

        headers = {
            "Authorization": "Bearer " + user_token,
            'Content-Type': 'application/json'
        }

        params = {
            'name': param['name'],
            'token': user_token,
            'validate': True
        }
        endpoint = consts.SLACK_BASE_URL + consts.SLACK_CHANNEL_CREATE_ENDPOINT

        # private channel
        if param['channel_type'] == "private":
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
            return action_result.set_status(
                phantom.APP_ERROR,
                "Error creating channel: {}\r\nDetails: {}".format(self._handle_py_ver_compat_for_input_str(resp_json.get('error', 'N/A')),
                self._handle_py_ver_compat_for_input_str(resp_json.get('detail', '')))
            )

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_channels(self, param):

        self.debug_print("param", param)
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        limit = self._validate_integers(action_result, param.get("limit", consts.SLACK_DEFAULT_LIMIT), consts.SLACK_LIMIT_KEY)
        if limit is None:
            return action_result.get_status()

        ret_val, resp_json = self._paginator(action_result, consts.SLACK_LIST_CHANNEL, "channels", limit=limit)

        if not ret_val:
            return action_result.get_status()

        action_result.add_data(resp_json)

        channels = resp_json.get('channels', [])

        for chan in channels:
            name = chan.get('name', 'unknownchannel')
            chan['name'] = '#' + name

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

        body.update({"limit": consts.SLACK_DEFAULT_LIMIT})
        results = {}

        while True:
            ret_val, resp_json = self._make_slack_rest_call(action_result, endpoint, body)

            if not ret_val:
                return phantom.APP_ERROR, None

            key_result_value = resp_json.get(key, [])

            if not results:
                if not key_result_value:
                    return action_result.set_status(phantom.APP_ERROR, "{} data not found in json output".format("users" if key == "members" else key)), None
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

        limit = self._validate_integers(action_result, param.get("limit", consts.SLACK_DEFAULT_LIMIT), consts.SLACK_LIMIT_KEY)
        if limit is None:
            return action_result.get_status()

        ret_val, resp_json = self._paginator(action_result, consts.SLACK_USER_LIST, "members", limit=limit)

        if not ret_val:
            return action_result.get_status()

        action_result.add_data(resp_json)

        users = resp_json.get('members', [])

        for user in users:
            name = user.get('name', 'unknownuser')
            user['name'] = '@' + name

        action_result.set_summary({"num_users": len(users)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_user(self, param):

        self.debug_print("param", param)
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        user_id = param['user_id']

        if not user_id.startswith('U'):
            return action_result.set_status(phantom.APP_ERROR, "The user parameter must be a user ID")

        ret_val, resp_json = self._make_slack_rest_call(action_result, consts.SLACK_USER_INFO, {'user': user_id})

        if not ret_val:
            return phantom.APP_ERROR

        action_result.add_data(resp_json)

        user = resp_json.get('user')

        if not user:
            return action_result.set_status(phantom.APP_ERROR, "User data not found in json output")

        name = user.get('name', '')
        user['name'] = '@' + name

        return action_result.set_status(phantom.APP_SUCCESS, "User data successfully retrieved")

    def _invite_users(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        user_token = self.get_config().get('user_token')

        if not user_token:
            return action_result.set_status(phantom.APP_ERROR, "user_token is required for this action. Navigate to the asset's configuration and add a token now and try again.")

        headers = {
            "Authorization": "Bearer " + user_token,
            'Content-Type': 'application/json'
        }

        users = [x.strip() for x in param['users'].split(',')]
        users = list(filter(None, users))

        params = {
            'users': users,
            'channel': param['channel_id'],
            'token': user_token
        }

        endpoint = consts.SLACK_BASE_URL + consts.SLACK_INVITE_TO_CHANNEL

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
            return action_result.set_status(
                phantom.APP_ERROR,
                "Error inviting to channel: {}\r\nDetails: {}".format(self._handle_py_ver_compat_for_input_str(resp_json.get('error', 'N/A')),
                self._handle_py_ver_compat_for_input_str(resp_json.get('detail', '')))
            )

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Invite sent to user(s)")

    def _send_message(self, param):

        self.debug_print("param", param)
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        message = self._handle_py_ver_compat_for_input_str(param['message'])

        if '\\' in message:
            if self._python_version == 2:
                message = message.decode('string_escape')
            else:
                message = bytes(message, "utf-8").decode("unicode_escape")

        if len(message) > consts.SLACK_MESSAGE_LIMIT:
            return (action_result.set_status(phantom.APP_ERROR, "Message too long. Please limit messages to {0} characters.".format(consts.SLACK_MESSAGE_LIMIT)))

        params = {'channel': param['destination'], 'text': message, 'as_user': True}

        ret_val, resp_json = self._make_slack_rest_call(action_result, consts.SLACK_SEND_MESSAGE, params)

        if not ret_val:
            return ret_val

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Message sent successfully")

    def _upload_file(self, param):

        self.debug_print("param", param)
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        caption = param.get('caption', '')

        if caption:
            caption += ' -- '

        caption += 'Uploaded from Phantom'

        vault_id = param['file']

        # check the vault for a file with the supplied ID
        try:
            file_info = Vault.get_file_info(vault_id)
            if not file_info:
                return action_result.set_status(phantom.APP_ERROR, consts.SLACK_ERR_UNABLE_TO_FETCH_FILE.format(key="info"))

            file_path = file_info[0].get("path")
            if not file_path:
                return action_result.set_status(phantom.APP_ERROR, consts.SLACK_ERR_UNABLE_TO_FETCH_FILE.format(key="path"))

            file_name = file_info[0].get("name")
            if not file_name:
                return action_result.set_status(phantom.APP_ERROR, consts.SLACK_ERR_UNABLE_TO_FETCH_FILE.format(key="name"))
        except:
            return action_result.set_status(phantom.APP_ERROR, "Could not find the specified Vault ID in vault")

        upfile = open(file_path, 'rb')

        params = {'channels': param['destination'], 'initial_comment': caption, 'filename': file_name}

        ret_val, resp_json = self._make_slack_rest_call(action_result, consts.SLACK_UPLOAD_FILE, params, files={'file': upfile})

        if not ret_val:
            return ret_val

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

        return action_result.set_status(phantom.APP_SUCCESS, "File uploaded successfully.")

    def _stop_bot(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        pid = self._state.get('pid', '')
        if pid:

            self._state.pop('pid')

            try:
                if 'slack_bot.pyc' in sh.ps('ww', pid):  # pylint: disable=E1101
                    sh.kill(pid)  # pylint: disable=E1101
                    action_result.set_status(phantom.APP_SUCCESS, "SlackBot has been stopped.")

            except:
                action_result.set_status(phantom.APP_SUCCESS, "SlackBot isn't running, not going to stop it.")

        else:
            action_result.set_status(phantom.APP_SUCCESS, "SlackBot isn't running, not going to stop it.")

        rest_url = consts.SLACK_PHANTOM_ASSET_INFO_URL.format(url=self.get_phantom_base_url(), asset_id=self.get_asset_id())

        ret_val, resp_json = self._make_rest_call(action_result, rest_url, False)

        if phantom.is_fail(ret_val):
            return ret_val

        asset_config = resp_json.get('configuration', {})

        ingest_config = asset_config.get('ingest', {})

        poll = ingest_config.get('poll')

        if poll is None:
            return action_result.set_status(phantom.APP_SUCCESS, "{} Failed to disable ingestion, please check that ingest settings are correct."
                    .format(action_result.get_message()))

        if not poll:
            return action_result.set_status(phantom.APP_SUCCESS, "{} Ingestion isn't enabled, not going to disable it.".format(action_result.get_message()))

        ingest_config['poll'] = False

        body = {'configuration': asset_config}

        ret_val, resp_json = self._make_rest_call(action_result, rest_url, False, method=requests.post, body=body)

        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "{} Ingestion has been disabled.".format(action_result.get_message()))

    def _on_poll(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        ret_val, resp_json = self._make_slack_rest_call(action_result, consts.SLACK_AUTH_TEST, {})

        if not ret_val:
            return ret_val

        bot_id = resp_json.get('user_id')

        if not bot_id:
            return action_result.set_status(phantom.APP_ERROR, "Could not get bot ID from Slack")

        pid = self._state.get('pid', '')

        if pid:

            try:
                if 'slack_bot.pyc' in sh.ps('ww', pid):  # pylint: disable=E1101
                    self.save_progress("Detected SlackBot running with pid {0}".format(pid))
                    return action_result.set_status(phantom.APP_SUCCESS, "SlackBot already running")
            except:
                pass

        config = self.get_config()
        bot_token = config.get('bot_token', '')
        ph_auth_token = config.get('ph_auth_token', None)

        if not ph_auth_token:
            return action_result.set_status(phantom.APP_ERROR, "The ph_auth_token asset configuration parameter is required to run the on_poll action.")

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
                return action_result.set_status(phantom.APP_ERROR, "Detected an instance of SlackBot running with the same bot token. Not going to start new instance.")

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

        return action_result.set_status(phantom.APP_SUCCESS, "SlackBot started")

    def _ask_question(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))
        config = self.get_config()

        # Need to make sure the configured verification token is in the app state so the request_handler can use it to verify POST requests
        if 'token' not in self._state:
            self._state['token'] = config[consts.SLACK_JSON_VERIFICATION_TOKEN]
            self.save_state(self._state)
        elif self._state['token'] != config[consts.SLACK_JSON_VERIFICATION_TOKEN]:
            self._state['token'] = config[consts.SLACK_JSON_VERIFICATION_TOKEN]
            self.save_state(self._state)

        # The default permission of state file in Phantom v4.9 is 600. So when from rest handler method (handle_request) reads this state file,
        # the action fails with "permission denied" error message
        # Adding the data of state file to another temporary file to resolve this issue
        _save_app_state(self._state, self.get_asset_id(), self)

        question = param['question']
        if len(question) > consts.SLACK_MESSAGE_LIMIT:
            return action_result.set_status(phantom.APP_ERROR, "Question too long. Please limit questions to {0} characters.".format(consts.SLACK_MESSAGE_LIMIT))

        user = param['destination']
        if user.startswith('#') or user.startswith('C'):
            # Don't want to send question to channels because then we would not know who was answering
            return action_result.set_status(phantom.APP_ERROR, "Questions may only be sent as direct messages to users. They may not be sent to channels.")

        qid = uuid.uuid4().hex
        apps_state_dir = os.path.dirname(os.path.abspath(__file__))
        local_data_state_dir = self.get_state_dir()
        state_dir = "{0},{1}".format(apps_state_dir, local_data_state_dir)

        answer_filename = '{0}.json'.format(qid)
        state_filename = "{0}_state.json".format(self.get_asset_id())

        path_json = {'answer': answer_filename,
                     'state': state_filename,
                     'directory': state_dir,
                     'confirmation': param.get('confirmation', ' ')}

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
                          'callback_id': json.dumps(path_json),
                          'color': '#422E61',
                          'attachment_type': 'default',
                          'actions': answers
                        }
                      ]

        params = {'channel': user, 'attachments': json.dumps(answer_json), 'as_user': True}

        ret_val, resp_json = self._make_slack_rest_call(action_result, consts.SLACK_SEND_MESSAGE, params)
        if not ret_val:
            return phantom.APP_ERROR

        answer_path = "{0}/{1}".format(local_data_state_dir, answer_filename)
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

            resp_json = json.loads(answer_file.read())

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
            return action_result.set_status(phantom.APP_ERROR, "Response to question not available")

        try:
            resp_json = json.loads(answer_file.read())
        except:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while parsing the response")

        action_result.add_data(resp_json)
        action_result.set_summary({'response_received': True, 'response': resp_json.get("actions", [{}])[0].get("value")})

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = None

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == self.ACTION_ID_TEST_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action_id == self.ACTION_ID_LIST_CHANNELS:
            ret_val = self._list_channels(param)
        elif action_id == self.ACTION_ID_POST_MESSAGE:
            ret_val = self._send_message(param)
        elif action_id == self.ACTION_ID_ASK_QUESTION:
            ret_val = self._ask_question(param)
        elif action_id == self.ACTION_ID_GET_RESPONSE:
            ret_val = self._get_response(param)
        elif action_id == self.ACTION_ID_UPLOAD_FILE:
            ret_val = self._upload_file(param)
        elif action_id == self.ACTION_ID_LIST_USERS:
            ret_val = self._list_users(param)
        elif action_id == self.ACTION_ID_GET_USER:
            ret_val = self._get_user(param)
        elif action_id == self.ACTION_ID_STOP_BOT:
            ret_val = self._stop_bot(param)
        elif action_id == self.ACTION_ID_ON_POLL:
            ret_val = self._on_poll(param)
        elif action_id == self.ACTION_ID_CREATE_CHANNEL:
            ret_val = self._create_channel(param)
        elif action_id == self.ACTION_ID_INVITE_USERS:
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
