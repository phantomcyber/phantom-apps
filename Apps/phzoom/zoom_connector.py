# File: zoom_connector.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from zoom_consts import *
import requests
import json
from bs4 import BeautifulSoup
from datetime import datetime
from datetime import timedelta
import jwt
from bs4 import UnicodeDammit
from password_generator import PasswordGenerator
from urllib.parse import unquote


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ZoomConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ZoomConnector, self).__init__()

        self._state = None

        self._base_url = None

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
            self.debug_print("Error occurred while parsing the error message")
            error_text = PARSE_ERR_MSG

        return error_text

    def _process_empty_response(self, response, action_result):

        if response.status_code in (200, 204):
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Status code: {}. Empty response and no information in the header".format(response.status_code)), None)

    def _process_html_response(self, response, action_result):

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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, unquote(error_text))

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(err_msg), None))

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

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

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()
        token = self._get_jwt(config)

        headers = {
            'Authorization': 'bearer {}'.format(token.decode('utf-8')),
            'User-Agent': 'Zoom-Jwt-Request',
            'content-type': 'application/json'
        }

        kwargs['headers'] = headers

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = "{}{}".format(self._base_url, endpoint)

        try:
            r = request_func(
                            url,
                            verify=config.get('verify_server_cert', False),
                            **kwargs)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error connecting to server. {0}".format(err_msg)), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, _ = self._make_rest_call('/users', action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        self.save_progress("Connected to Zoom API successfully")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_user_settings(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param['user_id']

        ret_val, response = self._make_rest_call('/users/{}/settings'.format(user_id), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, 'User settings for id {} successfully retrieved'.format(user_id))

    def _handle_update_user_settings(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param['user_id']

        pmi_password = self._get_password(param.get('pmi_password'), param.get('gen_pmi_password'))
        waiting_room = param.get('waiting_room')
        req_password_sched = param.get('req_password_sched')
        req_password_inst = param.get('req_password_inst')
        req_password_pmi = param.get('req_password_pmi')

        if not(pmi_password or waiting_room != "None" or req_password_sched != "None" or req_password_inst != "None"):
            return action_result.set_status(phantom.APP_ERROR, 'No settings were selected for update')

        data = {}

        if pmi_password or req_password_sched != 'None' or req_password_inst != 'None' or req_password_pmi != 'None':
            data['schedule_meeting'] = {}
            if pmi_password:
                data['schedule_meeting']['pmi_password'] = pmi_password
            if req_password_sched:
                data['schedule_meeting']['require_password_for_scheduling_new_meetings'] = req_password_sched == 'True'
            if req_password_inst:
                data['schedule_meeting']['require_password_for_instant_meetings'] = req_password_inst == 'True'
            if req_password_pmi:
                data['schedule_meeting']['require_password_for_pmi_meetings'] = ('all' if req_password_pmi == 'True' else 'none')
        if waiting_room != 'None':
            data['in_meeting'] = {'waiting_room': waiting_room == 'True'}

        ret_val, _ = self._make_rest_call('/users/{}/settings'.format(user_id), action_result, json=data, headers=None, method="patch")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({
            'pmi_password': ('Not Updated' if not(pmi_password) else pmi_password),
            'waiting_room': ('Not Updated' if waiting_room == 'None' else waiting_room),
            'require_password_for_instant_meetings': ('Not Updated' if req_password_inst == 'None' else req_password_inst),
            'require_password_for_scheduling_new_meetings': ('Not Updated' if req_password_sched == 'None' else req_password_sched),
            'require_password_for_personal_meeting_instance': ('Not Updated' if req_password_pmi == 'None' else req_password_pmi)
        })

        return action_result.set_status(phantom.APP_SUCCESS, 'User {} successfully updated'.format(user_id))

    def _handle_delete_meeting(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        meeting_id = param['meeting_id']

        ret_val, _ = self._make_rest_call('/meetings/{}'.format(meeting_id), action_result, headers=None, method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({
            'meeting_deleted': True,
        })

        return action_result.set_status(phantom.APP_SUCCESS, 'Meeting {} successfully deleted'.format(meeting_id))

    def _get_password(self, password, pass_gen):
        if pass_gen:
            pwgen = PasswordGenerator()
            pwgen.maxlen = 10
            return pwgen.generate()
        else:
            return password

    def _handle_update_meeting(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        meeting_id = param['meeting_id']
        password = self._get_password(param.get('password'), param.get('gen_password'))
        waiting_room = param.get('waiting_room')

        if not(password or waiting_room != "None"):
            return action_result.set_status(phantom.APP_ERROR, 'Either password or waiting room must be updated')

        data = {}

        if password:
            data['password'] = password
        if waiting_room != "None":
            data['settings'] = {'waiting_room': (waiting_room == 'True')}

        ret_val, _ = self._make_rest_call('/meetings/{}'.format(meeting_id), action_result, json=data, headers=None, method="patch")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({
            'meeting_updated': True,
            'password': password,
            'waiting_room': ('Not Updated' if waiting_room == 'None' else waiting_room)
        })

        return action_result.set_status(phantom.APP_SUCCESS, 'Meeting {} successfully updated'.format(meeting_id))

    def _handle_get_meeting_invite(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        meeting_id = param['meeting_id']

        ret_val, response = self._make_rest_call('/meetings/{}/invitation'.format(meeting_id), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        parsed_fields = {}

        try:
            for kv_pair in UnicodeDammit(response.get('invitation', '')).unicode_markup.replace('Join Zoom Meeting\r\n', 'invitation_link:').split('\r\n'):
                if kv_pair:
                    parts = kv_pair.split(':')
                    second_part = ':'.join(parts[1:]).strip()
                    if second_part:
                        parsed_fields[parts[0].lower().replace(' ', '_')] = second_part

            if parsed_fields.get('meeting_id'):
                parsed_fields['meeting_id'] = parsed_fields['meeting_id'].replace(' ', '')

        except Exception as err:
            err_msg = self._get_error_message_from_exception(err)
            self.debug_print("Error: {}".format(err_msg))
            self.save_progress('Could not parse invitation fields')

        response['parsed_fields'] = parsed_fields

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, 'Meeting invitation for id {} successfully retrieved'.format(meeting_id))

    def _handle_get_user(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        user_id = param['user_id']

        ret_val, response = self._make_rest_call('/users/{}'.format(user_id), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, 'User information for id {} successfully retrieved'.format(user_id))

    def _handle_get_meeting(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        meeting_id = param['meeting_id']

        ret_val, response = self._make_rest_call('/meetings/{}'.format(meeting_id), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, 'Meeting information for id {} successfully retrieved'.format(meeting_id))

    def _get_jwt(self, config):
        payload = {
            'iss': config['api_key'],
            'exp': datetime.now() + timedelta(hours=8)
        }

        token = jwt.encode(payload, config['api_secret'])

        return token

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id: {}".format(self.get_action_identifier()))

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_user':
            ret_val = self._handle_get_user(param)

        elif action_id == 'get_meeting':
            ret_val = self._handle_get_meeting(param)

        elif action_id == 'get_meeting_invitation':
            ret_val = self._handle_get_meeting_invite(param)

        elif action_id == 'update_meeting':
            ret_val = self._handle_update_meeting(param)

        elif action_id == 'delete_meeting':
            ret_val = self._handle_delete_meeting(param)

        elif action_id == 'get_user_settings':
            ret_val = self._handle_get_user_settings(param)

        elif action_id == 'update_user_settings':
            ret_val = self._handle_update_user_settings(param)

        return ret_val

    def initialize(self):

        # Load the state
        self._state = self.load_state()

        # Get the asset config
        config = self.get_config()

        self._base_url = config['base_url'].rstrip("/")

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
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
            login_url = ZoomConnector._get_phantom_base_url() + '/login'

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

        connector = ZoomConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
