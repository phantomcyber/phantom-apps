# File: anyrun_connector.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.rules as ph_rules
try:
    from urllib.parse import unquote
except:
    from urllib import unquote
from anyrun_consts import *
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AnyrunConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AnyrunConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
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
                    error_code = ANYRUN_ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ANYRUN_ERR_CODE_MSG
                error_msg = ANYRUN_ERR_MSG_UNAVAILABLE
        except:
            error_code = ANYRUN_ERR_CODE_MSG
            error_msg = ANYRUN_ERR_MSG_UNAVAILABLE

        try:
            if error_code in ANYRUN_ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(
                    error_code, error_msg)
        except:
            self.debug_print(ANYRUN_PARSE_ERR_MSG)
            error_text = ANYRUN_PARSE_ERR_MSG

        return error_text

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Status Code: {}. Empty response, no information in header".format(response.status_code)
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(
                        err)
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        error_msg = resp_json.get('message', 'Unknown error')

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            error_msg
        )

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
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = "{}{}".format(self._base_url, endpoint)

        try:
            r = request_func(
                url,
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except requests.exceptions.ConnectionError:
            err = "Error connecting to server. Connection Refused from the Server for %s" % (url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, err), resp_json)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(
                        err)
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(
            ANYRUN_TEST_CONNECTIVITY_ENDPOINT, action_result, params=None, headers=self._headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param['id']

        # make rest call
        ret_val, response = self._make_rest_call(
            ANYRUN_GET_REPORT_ENDPOINT.format(taskid=id), action_result, params=None, headers=self._headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        self.save_progress("Successfully fetched report for {}".format(id))
        try:
            action_result.add_data(response['data'])
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(err))

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully fetched report for {}".format(id))

    def _handle_detonate_file(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_id = param['vault_id']

        try:
            success, message, vault_meta_info = ph_rules.vault_info(vault_id=vault_id)
            vault_meta_info = list(vault_meta_info)
            if not success or not vault_meta_info:
                error_msg = " Error Details: {}".format(unquote(message)) if message else ''
                return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(ANYRUN_ERR_UNABLE_TO_FETCH_FILE.format(key="vault meta info"), error_msg))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "{}. {}".format(ANYRUN_ERR_UNABLE_TO_FETCH_FILE.format(key="vault meta info"), err))

        try:
            # phantom vault file path
            file_path = vault_meta_info[0].get('path')
            if not file_path:
                return action_result.set_status(phantom.APP_ERROR, ANYRUN_ERR_UNABLE_TO_FETCH_FILE.format(key="path"))
        except:
            return action_result.set_status(phantom.APP_ERROR, ANYRUN_ERR_UNABLE_TO_FETCH_FILE.format(key="path"))

        self.save_progress("Detonating file {}".format(file_path))
        files = [
            ('file', open(file_path, 'rb'))
        ]

        # make rest call
        ret_val, response = self._make_rest_call(
            ANYRUN_DETONATE_FILE_ENDPOINT, action_result, method="post", files=files, headers=self._headers
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        self.save_progress("Successfully detonated file")
        try:
            action_result.add_data(response['data'])
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing response from server. {}".format(err))

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully detonated file")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id: {}".format(self.get_action_identifier()))

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_report':
            ret_val = self._handle_get_report(param)

        elif action_id == 'detonate_file':
            ret_val = self._handle_detonate_file(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config['base_url']
        self._api_key = config['API_key']
        self._headers = {
            'Authorization': 'API-Key {}'.format(self._api_key)
        }
        # Security check on URL format
        if not self._base_url.endswith('/'):
            self._base_url += "/"

        return phantom.APP_SUCCESS

    def finalize(self):
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
            login_url = AnyrunConnector._get_phantom_base_url() + '/login'

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
            r2 = requests.post(login_url, verify=False,
                               data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AnyrunConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
