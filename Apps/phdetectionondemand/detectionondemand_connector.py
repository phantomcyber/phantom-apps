# !/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.vault import Vault
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from detectionondemand_consts import *
import requests
import time
import json
import sys
from bs4 import BeautifulSoup, UnicodeDammit


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class DetectionOnDemandConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(DetectionOnDemandConnector, self).__init__()

        self._state = None
        self._base_url = None
        self._api_token = None

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in the {}".format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in the {}".format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-negative integer value in the {}".format(key)), None

        return phantom.APP_SUCCESS, parameter

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
                    error_code = ERROR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERROR_CODE_MSG
                error_msg = ERROR_MSG_UNAVAILABLE
        except:
            error_code = ERROR_CODE_MSG
            error_msg = ERROR_MSG_UNAVAILABLE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERR_MSG
        except:
            error_msg = ERROR_MSG_UNAVAILABLE

        try:
            if error_code in ERROR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing error message")
            error_text = PARSE_ERR_MSG

        return error_text

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Status Code: {0}. Empty response and no information in the header".format(response.status_code)
            ), None
        )

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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            action_result.set_status(phantom.APP_ERROR, 'Unable to parse JSON response: {}'.format(err))

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
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
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            action_result.set_status(phantom.APP_ERROR, 'Error Connecting to server: {}'.format(err))

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Checking connectivity by fetching API health")
        # make rest call
        ret_val, response = self._make_rest_call(
            DOD_HEALTH_ENDPOINT, action_result, params=None, headers={DOD_API_AUTH_HEADER: self._api_token}
        )

        if not phantom.is_fail(ret_val) and response['status'] == 'success' and response['service_status'] == 'RUNNING':
            # Return success
            self.save_progress("Test Connectivity Passed")
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

    def _handle_detonate_file(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        vault_id = param['vault_id']
        password = param.get('password', None)
        command_param = param.get('param', None)

        try:
            file_info = Vault.get_file_info(vault_id=vault_id)[0]
            file_path = file_info['path']
            file_name = file_info['name']
        except:
            return action_result.set_status(phantom.APP_ERROR, "Unable to find vault item")

        try:
            files = {
                "file": (file_name, open(file_path, 'rb'))
            }
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            action_result.set_status(phantom.APP_ERROR, '{}'.format(err))

        data = {}
        if password:
            data['password'] = password
        if command_param:
            data['param'] = command_param
        # make rest call
        ret_val, response = self._make_rest_call(
            DOD_FILES_ENDPOINT, action_result, method="post", files=files, data=data, headers={DOD_API_AUTH_HEADER: self._api_token}
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_url(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Format the url as a stringly typed array: ex. ["https://www.test.com"]
        urls = {
            'urls': f'["{param["url"]}"]'
        }

        # make rest call
        ret_val, response = self._make_rest_call(
            '/urls', action_result, method="post", files=urls, data=None, headers={DOD_API_AUTH_HEADER: self._api_token}
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_hash(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        md5_hash = param['md5_hash']

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        hash_ret_val, hash_response = self._make_rest_call(
            f'{DOD_HASHES_ENDPOINT}/{md5_hash}', action_result, params={}, headers={DOD_API_AUTH_HEADER: self._api_token}
        )

        if phantom.is_fail(hash_ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(hash_response)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary["is_malicious"] = hash_response["is_malicious"]

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):
        attempt = 1

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        report_id = param['report_id']
        # Integer Validation for 'presigned_url_expiry' parameter
        expiry = param['presigned_url_expiry']
        ret_val, expiry = self._validate_integer(action_result, expiry, PRESIGNED_URL_EXPIRY_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Integer Validation for 'poll_attempts' parameter
        poll_attempts = param['poll_attempts']
        ret_val, poll_attempts = self._validate_integer(action_result, poll_attempts, POLL_ATTEMPTS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Integer Validation for 'poll_interval' parameter
        poll_interval = param['poll_interval']
        ret_val, poll_interval = self._validate_integer(action_result, poll_interval, POLL_INTERVAL_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        while attempt <= poll_attempts:
            self.save_progress(f'Polling attempt {attempt} of {poll_attempts}')
            report_ret_val, report_response = self._make_rest_call(
                f'{DOD_REPORTS_ENDPOINT}/{report_id}', action_result, params={'extended': True}, headers={DOD_API_AUTH_HEADER: self._api_token}
            )
            if phantom.is_fail(report_ret_val):
                return report_ret_val
            self.debug_print(report_response)
            if report_response.get('overall_status') == "DONE":
                url_ret_val, url_response = self._make_rest_call(
                    f'{DOD_PRESIGNED_URL_ENDPOINT}/{report_id}', action_result, params={'expiry': expiry}, headers={DOD_API_AUTH_HEADER: self._api_token}
                )
                if phantom.is_fail(url_ret_val):
                    self.debug_print(url_response)
                    url_response = {'error': 'Unable to fetch presigned URL'}
                else:
                    summary = action_result.update_summary({})
                    summary["dashboard"] = url_response["presigned_report_url"]

                action_result.add_data({**report_response, **url_response})
                return action_result.set_status(phantom.APP_SUCCESS)

            attempt += 1
            time.sleep(poll_interval)

        return action_result.set_status(phantom.APP_ERROR, "Maximum report polls reached")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'detonate_file':
            ret_val = self._handle_detonate_file(param)

        elif action_id == 'detonate_url':
            ret_val = self._handle_detonate_url(param)

        elif action_id == 'get_report':
            ret_val = self._handle_get_report(param)

        elif action_id == 'lookup_hash':
            ret_val = self._handle_lookup_hash(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')
        self._api_token = config.get('api_token')

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
            login_url = DetectionOnDemandConnector._get_phantom_base_url() + '/login'

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

        connector = DetectionOnDemandConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
