# File: urlhaus_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from urlhaus_consts import *

import requests
import json
from bs4 import BeautifulSoup, UnicodeDammit
import sys


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class UrlhausConnector(BaseConnector):

    def __init__(self):

        super(UrlhausConnector, self).__init__()

        self._state = None
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Status Code: {0}. Error: Empty response and no information in the header".format(response.status_code)
            ), None
        )

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

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

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        """ This function is used to process json response.

        :param r: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}"
                                         .format(self._get_error_message_from_exception(e))), None)

        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        """ This function is used to process html response.

        :param r: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        if not r.text:
            return self._process_empty_response(r, action_result)

        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}'))
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except Exception:
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
                error_text = error_msg
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing error message")
            error_text = PARSE_ERR_MSG

        return error_text

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
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. {0}".format(self._get_error_message_from_exception(e))), resp_json)
        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")
        ret_val, _ = self._make_rest_call(
            '/urls/recent/limit/1', action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_url(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url = param['url']
        data = {}
        data['url'] = url

        ret_val, response = self._make_rest_call(
            '/url', action_result, params=None, headers=None, method="post", data=data)

        if phantom.is_fail(ret_val):
            self.save_progress("Failed to contact URLhaus")
            return action_result.get_status()

        action_result.add_data(response)

        try:
            summary = action_result.update_summary({})
            if response['query_status'] == "no_results":
                summary['message'] = "No results found for: {0}".format(url)
            elif response['query_status'] == "ok":
                summary['date_added'] = response['date_added']
                payload_count = len(response['payloads'])
                summary['payload_count'] = payload_count
                summary['message'] = "URL {0} observed dropping {1} payloads".format(
                    url, payload_count)
            summary['query_status'] = response['query_status']
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']
        data = {}
        data['host'] = ip

        ret_val, response = self._make_rest_call(
            '/host', action_result, params=None, headers=None, method="post", data=data)

        if phantom.is_fail(ret_val):
            self.save_progress("Failed to contact URLhaus")
            return action_result.get_status()

        action_result.add_data(response)

        try:
            summary = action_result.update_summary({})
            if response['query_status'] == "no_results":
                summary['message'] = "No results found for: {0}".format(ip)
            elif response['query_status'] == "ok":
                summary['firstseen'] = response['firstseen']
                url_count = len(response['urls'])
                summary['url_count'] = url_count
                summary['message'] = "IP {0} observed serving {1} URLs".format(ip, url_count)
            summary['query_status'] = response['query_status']
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_domain(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']
        data = {}
        data['host'] = domain

        ret_val, response = self._make_rest_call(
            '/host', action_result, params=None, headers=None, method="post", data=data)

        if phantom.is_fail(ret_val):
            self.save_progress("Failed to contact URLhaus")
            return action_result.get_status()

        action_result.add_data(response)

        try:
            summary = action_result.update_summary({})
            if response['query_status'] == "no_results":
                summary['message'] = "No results found for: {0}".format(domain)
            elif response['query_status'] == "ok":
                summary['firstseen'] = response['firstseen']
                url_count = len(response['urls'])
                summary['url_count'] = url_count
                summary['message'] = "Domain {0}  observed serving {1} URLs".format(domain, url_count)
            summary['query_status'] = response['query_status']
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_hash(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        file_hash = param['file_hash']
        data = {}
        if len(file_hash) == 64:
            data['sha256_hash'] = file_hash
        elif len(file_hash) == 32:
            data['md5_hash'] = file_hash
        else:
            return action_result.set_status(
                phantom.APP_ERROR, "File Hash length not supported. Please verify hash is sha256 (64 char) or md5 (32)")

        ret_val, response = self._make_rest_call(
            '/payload', action_result, params=None, headers=None, method="post", data=data)

        if phantom.is_fail(ret_val):
            self.save_progress("Failed to contact URLhaus")
            return action_result.get_status()

        action_result.add_data(response)

        try:
            summary = action_result.update_summary({})
            if response['query_status'] == "no_results":
                summary['message'] = "No results found for: {0}".format(file_hash)
            elif response['query_status'] == "ok":
                summary['firstseen'] = response['firstseen']
                url_count = len(response['urls'])
                summary['url_count'] = url_count
                signature = response['signature']
                summary['message'] = "File Hash {0} observed being served by {1} URLs. Possible signature {2}".format(
                    file_hash, url_count, signature)
            summary['query_status'] = response['query_status']
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'lookup_url':
            ret_val = self._handle_lookup_url(param)

        elif action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)

        elif action_id == 'lookup_domain':
            ret_val = self._handle_lookup_domain(param)

        elif action_id == 'lookup_hash':
            ret_val = self._handle_lookup_hash(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config.get('base_url')
        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

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
            login_url = UrlhausConnector._get_phantom_base_url() + '/login'

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

        connector = UrlhausConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
