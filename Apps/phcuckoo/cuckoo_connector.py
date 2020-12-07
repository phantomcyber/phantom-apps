# --
# File: cuckoo_connector.py
#
# Copyright (c) 2014-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

from cuckoo_consts import *
import math
import time
import json
import requests
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class CuckooConnector(BaseConnector):

    def __init__(self):
        # Call the BaseConnectors init first
        super(CuckooConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        config = self.get_config()
        self._state = self.load_state()

        self._host = config.get('server')
        self._port = config.get('port')
        self._use_https = config.get('use_https', False)
        self._append_uri = config.get('append_uri', '')
        self._web_ui_base_url = config.get('web_ui_base_url')
        self._verify_server_cert = config.get('verify_server_cert', False)
        self._base_url = '{scheme}://{host}:{port}{append_uri}'.format(
            scheme='https' if self._use_https else 'http',
            host=self._host,
            port=self._port,
            append_uri=self._append_uri
        )
        self._base_url = self._base_url.rstrip("/")
        self.save_progress("Base URL: {}".format(self._base_url))

        self._cuckoo_timeout = config.get('timeout', 60)
        # Validate 'timeout' configuration parameter
        ret_val, self._cuckoo_timeout = self._validate_integer(self, self._cuckoo_timeout, TIMEOUT_KEY)
        if phantom.is_fail(ret_val):
            return self.get_status()

        self.username = config.get('username')
        self.password = config.get('password')
        self._auth = None
        if self.username and self.password:
            self._auth = (self.username, self.password)
        self._version = None

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(key=key)), None

        return phantom.APP_SUCCESS, parameter

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

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Status code: {0}. Empty response and no information in the header".format(response.status_code)), None)

    def _process_html_response(self, response, action_result):

        if response.status_code == 200:
            # Let's actually try to parse it as a json first...
            ret_val, response = self._process_json_response(response, action_result)
            if not phantom.is_fail(ret_val):
                return RetVal(ret_val, response)

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
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. {0}".format(err)), None)

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

        # Process an HTML resonse, Do this no matter what the api talks.
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
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, json=None, files=None, method="get"):

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = "{0}{1}".format(self._base_url, endpoint)

        print("auth", self._auth, "headers", headers, "data", data, "json", json, "files", files)
        try:
            r = request_func(
                url,
                auth=self._auth,
                data=data,
                json=json,
                headers=headers,
                verify=self._verify_server_cert,
                params=params,
                files=files
            )
        except requests.exceptions.InvalidURL:
            error_message = "Error connecting to server. Invalid URL: %s" % (url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.InvalidSchema:
            error_message = "Error connecting to server. No connection adapters were found for %s" % (url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.ConnectionError:
            error_message = "Error connecting to server. Connection Refused from the Server for %s" % (url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(err)), resp_json)

        print("request", r.request.headers)
        print("response", r.text)

        return self._process_response(r, action_result)

    def _check_version(self, action_result):
        self.save_progress("Checking Cuckoo Version")
        ret_val, response = self._make_rest_call('/cuckoo/status', action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        try:
            version = response['version']
        except KeyError:
            return action_result.set_status(
                phantom.APP_ERROR, "Error retrieving version information"
            )

        self._version = version
        self.save_progress("Using Version: {}".format(version))
        return phantom.APP_SUCCESS

    def _queue_analysis(self, action_result, object_type, **kwargs):
        ret_val, response = self._make_rest_call(
            '/tasks/create/{}'.format(object_type),
            action_result,
            method="post",
            **kwargs
        )
        if phantom.is_fail(ret_val):
            return ret_val, None

        task_ids = response.get('task_ids')
        if type(task_ids) == list:
            if len(task_ids) > 0:
                return phantom.APP_SUCCESS, task_ids
            
            else:
                return action_result.set_status(phantom.APP_ERROR, "Retrieved zero length task id list"), []

        try:
            return phantom.APP_SUCCESS, response['task_id']
        except KeyError:
            return action_result.set_status(
                phantom.APP_ERROR, "Unable to retrieve 'task id'"
            ), None

    def _poll_for_task(self, action_result, task_id, key=""):
        max_count = int(math.ceil(self._cuckoo_timeout / POLL_SLEEP_SECS))

        result_data = {}

        summary = action_result.update_summary({})
        summary[TARGET_KEY] = key
        summary[TASK_ID_KEY] = task_id
        if self._web_ui_base_url:
            summary[RESULTS_URL_KEY] = '{}/analysis/{}'.format(self._web_ui_base_url.rstrip('/'), task_id)

        count = 1
        while count <= max_count:
            self.save_progress("Polling for task: Attempt {0} of {1}".format(count, max_count))
            ret_val, response = self._make_rest_call('/tasks/view/{}'.format(task_id), action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                result_data[RESULT_STATUS_KEY] = response[RESPONSE_TASK_KEY]
            except KeyError:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching 'task status'")
            try:
                status = response[RESPONSE_TASK_KEY][RESPONSE_STATUS_KEY]
            except KeyError:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching 'status'")

            if status in CUCKOO_POLL_STATES:
                count += 1
                time.sleep(POLL_SLEEP_SECS)
            elif status in CUCKOO_DONE_STATES:
                ret_val, response = self._make_rest_call('/tasks/report/{}'.format(task_id), action_result)
                if phantom.is_fail(ret_val):
                    return action_result.get_status()
                result_data[RESULT_REPORT_KEY] = response
                action_result.add_data(result_data)
                return action_result.set_status(phantom.APP_SUCCESS)
        # Timed out
        action_result.add_data(result_data)
        return action_result.set_status(phantom.APP_SUCCESS, "Polling timed out, continue with get report")

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_version(action_result)
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_version(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        vault_id = param['vault_id']
        file_name = param.get('file_name')
        dozip = param.get("zip_and_encrypt")
        zip_password = param.get( "zip_password") or "infected"

        vault_info = Vault.get_file_info(vault_id=vault_id)
        if not vault_info:
            return action_result.set_status(
                phantom.APP_ERROR, "Invalid Vault ID"
            )

        try:
            file_info = vault_info[0]
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting 'File Info'. {}".format(err))

        try:
            file_path = file_info['path']
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting 'File Path'")

        if not file_name:
            try:
                file_name = file_info['name']
            except KeyError:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting 'File Name'")

        try:
            payload = open(file_path, 'rb')
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error opening file. {}".format(err))

        if dozip:
            try:
                import zip_and_encrypt as z
                zae = z.zip_and_encrypt("/tmp/phcuckoo_app_", zip_password)
                zae.add(file_path)
                payload = zae.archive_fp

            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, f"Error: {e}")

        files = {
            'file': (file_name, payload)
        }

        ret_val, task_id = self._queue_analysis(action_result, "file", files=files)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return self._poll_for_task(action_result, task_id, key=file_name)

    def _handle_detonate_url(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_version(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        url = param['url']

        data = {
            'url': url
        }

        ret_val, task_id = self._queue_analysis(action_result, 'url', data=data)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return self._poll_for_task(action_result, task_id, key=url)

    def _handle_submit_strings(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_version(action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        strings = "\n".join(map(lambda x:x.strip(), param['hash'].split()))
        strings = "\n".join(map(lambda x:x.strip(), strings.split(",")))
        strings = list(map(lambda x:x.strip(), strings.split("\n")))
        
        if len(strings) == 0:
            return action_result.set_status(phantom.APP_ERROR, "Empty hash parameter")

        if len(strings[0]) == 0:
            return action_result.set_status(phantom.APP_ERROR, "Empty hash parameter")

        files = { 'strings': (None, strings[0]) }
        ret_val, task_ids = self._queue_analysis(action_result, 'submit', files=files)
        if phantom.is_fail(ret_val):
            return ret_val
        return self._poll_for_task(action_result, task_ids[0], key=strings[0])

        """
        summary = {}
        action_ret_val = phantom.APP_ERROR
        for x in strings:
            files = { 'strings': (None, x) }
            ret_val, task_ids = self._queue_analysis(action_result, 'submit', files=files)
            if phantom.is_fail(ret_val):
                continue
            action_ret_val = phantom.APP_SUCCESS
            self._poll_for_task(action_result, task_ids[0], key=x)
            summary.update({str(task_ids[0]): x})

        action_result.set_summary(summary)
        return action_result.set_status(action_ret_val)
        """

    def _handle_get_report(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = self._check_version(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        task_id = param['id']
        return self._poll_for_task(action_result, task_id)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'detonate_file':
            ret_val = self._handle_detonate_file(param)

        elif action_id == 'get_report':
            ret_val = self._handle_get_report(param)

        elif action_id == 'detonate_url':
            ret_val = self._handle_detonate_url(param)

        elif action_id == 'submit_strings':
            ret_val = self._handle_submit_strings(param)

        return ret_val


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
            login_url = BaseConnector._get_phantom_base_url() + "/login"
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
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CuckooConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
