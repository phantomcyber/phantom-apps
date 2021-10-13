# File: minemeld_connector.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Usage of the consts file is recommended
# from minemeld_consts import *
import requests
import json
from bs4 import BeautifulSoup
import subprocess
import os
import tempfile
from minemeld_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class MinemeldConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(MinemeldConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

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
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            # auth=(username, password),  # basic authentication
                            verify=config.get('verify_server_cert', False),
                            **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        config = self.get_config()

        endpoint = config['endpoint']
        username = config['username']
        password = config['password']

        dir_path = os.path.dirname(os.path.realpath(__file__))
        script_abs_name = "{}/minemeld-sync.py".format(dir_path)  # /opt/phantom/bin/phenv python2.7 ..

        tmp_indicator = "/tmp/minemeldtemp"
        if not os.path.exists(tmp_indicator):
                stream = os.popen('echo 8.8.8.8 > {}; cat {}'.format(tmp_indicator, tmp_indicator))
                output = stream.read()
                self.save_progress("[-] output: {}".format(output))
        final_cmd = ("/opt/phantom/bin/phenv python2.7 {script_abs_name}"
                    " --dry-run -k -m {endpoint} -u {username} -p {password}"
                    " -t IPv4 wlWhiteListIPv4 {tmp_indicator}".format(
                        script_abs_name=script_abs_name,
                        endpoint=endpoint,
                        username=username,
                        password=password,
                        tmp_indicator=tmp_indicator
                    ))
        out = subprocess.Popen(final_cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        stdout, stderr = out.communicate()
        stdout = stdout.replace("WARNING:__main__:MineMeld cert verification disabled", "Cert Verify: 0")
        # Remove tmp file.
        # os.unlink(tmp_file_path.name)

        # Clean the Test Connectivity Output
        if "\n" in stdout and "module" in stdout:
            stdout = "{} {}".format(stdout.split("\n")[-1], stdout.split("\n")[-2])

        self.save_progress("\t [ - ] stdout: {}\n\t[ - ]stderr: {} ".format(stdout.replace('INFO', '[ - ]'), stderr))

        # Return success
        if "8.8.8.8 (add)" in stdout:
            self.save_progress(MINEMELD_SUCCESS_TEST_CONNECTIVITY)
        else:
            self.save_progress(MINEMELD_ERR_TEST_CONNECTIVITY)
            return action_result.set_status(phantom.APP_ERROR, MINEMELD_ERR_INVALID_CONFIG_PARAM)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_upload_file(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        config = self.get_config()

        endpoint = config['endpoint']
        username = config['username']
        password = config['password']

        vault_id = param['vault_id']

        # Find vault path  and info for given vault ID
        vault_path = Vault.get_file_path(vault_id)
        vault_info = Vault.get_file_info(vault_id)

        # check if vault path is accessible
        if not vault_path:
            return action_result.set_status(phantom.APP_ERROR, MINEMELD_VAULT_ID_NOT_FOUND)

        # check if vault info is accessible
        if not vault_info:
            return action_result.set_status(phantom.APP_ERROR, MINEMELD_VAULT_ID_NOT_FOUND)

        file_info = vault_info[0]
        file_name = file_info['path']

        # Optional values should use the .get() function
        node_name = param.get('node_name', 'wlWhiteListIPv4')
        file_type = param.get('file_type', 'IPv4')
        dry_run = param.get('dry_run', False)
        is_remove = param.get('is_remove', False)
        is_update = param.get('is_update', False)

        self.save_progress("[-] Path: {}".format(os.getcwd()))
        self.save_progress("vault id: {} - target node_name: {}  file_type: {}    dry_run: {}".format(vault_id, node_name, file_type, dry_run))

        # Command Constructor
        dir_path = os.path.dirname(os.path.realpath(__file__))
        script_abs_name = "{}/minemeld-sync.py".format(dir_path)  # /opt/phantom/bin/phenv python2.7 ..

        dry_run_arg = "--dry-run"
        remove_arg = "--delete"
        update_arg = "--update"
        base_cmd = ("/opt/phantom/bin/phenv python2.7 {script_abs_name}"
                    " -k -m {endpoint} -u {username} -p {password}"
                    " -t {file_type} {node_name} {input_file}".format(
                        script_abs_name=script_abs_name,
                        endpoint=endpoint,
                        username=username,
                        password=password,
                        file_type=file_type,
                        node_name=node_name,
                        input_file=file_name))

        final_cmd = base_cmd

        if dry_run:
            final_cmd = "{} {}".format(final_cmd, dry_run_arg)
        if is_remove:
            final_cmd = "{} {}".format(final_cmd, remove_arg)
        if is_update:
            final_cmd = "{} {}".format(final_cmd, update_arg)

        # self.save_progress("[-] final_cmd: {}".format(final_cmd))

        # make rest call
        # ret_val, response = self._make_rest_call('/endpoint', action_result, params=None, headers=None)
        out = subprocess.Popen(final_cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = out.communicate()

        self.save_progress("stdout: {} - stderr: {} ".format(stdout, stderr))

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(stdout)
        action_result.add_data(stderr)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_send_indicator(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly

        config = self.get_config()

        endpoint = config['endpoint']
        username = config['username']
        password = config['password']

        indicator = param['indicator']

        share_level = param.get('share_level')

        # Optional values should use the .get() function
        node_name = param.get('node_name', 'wlWhiteListIPv4')
        file_type = param.get('file_type', 'Automatic')
        dry_run = param.get('dry_run', False)

        # Newly added
        is_update = param.get('is_update', True)
        is_remove = param.get('is_remove', False)
        self.save_progress("[-] is_update: {}\tis_remove: {}".format(is_update, is_remove))

        dir_path = os.path.dirname(os.path.realpath(__file__))
        script_abs_name = "{}/minemeld-sync.py".format(dir_path)  # /opt/phantom/bin/phenv python2.7 ..
        self.save_progress("[-] script_abs_name: {}".format(script_abs_name))
        self.save_progress("[-] share_level: {}, Indicator: {} - \ttarget node_name: {}  \tfile_type: {}    \tdry_run: {}".format(
                share_level, indicator, node_name, file_type, dry_run))

        # Check if indicator is domain, IP, or Url
        if "Automatic" in file_type:
            self.save_progress("[-] Automatic")
            if "//" in indicator:
                file_type = "URL"
            elif indicator.count(".") is 3 and indicator[0].isdigit() is True and indicator[-1].isdigit() is True:
                file_type = "IPv4"
            elif "::" in indicator:
                file_type = "IPv6"
            else:
                file_type = "domain"

        self.save_progress("[-] file_type: {}".format(file_type))

        # Create a tmp file to store input parameter (IOC)
        if hasattr(Vault, 'get_vault_tmp_dir'):
            tmp_file_path = tempfile.NamedTemporaryFile(dir=Vault.get_vault_tmp_dir(), delete=False)
            input_file = tmp_file_path.name
        else:
            tmp_file_path = tempfile.NamedTemporaryFile(dir="/opt/phantom/vault/tmp/", delete=False)
            input_file = tmp_file_path.name

        self.save_progress("[-] tmp_file_path: {}".format(tmp_file_path.name))
        tmp_file_path.write(indicator)
        tmp_file_path.close()

        '''
        stream = os.popen('echo Test Returned output')
        output = stream.read()
        self.save_progress("[-] output: {}".format(output))
        '''
        # Command Constructor
        dry_run_arg = "--dry-run"
        remove_arg = "--delete"
        update_arg = "--update"
        base_cmd = ("/opt/phantom/bin/phenv python2.7 {script_abs_name}"
                    " -k -m {endpoint} -u {username} -p {password}"
                    " -t {file_type} {node_name} {input_file}"
                    " --share-level {share_level}".format(
                        script_abs_name=script_abs_name,
                        endpoint=endpoint,
                        username=username,
                        password=password,
                        file_type=file_type,
                        node_name=node_name,
                        input_file=input_file,
                        share_level=share_level))

        final_cmd = base_cmd

        if dry_run:
            final_cmd = "{} {}".format(final_cmd, dry_run_arg)
        if is_remove:
            final_cmd = "{} {}".format(final_cmd, remove_arg)
        if is_update:
            final_cmd = "{} {}".format(final_cmd, update_arg)

        # self.save_progress("[-] final_cmd: {}".format(final_cmd))

        # make process exec call
        out = subprocess.Popen(final_cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        # Now post process the data,  uncomment code as you deem fit
        stdout, stderr = out.communicate()
        stdout = stdout.replace("WARNING:__main__:MineMeld cert verification disabled", "Cert Verify: 0")
        self.save_progress("stdout: {} - stderr: {} ".format(stdout, stderr))

        # Remove tmp file.
        os.unlink(tmp_file_path.name)

        # Add the response into the data section
        action_result.add_data(stdout)
        action_result.add_data(stderr)

        if "Traceback" in stdout:
            return action_result.set_status(phantom.APP_ERROR, "Error from minemeld-sync.py - {}".format(stdout))

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'upload_file':
            ret_val = self._handle_upload_file(param)

        elif action_id == 'send_indicator':
            ret_val = self._handle_send_indicator(param)

        # TODO: Implement Action: 'list nodes' - Undocumented API Call: https://minemeld-host/status/minemeld

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

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
            login_url = MinemeldConnector._get_phantom_base_url() + '/login'

            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MinemeldConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
