# File: corelight_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
import requests
import json
import base64
import os
import uuid
import shutil
from bs4 import BeautifulSoup
from phantom.vault import Vault


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CorelightConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CorelightConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._username = None
        self._password = None
        self._local_dir = None

    def _process_empty_response(self, response, action_result):

        self.save_progress("Status: {0}".format(response.status_code))

        if response.status_code == 202:
             location = response.headers['location']
             self.save_progress("Location: {0}".format(location))
             output = {
                 'location': location
             }
             action_result.add_data(output)
             return RetVal(phantom.APP_SUCCESS, {})

        if response.status_code == 200:
            self.save_progress("Location: {0}".format(response))
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        if status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

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

        try:
            # Create a URL to connect to
            if ("https://" in endpoint):
                url = endpoint
            else:
                url = self._base_url + endpoint
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                            "Error while creating the endpoint for the action. Please check the asset configuration and action parameters. Error: {0}".format(str(e))), resp_json)

        try:
            r = request_func(
                            url,
                            auth=(self._user, self._password),
                            verify=config.get('verify_server_cert', False),
                            **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")
        ret_val, response = self._make_rest_call('/api/authinfo', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_intel(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ipCheck = param.get('ipaddress', '')
        name = "phantom_intel_corelight.dat"

        if (ipCheck):
            indicatorType = "Intel::ADDR"

        else:
            indicatorType = "Intel::DOMAIN"

        update = param['is_this_a_update']

        if (update):
            f = open("{0}/{1}".format(self._local_dir, name), "w")
            f.write("#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\n")
        else:
            ret_val = self._fetch_list_intel_framework(action_result)
            if ret_val is None:
                return action_result.get_status()
            f = open("{0}/phantom_intel_corelight.dat".format(self._local_dir), "a")

        ioc = param['ioc']
        source = param.get('meta_source', "Phantom")
        url = param.get('meta_url', "Phantom")
        desc = param.get('meta_desc', "Phantom")
        self.save_progress("Check IOC type: {0}".format(type(ioc)))
        islist = isinstance(ioc, list)
        isstr = isinstance(ioc, str)
        if (islist):
            for item in ioc:
                f.write(item + "\t" + indicatorType + "\t" + source + "\t" + desc + "\t" + url + "\n")
        elif (isstr):
            f.write(ioc + "\t" + indicatorType + "\t" + source + "\t" + desc + "\t" + url + "\n")

        # make rest call
        f.close()
        f = open("{0}/{1}".format(self._local_dir, name), "r")
        files = {'file': f}
        ret_val, response = self._make_rest_call('/api/bro/intel?dry-run=0', action_result, params=None, headers=None, method="put", files=files)
        f.close()
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_conf(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._make_rest_call('/api/configuration', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _fetch_list_intel_framework(self, action_result):
        ret_val, response = self._make_rest_call('/api/bro/intel', action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            return None

        if not response.get("file", {}).get("content"):
            action_result.set_status(phantom.APP_ERROR, "No intel framework data found")
            return None

        decode = base64.b64decode(response.get("file", {}).get("content"))
        response["file"]["content"] = decode
        f = open("{0}/phantom_intel_corelight.dat".format(self._local_dir), "w")
        f.write(response["file"]["content"])
        f.close()

        if (phantom.is_fail(ret_val)):
            return None

        return response

    def _handle_list_intel_framework(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        response = self._fetch_list_intel_framework(action_result)

        if response is None:
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_input_framework(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._make_rest_call('/api/bro/input', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_input_framework(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        append = param['append']
        name = param['name']
        input = param['input']

        if (append):
            f = open("{0}/{1}".format(self._local_dir, name), "w")
            f.write(input)
            files = {'file': f}
            ret_val, response = self._make_rest_call('/api/bro/inpu' + name, action_result, params=None, headers=None, method="put", files=files)
        else:
            f = open("{0}/{1}".format(self._local_dir, name), "w")
            fields = param.get('fields')
            f.write(fields + "\n")
            f.write(input)
            files = {'file': f}
            ret_val, response = self._make_rest_call('/api/bro/inpu' + name, action_result, params=None, headers=None, method="post", files=files)

        f.close()

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_backup_corelight(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        bundlePassword = param['bundle_password']
        uri = '/api/provision/bundle?bundle-password=' + bundlePassword + '&no-sensitive=0&type=backup'
        ret_val, response = self._make_rest_call(uri, action_result, params=None, headers=None)

        try:
            fileName = param['backup_name']
            file_path = "{0}/{1}".format(self._local_dir, fileName)
            output = json.dumps(response)
            with open(file_path, 'wb') as f:
                f.write(output)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to write to a temporary file in the folder {0}".format(self._local_dir), e)

        vault_ret_dict = Vault.add_attachment(file_path, self.get_container_id(), file_name=fileName)
        curr_data = {}
        if (vault_ret_dict['succeeded']):
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
            curr_data[phantom.APP_JSON_NAME] = fileName
            action_result.add_data(curr_data)
            wanted_keys = [phantom.APP_JSON_VAULT_ID, phantom.APP_JSON_NAME]
            summary = {x: curr_data[x] for x in wanted_keys}
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_restore_corelight(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        vault_info = Vault.get_file_info(vault_id=param.get('vault_id'))

        data_string = None

        for item in vault_info:
            vault_path = item.get('path')
            if vault_path is None:
                return action_result.set_status(phantom.APP_ERROR, "Could not find a path associated with the provided vault ID")

            try:
                vault_file = open(vault_path)
                data_string = vault_file.read()
                # data = json.loads(data_string)
                # self.save_progress("restore: {0}".format(data_string))
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Unable to open vault file: " + str(e))

        bundlePassword = param['bundle_password']
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "corelight-client v1.5.4",
            "Accept": "application/json"
        }
        uri = "/api/provision/bundle?bundle-password=" + bundlePassword + "&dry-run=0"
        ret_val, response = self._make_rest_call(uri, action_result, params=None, headers=headers, method="put", data=data_string)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_check_results(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        location = param['location']
        ret_val, response = self._make_rest_call(location, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'ip_intel':
            ret_val = self._handle_ip_intel(param)

        elif action_id == 'get_conf':
            ret_val = self._handle_get_conf(param)

        elif action_id == 'list_intel_framework':
            ret_val = self._handle_list_intel_framework(param)

        elif action_id == 'list_input_framework':
            ret_val = self._handle_list_input_framework(param)

        elif action_id == 'input_framework':
            ret_val = self._handle_input_framework(param)

        elif action_id == 'backup_corelight':
            ret_val = self._handle_backup_corelight(param)

        elif action_id == 'restore_corelight':
            ret_val = self._handle_restore_corelight(param)

        elif action_id == 'check_results':
            ret_val = self._handle_check_results(param)

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
        self._user = config.get('user')
        self._password = config.get('password')

        if self.get_action_identifier() in ['ip_intel', 'list_intel_framework', 'input_framework', 'backup_corelight']:
            if hasattr(Vault, 'get_vault_tmp_dir'):
                temp_dir = Vault.get_vault_tmp_dir()
            else:
                temp_dir = 'opt/phantom/vault/tmp'
            guid = uuid.uuid4()
            self._local_dir = temp_dir + '/{}'.format(guid)

            try:
                os.makedirs(self._local_dir)
            except Exception as e:
                return self.set_status(phantom.APP_ERROR, "Unable to create the temporary directory {0}".format(self._local_dir), e)

        return phantom.APP_SUCCESS

    def finalize(self):

        # remove the /tmp/<> temporary directory
        shutil.rmtree(self._local_dir)

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
            login_url = CorelightConnector._get_phantom_base_url() + '/login'

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

        connector = CorelightConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
