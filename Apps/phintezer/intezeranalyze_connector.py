# File: intezeranalyze_connector.py
#
# Copyright (c) 2019 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.rules as rules


# Usage of the consts file is recommended
# from intezeranalyze_consts import *
import requests
import json
from bs4 import BeautifulSoup
import time
import os


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class IntezerAnalyzeConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(IntezerAnalyzeConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_reponse(self, response, action_result):

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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text.encode("utf-8"))

        message = message.replace('{', '{{').replace('}', '}}')

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
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", json_var=None, files=None):

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
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params,
                            json=json_var,
                            files=files)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def check_file(self, file, action_result):
        # Check if the file exists first
        if os.path.exists(file):
            # Check if the file is an approved format
            if os.path.getsize(file) / 1024 / 1024 < 19:
                return True
            else:
                message = "File is over 20mb: {}".format(file)
                return action_result.set_status(phantom.APP_ERROR, status_message=message)
            self.save_progress("File checked successfully")
        else:
            message = "File does not exist"
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Place api key in own self variable.
        endpoint = 'is-available'

        # Make connection to the Intezer Analyze endpoint
        ret_val, response = self._make_rest_call(endpoint, action_result)

        # Connect to Phantom Endpoint
        self.save_progress("Connecting to Intezer Analyze test endpoint")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            message = "Test Connectivity Failed for Intezer Analyze.  Message: {}, Response Code: {}".format(response, ret_val)
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_file(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Place vault id in in its own variable.
        vault_id_str = param['vault_id']

        try:
            success, message, info = rules.vault_info(vault_id=vault_id_str)
            info = json.loads(json.dumps(info[0]))
            filepath = info['path']
        except:
            return action_result.set_status(phantom.APP_ERROR, 'File not found in vault: {}'.format(vault_id_str))

        # Issue request to Intezer Analyze
        endpoint = 'v1-2/analyze'

        # Parameters to send to Intezer
        params = {
            'api_key': api_key
        }

        # Perform file check
        file_check = self.check_file(str(filepath), action_result)

        str_vault_dict = str(filepath)
        # Check file type is correct
        if file_check:
            file_list = {'file': open(str_vault_dict, 'rb')}
            self.save_progress("File has been found. Location is: {}".format(str_vault_dict))

        # Make connection to the Intezer Analyze endpoint
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", data=params, files=file_list)

        if (phantom.is_fail(ret_val)):
            # so just return from here
            # the call to the 3rd party device or service failed, action result should contain all the error details
            message = "Failed request to detonate file endpoint. Message: {}, Response: {}".format(response, ret_val)
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        if response['analysis_id']:
            self.save_progress("File has been posted to Intezer Analyze successfully")

            # Pass Analysis ID to Intezer Analyze
            analysis_id = response['analysis_id']

            # Create new request to the endpoint that holds the reports
            endpoint = 'v1-2/analyses/{}'.format(analysis_id)

            # Make connection to the Intezer Report Endpoint
            ret_val, response = self._make_rest_call(endpoint, action_result, json_var=params, method="post")

            # If the response is a failure
            if (phantom.is_fail(ret_val)):
                    message = "Failed retrieving analysis id from output. Message: {}".format(response)
                    return action_result.set_status(phantom.APP_ERROR, status_message=message)
            # Report is Queued or In Progress
            i = 0
            # While the result is not succeeded or 50 seconds has not elapsed
            while i < 10 and response['status'] != 'succeeded':
                self.save_progress("Sleeping 60 seconds while report is being fetched")
                # Sleep 60 seconds
                time.sleep(60)
                # Make connection to the Intezer Report Endpoint
                ret_val, response = self._make_rest_call(endpoint, action_result, json_var=params, method="post")
                # Increment the timeout counter
                i += 1
                # If we reach 10 minutes and the analysis has not returned
                if i == 10:
                    return action_result.set_status(phantom.APP_ERROR, status_message="Timed out whilst waiting for report to build")
                # If the response is a failure
                if (phantom.is_fail(ret_val)):
                    message = "Failed retrieving report for Intezer Analyze. Message: {}".format(response)
                    return action_result.set_status(phantom.APP_ERROR, status_message=message)

            # Create new python dictionary to store output
            data_output = response

            # Add the response into the data section
            action_result.add_data(data_output)

            # Add a dictionary that is made up of the most important values from data into the summary
            summary = action_result.update_summary({})
            summary['sha256'] = data_output['result']['sha256']
            summary['verdict'] = data_output['result']['verdict']
            summary['analysis_url'] = data_output['result']['analysis_url']

            # Return success, no need to set the message, only the status
            # BaseConnector will create a textual message based off of the summary dictionary
            return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        try:
            # Place vault id in in its own variable.
            report_id = param['id'].encode('utf-8')
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, status_message="Please provide valid ID")

        # Issue request to Intezer Analyze
        endpoint = 'v1-2/analyses/{}'.format(report_id)

        # Parameters to send to Intezer
        params = {
            'api_key': api_key
        }

        # Make connection to the Intezer Analyze endpoint
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", json_var=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            message = "Failed request to retrieve report. Message: {}".format(response)
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        if response['analysis_id']:
            self.save_progress("Report request has been posted to Intezer Analyze successfully")

            # Pass Analysis ID to Intezer Analyze
            analysis_id = response['analysis_id']

            # Create new request to the endpoint that holds the reports
            endpoint = 'v1-2/analyses/{}'.format(analysis_id)

            # Create new python dictionary to store output
            data_output = response

            # Add the response into the data section
            action_result.add_data(data_output)

            # Add a dictionary that is made up of the most important values from data into the summary
            summary = action_result.update_summary({})
            summary['sha256'] = data_output['result']['sha256']
            summary['verdict'] = data_output['result']['verdict']
            summary['analysis_url'] = data_output['result']['analysis_url']

            # Return success, no need to set the message, only the status
            # BaseConnector will create a textual message based off of the summary dictionary
            return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_file_reputation(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add config to init variable to get root API Key
        config = self.get_config()

        # Place api key in its own variable.
        api_key = config.get('apiKey')

        # Place vault id in in its own variable.
        sha_hash = param['hash']

        # Issue request to Intezer Analyze
        endpoint = '/v1-2/analyze-by-sha256'

        # Parameters to send to Intezer
        params = {
            'sha256': sha_hash,
            'api_key': api_key
        }

        # Make connection to the Intezer Analyze endpoint
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", json_var=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            message = "Failed request to retrieve hash report. Message: {}".format(response)
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        if response['analysis_id']:
            self.save_progress("Report request has been posted to Intezer Analyze successfully")

            # Pass Analysis ID to Intezer Analyze
            analysis_id = response['analysis_id']

            # Parameters
            params_rep = {'api_key': api_key}
            # Create new request to the endpoint that holds the reports
            endpoint = 'v1-2/analyses/{}'.format(analysis_id)

            # Make Second Call to Report URL
            ret_val, response = self._make_rest_call(endpoint, action_result, json_var=params_rep, method="post")
            # Report is Queued or In Progress
            i = 0
            # While the result is not succeeded or 50 seconds has not elapsed
            while i < 10 and response['status'] != 'succeeded':
                self.save_progress("Sleeping 60 seconds while report is being fetched")
                # Sleep 60 seconds
                time.sleep(60)
                # Make connection to the Intezer Report Endpoint
                ret_val, response = self._make_rest_call(endpoint, action_result, json_var=params_rep, method="post")
                # Increment the timeout counter
                i += 1
                # If we reach 10 minutes and the analysis has not returned
                if i == 10:
                    return action_result.set_status(phantom.APP_ERROR, status_message="Timed out whilst waiting for report to build")
                # If the response is a failure
                if (phantom.is_fail(ret_val)):
                    message = "Failed retrieving report for Intezer Analyze. Message: {}".format(response)
                    return action_result.set_status(phantom.APP_ERROR, status_message=message)

            # Make connection to the Intezer Report Endpoint
            ret_val, response = self._make_rest_call(endpoint, action_result, json_var=params_rep, method="post")
            self.save_progress("Result output: {}".format(response))
            # Create new python dictionary to store output
            data_output = response

            # Add the response into the data section
            action_result.add_data(data_output)

            # Add a dictionary that is made up of the most important values from data into the summary
            summary = action_result.update_summary({})
            summary['sha256'] = sha_hash
            summary['verdict'] = data_output['result']['verdict']
            summary['analysis_url'] = data_output['result']['analysis_url']

            # Return success, no need to set the message, only the status
            # BaseConnector will create a textual message based off of the summary dictionary
            return action_result.set_status(phantom.APP_SUCCESS)

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

        elif action_id == 'file_reputation':
            ret_val = self._handle_file_reputation(param)
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

        # Save the state, this data is saved accross actions and app upgrades
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
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
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
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = IntezerAnalyzeConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
