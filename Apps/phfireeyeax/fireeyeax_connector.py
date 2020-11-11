#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Usage of the consts file is recommended
from fireeyeax_consts import *
import requests
from requests.auth import HTTPBasicAuth
import json
from bs4 import BeautifulSoup
from bs4 import UnicodeDammit
import uuid
import os
# import pudb


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class FireeyeAxConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(FireeyeAxConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_octet_response(self, r, action_result):
        # Create a unqiue ID for this file
        guid = uuid.uuid4()

        if hasattr(Vault, 'get_vault_tmp_dir'):
            local_dir = ('{}/{}').format(Vault.get_vault_tmp_dir(), guid)
        else:
            local_dir = ('/opt/phantom/vault/tmp/{}').format(guid)

        self.save_progress(('Using temp directory: {0}').format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'Unable to create temporary vault folder.', e)

        action_params = self.get_current_param()

        # Get the parameter passed into the function that caused an octect-stream response
        # Many cases this will be a file download function
        acq_id = action_params.get('uuid', 'no_id')

        # Set the file name for the vault
        filename = "{}_artifacts.zip".format(acq_id)

        zip_file_path = ('{0}/{1}').format(local_dir, filename)

        if r.status_code == 200:

            try:
                # Write the file to disk
                with open(zip_file_path, 'wb') as (f):
                    f.write(r.content)
            except Exception as e:
                return RetVal(action_result.set_status(phantom.APP_ERROR, ('Unable to write zip file to disk. Error: {0}').format(str(e))), None)
            else:
                try:
                    vault_results = Vault.add_attachment(zip_file_path, self.get_container_id(), file_name=filename)
                    return RetVal(phantom.APP_SUCCESS, vault_results)
                except Exception as e:
                    return RetVal(action_result.set_status(phantom.APP_ERROR, ('Unable to store file in Phantom Vault. Error: {0}').format(str(e))), None)

        message = ('Error from server. Status Code: {0} Data from server: {1}').format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process an octet response.
        # This is mainly for processing data downloaded during acquistions.
        if 'octet' in r.headers.get('Content-Type', ''):
            return self._process_octet_response(r, action_result)

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

    def _make_rest_call(self, endpoint, action_result, method="get", get_file=False, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts
        resp_json = None

        try:
            login_url = self._base_url + FIREEYEAX_LOGIN_ENDPOINT

            self.save_progress('AX Auth: Execute REST Call')

            req = requests.post(
                login_url,
                auth=HTTPBasicAuth(self._username, self._password),  # basic authentication
                verify=self._verify,
                headers=self._header
            )

            # Add the authorization value to the header
            if req.status_code >= 200 and req.status_code <= 204:
                self.save_progress('AX Auth: Process Response - Token Success')

                self._header['X-FeApi-Token'] = req.headers.get('X-FeApi-Token')
            else:
                self.save_progress('AX Auth: Process Response - Token Failed')

                message = 'AX Auth Failed, please confirm username and password'

                return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        except requests.exceptions.RequestException as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, ('Error Connecting to server. Details: {0}').format(str(e))), resp_json)
        else:
            # After we Login now proceed to call the endpoint we want
            try:
                request_func = getattr(requests, method)
            except AttributeError:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                    resp_json
                )

            # Create a URL to connect to
            url = self._base_url + endpoint

            # If we are submitting a file for detonation we need to update the content-type
            if "files" in kwargs.keys() or FIREEYEAX_DETONATE_FILE_ENDPOINT == endpoint:
                # Remove the Content-Type variable. Requests adds this automatically when uploading Files
                del self._header['Content-Type']
            # If we are downloading the artifact data from a submissions we need to update the content-type
            elif get_file is True:
                self._header['Content-Type'] = 'application/zip'

            try:
                r = request_func(
                    url,
                    verify=self._verify,
                    headers=self._header,
                    **kwargs
                )

            except Exception as e:
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                    ), resp_json
                )

            else:
                # Logout of the API.

                # Force reset of the header content-type
                # Have to do this since detonate file makes up change the value
                # Probably a better way to do this
                self._header['Content-Type'] = 'application/json'

                try:
                    self.save_progress('AX Logout: Execute REST Call')

                    logout_url = self._base_url + FIREEYEAX_LOGOUT_ENDPOINT

                    self.save_progress('AX Auth: Execute REST Call')

                    req = requests.post(
                        logout_url,
                        verify=self._verify,
                        headers=self._header
                    )

                except requests.exceptions.RequestException as e:
                    return RetVal(action_result.set_status(phantom.APP_ERROR, ('Error Connecting to server. Details: {0}').format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")

        params = {'duration': '2_hours'}

        endpoint = FIREEYEAX_ALERTS_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint, action_result, method="get", params=params
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_file(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        vault_id = UnicodeDammit(param.get('vault_id')).unicode_markup.encode('utf-8')

        # Get vault info from the vauld_id parameter
        try:
            vault_info = Vault.get_file_info(vault_id=vault_id)
        except Exception as e:
            if e.message:
                try:
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                except:
                    error_msg = "Unknown error occurred."
            else:
                error_msg = "Unknown error occurred."
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the file info. Error: {}".format(error_msg))

        if not vault_info:
            return action_result.set_status(phantom.APP_ERROR, "Error while fetching the vault information of the vault id: '{}'".format(param.get('vault_id')))

        # Loop through the Vault infomation
        for item in vault_info:

            vault_path = item.get('path')

            if vault_path is None:
                return action_result.set_status(phantom.APP_ERROR, "Could not find a path associated with the provided vault ID")

            try:
                # Open the file
                vault_file = open(item.get('path'), 'rb')

                # Create the files data to send to the console
                files = {
                    'file': (item['name'], vault_file)
                }

            except Exception as e:
                if e.message:
                    try:
                        error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                    except:
                        error_msg = "Unknown error occurred."
                else:
                    error_msg = "Unknown error occurred."

                return action_result.set_status(phantom.APP_ERROR, "Unable to open vault file: {}".format(error_msg))

        # Process parameters
        profile = param.get("profile")
        profile = [x.strip() for x in profile.split(',')]
        profile = list(filter(None, profile))

        # Get the other parameters and information
        priority = 0 if param['priority'] == 'Normal' else 1
        analysis_type = 1 if param['analysis_type'] == 'Live' else 2
        timeout = param.get('timeout')
        force = "true" if param['force'].lower() == "true" else "false"

        # When analysis type = 2 (Sandbox), prefetch must equal 1
        if analysis_type == 2:
            prefetch = 1
        else:
            prefetch = 1 if param['prefetch'].lower() is "true" else 0

        if param['enable_vnc']:
            enable_vnc = "true" if param['enable_vnc'].lower() == "true" else "false"

        data = {}

        # Get the application code to use for the detonation
        application = self.get_application_code(param.get('application'))

        # Create the data based on the parameters
        options = {
            "priority": priority,
            "analysistype": analysis_type,
            "force": force,
            "prefetch": prefetch,
            "profiles": profile,
            "application": application,
            "timeout": timeout,
            "enable_vnc": enable_vnc
        }

        # Need to stringify the options parameter
        data = {
            'options': json.dumps(options)
        }

        endpoint = FIREEYEAX_DETONATE_FILE_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint, action_result, method="post", files=files, data=data
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        resp_data = response[0]
        resp_data['submission_details'] = json.loads(resp_data['submission_details'])

        # Add the response into the data section
        action_result.add_data(resp_data)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_url(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        data = {}

        # Access action parameters passed in the 'param' dictionary
        urls = param.get("urls")
        urls = [x.strip() for x in urls.split(',')]
        urls = list(filter(None, urls))

        profile = param.get("profile")
        profile = [x.strip() for x in profile.split(',')]
        profile = list(filter(None, profile))

        # Get the other parameters and information
        priority = 0 if param['priority'].lower() == 'normal' else 1
        analysis_type = 1 if param['analysis_type'].lower == 'live' else 2
        force = "true" if param['force'].lower() == "true" else "false"
        prefetch = 1 if param['prefetch'].lower() == "true" else 0

        timeout = param.get('timeout')

        # Get the application code to use for the detonation
        application = self.get_application_code(param.get('application'))

        data = {
            "priority": priority,
            "analysistype": analysis_type,
            "force": force,
            "prefetch": prefetch,
            "urls": urls,
            "profiles": profile,
            "application": application,
            "timeout": timeout
        }

        if param['enable_vnc']:
            data['enable_vnc'] = "true" if param['enable_vnc'].lower() == "true" else "false"

        endpoint = FIREEYEAX_DETONATE_URL_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint, action_result, method="post", data=json.dumps(data)
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # Updating the response data so we can properly get the data. The data is returned by a string so we need to convert it into JSON to be useable
        resp_data = response['entity']['response']
        resp_data[0]['submission_details'] = json.loads(resp_data[0]['submission_details'])

        action_result.add_data(resp_data)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        id = param.get('id')

        params = {}
        # Add parameter to get more information on the report
        params['info_level'] = "extended" if param['extended'].lower() == "true" else "normal"

        endpoint = FIREEYEAX_GET_RESULTS_ENDPOINT.format(submission_id=id)

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint, action_result, params=params
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_save_artifacts(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        # Required values can be accessed directly
        uuid = param.get('uuid')

        endpoint = FIREEYEAX_SAVE_ARTIFACTS_ENDPOINT.format(uuid=uuid)

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint, action_result, get_file=True
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_status(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        id = param.get('id')

        endpoint = FIREEYEAX_GET_STATUS_ENDPOINT.format(submission_id=id)

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint, action_result
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        resp_data = response
        resp_data['submission_details'] = json.loads(resp_data['submission_details'])

        action_result.add_data(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    # Returns the application code for submitting URL's and Files to AX
    def get_application_code(self, application):
        # Set default
        code = "0"
        try:
            code = FIREEYEAX_APPLICATION_CODES[application]
        except KeyError:
            self.save_progress("Application {} is not found in the list of avaliable applications. Reverting to Default application code 0.".format(application))
            pass

        return code

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.
        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'detonate_file': self._handle_detonate_file,
            'detonate_url': self._handle_detonate_url,
            'get_report': self._handle_get_report,
            'save_artifacts': self._handle_save_artifacts,
            'get_status': self._handle_get_status
        }

        # Get the action that we are supposed to execute for this App Run
        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)
        return action_execution_status

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # Base URL initalize
        base_url = ""

        # Check to see which instance the user selected. Use the appropate URL.
        base_url = config.get('base_url')

        self._base_url = "{}/{}".format(base_url, FIREEYEAX_API_PATH)

        self._header = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        self._username = config.get('username')
        self._password = config.get('password')

        self._verify = config.get('verify_server_cert', False)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    # import pudb
    import argparse

    # pudb.set_trace()

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
            login_url = FireeyeAxConnector._get_phantom_base_url() + '/login'

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

        connector = FireeyeAxConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
