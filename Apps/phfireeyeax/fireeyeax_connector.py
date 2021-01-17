# File: fireeyeax_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault
import phantom.rules as phantom_rules

# Usage of the consts file is recommended
from fireeyeax_consts import *
import requests
import json
from bs4 import BeautifulSoup, UnicodeDammit
import uuid
import os
import sys


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
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERR_MSG
        except:
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

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Status code: {0}. Empty response and no information in the header".format(response.status_code)
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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                self._handle_py_ver_compat_for_input_str(error_text))

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
                    phantom.APP_ERROR, "Unable to parse JSON response. {0}".format(err)
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        error_message = r.text.replace('{', '{{').replace('}', '}}')
        error_message = self._handle_py_ver_compat_for_input_str(error_message)
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, error_message)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_octet_response(self, r, action_result):
        # Create a unique ID for this file
        guid = uuid.uuid4()

        if hasattr(Vault, 'get_vault_tmp_dir'):
            local_dir = ('{}/{}').format(Vault.get_vault_tmp_dir(), guid)
        else:
            local_dir = ('/opt/phantom/vault/tmp/{}').format(guid)

        self.save_progress("Using temp directory: {0}".format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, 'Unable to create temporary vault folder. {}'.format(err))

        action_params = self.get_current_param()

        # Get the parameter passed into the function that caused an octet-stream response
        # Many cases this will be a file download function
        acq_id = action_params.get('uuid', 'no_id')

        # Set the file name for the vault
        filename = "{}_artifacts.zip".format(acq_id)

        zip_file_path = "{0}/{1}".format(local_dir, filename)

        if r.status_code == 200:

            try:
                # Write the file to disk
                with open(zip_file_path, 'wb') as f:
                    f.write(r.content)
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to write zip file to disk. {0}".format(err)), None)
            else:
                try:
                    vault_results = Vault.add_attachment(zip_file_path, self.get_container_id(), file_name=filename)
                    return RetVal(phantom.APP_SUCCESS, vault_results)
                except Exception as e:
                    err = self._get_error_message_from_exception(e)
                    return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to store file in Phantom Vault. {0}".format(err)), None)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process an octet response.
        # This is mainly for processing data downloaded during acquisition.
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
            self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}'))
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", get_file=False, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts
        resp_json = None

        try:
            request_func = getattr(requests, "post")
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        try:
            login_url = "{0}{1}".format(self._base_url, FIREEYEAX_LOGIN_ENDPOINT)

            self.save_progress('AX Auth: Execute REST Call')

            req = request_func(
                login_url,
                auth=(self._username, self._password),  # basic authentication
                verify=self._verify,
                headers=self._header
            )
            # Add the authorization value to the header
            if req.status_code >= 200 and req.status_code <= 204:
                self.save_progress('AX Auth: Process Response - Token Success')

                self._header['X-FeApi-Token'] = req.headers.get('X-FeApi-Token')
            else:
                self.save_progress('AX Auth: Process Response - Token Failed')

                message = "AX Auth Failed, please confirm 'username' and 'password'"

                return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        except requests.exceptions.InvalidURL:
            error_message = "Error connecting to server. Invalid URL %s" % (login_url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.ConnectionError:
            error_message = "Error connecting to server. Connection Refused from the Server for %s" % (login_url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.InvalidSchema:
            error_message = "Error connecting to server. No connection adapters were found for %s" % (login_url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(err)), resp_json)
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
            try:
                url = "{0}{1}".format(self._base_url, endpoint)
            except:
                error_msg = "Failed to parse the url"
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, error_msg),
                    resp_json
                )

            # If we are submitting a file for detonation we need to update the content-type
            if "files" in kwargs.keys() or FIREEYEAX_DETONATE_FILE_ENDPOINT == endpoint:
                # Remove the Content-Type variable. Requests adds this automatically when uploading Files
                del self._header['Content-Type']
            # If we are downloading the artifact data from a submissions we need to update the content-type
            elif get_file:
                self._header['Content-Type'] = 'application/zip'

            try:
                r = request_func(
                    url,
                    verify=self._verify,
                    headers=self._header,
                    **kwargs
                )
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR, "Error Connecting to server. {0}".format(err)
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

                    logout_url = "{0}{1}".format(self._base_url, FIREEYEAX_LOGOUT_ENDPOINT)

                    self.save_progress('AX Auth: Execute REST Call')

                    req = requests.post(
                        logout_url,
                        verify=self._verify,
                        headers=self._header
                    )

                except requests.exceptions.RequestException as e:
                    err = self._get_error_message_from_exception(e)
                    return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(err)), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")

        params = {'duration': '2_hours'}

        endpoint = FIREEYEAX_ALERTS_ENDPOINT

        # make rest call
        ret_val, _ = self._make_rest_call(
            endpoint, action_result, params=params
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
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
        vault_id = self._handle_py_ver_compat_for_input_str(param.get('vault_id'))

        # Get vault info from the vauld_id parameter
        try:
            success, msg, vault_info = phantom_rules.vault_info(vault_id=vault_id)
        except:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the vault information of the specified Vault ID")

        if not vault_info:
            try:
                error_msg = "Error occurred while fetching the vault information of the Vault ID: {}".format(vault_id)
            except:
                error_msg = "Error occurred while fetching the vault information of the specified Vault ID"

            return action_result.set_status(phantom.APP_ERROR, error_msg)

        # Loop through the Vault infomation
        for item in vault_info:
            vault_path = item.get('path')
            if vault_path is None:
                return action_result.set_status(phantom.APP_ERROR, "Could not find a path associated with the provided Vault ID")
            try:
                # Open the file
                vault_file = open(vault_path, 'rb')
                # Create the files data to send to the console
                files = {
                    'file': (item['name'], vault_file)
                }
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Unable to open vault file: {}".format(error_msg))

        # Process parameters
        profile = param.get("profile")
        try:
            profile = [x.strip() for x in profile.split(',')]
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing the {}".format(PROFILE_ACTION_PARAM))
        profile = list(filter(None, profile))
        if not profile:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid value for the {}".format(PROFILE_ACTION_PARAM))

        # Get the other parameters and information
        priority = 0 if param['priority'].lower() == 'normal' else 1
        analysis_type = 1 if param['analysis_type'].lower() == 'live' else 2

        timeout = param.get('timeout')
        # Validate 'timeout' action parameter
        ret_val, timeout = self._validate_integer(action_result, timeout, TIMEOUT_ACTION_PARAM)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        force = "true" if param.get('force', True) else "false"

        # When analysis type = 2 (Sandbox), prefetch must equal 1
        if analysis_type == 2:
            prefetch = 1
        else:
            prefetch = 1 if param.get('prefetch', False) else 0

        enable_vnc = "true" if param.get('enable_vnc', False) else "false"

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
            return action_result.get_status()

        # Now post process the data, uncomment code as you deem fit
        try:
            resp_data = response[0]
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching data from API response. {}".format(err))

        try:
            resp_data['submission_details'] = json.loads(resp_data['submission_details'])
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing API response. {}".format(err))

        # Add the response into the data section
        if isinstance(resp_data, list):
            for alert in resp_data:
                action_result.add_data(alert)
        else:
            action_result.add_data(resp_data)

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
        try:
            urls = [x.strip() for x in urls.split(',')]
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing the {}".format(URL_ACTION_PARAM))
        urls = list(filter(None, urls))
        if not urls:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid value for the {}".format(URL_ACTION_PARAM))

        profile = param.get("profile")
        try:
            profile = [x.strip() for x in profile.split(',')]
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing the {}".format(PROFILE_ACTION_PARAM))
        profile = list(filter(None, profile))
        if not profile:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid value for the {}".format(PROFILE_ACTION_PARAM))

        # Get the other parameters and information
        priority = 0 if param['priority'].lower() == 'normal' else 1
        analysis_type = 1 if param['analysis_type'].lower() == 'live' else 2

        force = "true" if param.get('force', True) else "false"

        prefetch = 1 if param.get('prefetch', False) else 0

        timeout = param.get('timeout')
        # Validate 'timeout' action parameter
        ret_val, timeout = self._validate_integer(action_result, timeout, TIMEOUT_ACTION_PARAM)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Get the application code to use for the detonation
        application = self.get_application_code(param.get('application'))

        enable_vnc = "true" if param.get('enable_vnc', False) else "false"

        data = {
            "priority": priority,
            "analysistype": analysis_type,
            "force": force,
            "prefetch": prefetch,
            "urls": urls,
            "profiles": profile,
            "application": application,
            "enable_vnc": enable_vnc,
            "timeout": timeout
        }

        endpoint = FIREEYEAX_DETONATE_URL_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint, action_result, method="post", data=json.dumps(data)
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        # Updating the response data so we can properly get the data. The data is returned by a string so we need to convert it into JSON to be useable
        try:
            resp_data = response['entity']['response']
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching data from API response. {}".format(err))

        try:
            resp_data[0]['submission_details'] = json.loads(resp_data[0]['submission_details'])
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing API response. {}".format(err))

        if isinstance(resp_data, list):
            for alert in resp_data:
                action_result.add_data(alert)
        else:
            action_result.add_data(resp_data)

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
        params['info_level'] = "extended" if param.get('extended', False) else "normal"

        endpoint = FIREEYEAX_GET_RESULTS_ENDPOINT.format(submission_id=id)

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint, action_result, params=params
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

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
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

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
            return action_result.get_status()

        # Add the response into the data section
        resp_data = response
        try:
            resp_data['submission_details'] = json.loads(resp_data['submission_details'])
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while processing API response. {}".format(err))

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    # Returns the application code for submitting URL's and Files to AX
    def get_application_code(self, application):
        # Set default
        code = "0"
        try:
            code = FIREEYEAX_APPLICATION_CODES[application]
        except KeyError:
            self.save_progress("Could not find the specified application in the available application list. Reverting to Default application code 0")
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

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version")

        # Check to see which instance the user selected. Use the appropriate URL.
        base_url = config.get('base_url').strip("/")

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
