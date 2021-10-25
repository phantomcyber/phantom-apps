# File: terraformcloud_connector.py
#
# Copyright (c) 2020 Splunk Inc.
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

from terraformcloud_consts import *
import requests
import json
from bs4 import BeautifulSoup, UnicodeDammit
import sys


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TerraformCloudConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TerraformCloudConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Status Code: {}. Empty response and no information in the header".format(response.status_code)), None)

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
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. {0}".format(self._get_error_message_from_exception(e))), None)

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

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, ERR_VALID_INT_MSG.format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, ERR_VALID_INT_MSG.format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, ERR_NON_NEG_INT_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _make_rest_call(self, endpoint, action_result, method="get", headers=None, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        _headers = {
            "authorization": "Bearer {}".format(self._auth_token)
        }

        if headers:
            _headers.update(headers)

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = "{}{}".format(self._base_url, endpoint)

        try:
            r = request_func(
                            url,
                            verify=False,
                            headers=_headers,
                            **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(self._get_error_message_from_exception(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to account details endpoint...")

        # make rest call
        ret_val, response = self._make_rest_call(TERRAFORM_ENDPOINT_ACCOUNT_DETAILS, action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_workspaces(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        organization_name = param['organization_name']
        page_num = param.get('page_num', 1)
        ret_val, page_num = self._validate_integer(action_result, page_num, PAGE_NUM_INT_PARAM)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        page_size = param.get('page_size', 100)
        ret_val, page_size = self._validate_integer(action_result, page_size, PAGE_SIZE_INT_PARAM)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = {
            'page[num]': page_num,
            'page[size]': page_size
        }

        self.save_progress("Params: {}".format(params))

        endpoint = TERRAFORM_ENDPOINT_WORKSPACES.format(organization_name=organization_name)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_runs(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        workspace_id = param['id']
        page_num = param.get('page_num', 1)
        ret_val, page_num = self._validate_integer(action_result, page_num, PAGE_NUM_INT_PARAM)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        page_size = param.get('page_size', 20)
        ret_val, page_size = self._validate_integer(action_result, page_size, PAGE_SIZE_INT_PARAM)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = {
            'page[num]': page_num,
            'page[size]': page_size
        }

        endpoint = TERRAFORM_ENDPOINT_LIST_RUNS.format(id=workspace_id)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_run(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        workspace_id = param['workspace_id']
        configuration_version = param.get('configuration_version')
        message = param.get('message')
        is_destroy = param.get('is_destroy', False)

        params = {
            "data": {
                "attributes": {
                    "is-destroy": is_destroy,
                    "message": message
                }
            },
            "relationships": {
                "workspace": {
                    "data": {
                        "type": "workspaces",
                        "id": workspace_id
                    }
                }
            },
            "configuration-version": {
                "data": {
                    "type": "configuration-versions",
                    "id": configuration_version
                }
            }
        }

        headers = {
            'Content-Type': 'application/vnd.api+json'
        }

        # make rest call
        ret_val, response = self._make_rest_call(TERRAFORM_ENDPOINT_RUNS, action_result, method="post", headers=headers, json=params)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_workspace(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        organization_name = param['organization_name']

        post_data = {
            'type': 'workspaces',
            'attributes': {
                'name': param['workspace_name']
            }
        }

        if param.get('description'):
            post_data['attributes']['description'] = param.get('description')

        if param.get('vcs_repo_id'):
            # both repo id and token id are required
            if not param.get('vcs_token_id'):
                return action_result.set_status(phantom.APP_ERROR, "If a VCS repo is to be linked to this workspace, both the repository ID and the token ID are required")

            post_data['attributes']['vcs-repo'] = {
                'identifier': param.get('vcs_repo_id'),
                'oauth-token-id': param.get('vcs_token_id')
            }

        post_data['attributes']['file-triggers-enabled'] = param.get('file_triggers_enabled', True)
        post_data['attributes']['auto-apply'] = param.get('auto_apply', False)
        post_data['attributes']['queue-all-runs'] = param.get('queue_all_runs', False)
        post_data = {
            'data': post_data
        }
        endpoint = TERRAFORM_ENDPOINT_WORKSPACES.format(organization_name=organization_name)

        headers = {
            'Content-Type': 'application/vnd.api+json'
        }

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", headers=headers, json=post_data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        resp_data = response.get('data', {})

        action_result.add_data(resp_data)

        summary = action_result.update_summary({})
        summary['workspace_id'] = resp_data.get('id')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_apply_run(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        run_id = param['id']
        comment = param.get('comment')

        params = {}

        if comment:
            params['comment'] = comment

        headers = {
            'Content-Type': 'application/vnd.api+json'
        }

        endpoint = TERRAFORM_ENDPOINT_APPLY_RUN.format(run_id=run_id)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, method="post", headers=headers, json=params)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_apply(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param['id']

        endpoint = TERRAFORM_ENDPOINT_APPLIES.format(id=id)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_plan(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param['id']

        endpoint = TERRAFORM_ENDPOINT_PLANS.format(id=id)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response.get('data', {}))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_run(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param['id']

        endpoint = "{}/{}".format(TERRAFORM_ENDPOINT_RUNS, id)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response.get('data', {}))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_workspace(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        id = param.get('id')
        organization_name = param.get('organization_name')
        workspace_name = param.get('workspace_name')

        if id:
            endpoint = TERRAFORM_ENDPOINT_GET_WORKSPACE_BY_ID.format(id=id)
        elif organization_name and workspace_name:
            endpoint = "{}/{}".format(TERRAFORM_ENDPOINT_WORKSPACES.format(organization_name=organization_name), workspace_name)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Please provide 'id' or both the 'organization name' and 'workspace name' action parameters")

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response.get('data', {}))

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_workspaces':
            ret_val = self._handle_list_workspaces(param)

        elif action_id == 'list_runs':
            ret_val = self._handle_list_runs(param)

        elif action_id == 'create_run':
            ret_val = self._handle_create_run(param)

        elif action_id == 'create_workspace':
            ret_val = self._handle_create_workspace(param)

        elif action_id == 'apply_run':
            ret_val = self._handle_apply_run(param)

        elif action_id == 'get_apply':
            ret_val = self._handle_get_apply(param)

        elif action_id == 'get_plan':
            ret_val = self._handle_get_plan(param)

        elif action_id == 'get_run':
            ret_val = self._handle_get_run(param)

        elif action_id == 'get_workspace':
            ret_val = self._handle_get_workspace(param)

        return ret_val

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

        # base URL
        self._base_url = config.get('base_url', TERRAFORM_DEFAULT_URL).strip('/')
        self._base_url = "{}{}".format(self._base_url, TERRAFORM_BASE_API_ENDPOINT)

        # token
        self._auth_token = config["token"]

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
            login_url = TerraformCloudConnector._get_phantom_base_url() + '/login'

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

        connector = TerraformCloudConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
