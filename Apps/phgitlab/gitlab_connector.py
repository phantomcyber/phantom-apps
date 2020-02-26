# File: gitlab_connector.py
# Copyright (c) Peter Bertel, 2020
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
import requests
import json
from bs4 import BeautifulSoup, UnicodeDammit


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class GitlabConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(GitlabConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        # self._base_url = "{}/api/v4".format(config.get('gitlab_location'))

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
        url = "{0}{1}".format(self._base_url, endpoint)
        self.save_progress("Connecting to endpoint: {}".format(url))
        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs)
        except requests.exceptions.ConnectionError:
            error_msg = "Connection refused by the server: {0}".format(url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(error_msg))), resp_json)
        except Exception as e:
            if e.message:
                if isinstance(e.message, basestring):
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('UTF-8')
                else:
                    try:
                        error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                    except:
                        error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
            else:
                error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_msg)), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")

        # make rest call
        ret_val, response = self._make_rest_call('/users', action_result, params=None, headers=self._rest_auth_header)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS, "Test Connectivity passed")

    def _handle_list_users(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._make_rest_call('/users', action_result, params=None, headers=self._rest_auth_header)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response:
            action_result.add_data(item)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully returned users")

    def _handle_list_projects(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._make_rest_call('/projects', action_result, params=None, headers=self._rest_auth_header)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response:
            action_result.add_data(item)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_branches(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        project_id = param['project_id']

        # make rest call
        ret_val, response = self._make_rest_call('/projects/{}/repository/branches'.format(project_id), action_result, params=None, headers=self._rest_auth_header)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response:
            action_result.add_data(item)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_trigger(self, param):

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        project_id = param['project_id']
        trigger_name = param['trigger_name']
        trigger_data = {'description': trigger_name}

        # make rest call
        ret_val, response = self._make_rest_call('/projects/{}/triggers'.format(
            project_id), action_result, method="post", params=None, headers=self._rest_auth_header, data=trigger_data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['trigger_token'] = response['token']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_triggers(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        project_id = param['project_id']

        # make rest call
        ret_val, response = self._make_rest_call('/projects/{}/triggers'.format(project_id), action_result, params=None, headers=self._rest_auth_header)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response:
            action_result.add_data(item)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_pipeline(self, param):

        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        trigger_token = UnicodeDammit(param['trigger_token']).unicode_markup.encode('utf-8')
        project_id = param['project_id']
        branch = param['branch']

        rest_params = {'token': trigger_token, 'ref': branch}

        # make rest call
        ret_val, response = self._make_rest_call('/projects/{}/trigger/pipeline'.format(project_id), action_result,
                                                 method="post", params=rest_params, headers=self._rest_auth_header)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary_dict = {'pipeline_id': response['id'], 'pipeline_web_url': response['web_url']}

        summary = action_result.update_summary({})
        summary.update(summary_dict)
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_users':
            ret_val = self._handle_list_users(param)

        elif action_id == 'list_projects':
            ret_val = self._handle_list_projects(param)

        elif action_id == 'list_branches':
            ret_val = self._handle_list_branches(param)

        elif action_id == 'create_trigger':
            ret_val = self._handle_create_trigger(param)

        elif action_id == 'list_triggers':
            ret_val = self._handle_list_triggers(param)

        elif action_id == 'run_pipeline':
            ret_val = self._handle_run_pipeline(param)

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

        self._base_url = "{0}/api/v4".format(UnicodeDammit(config['gitlab_location']).unicode_markup.encode('UTF-8'))
        self._personal_access_token = config['personal_access_token']

        self._rest_auth_header = {"PRIVATE-TOKEN": self._personal_access_token}

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
            login_url = GitlabConnector._get_phantom_base_url() + '/login'

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

        connector = GitlabConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
