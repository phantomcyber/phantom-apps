# File: splunkoncall_connector.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from splunkoncall_consts import INTEGRATION_URL_MISSING, UPDATE_INCIDENT_ERROR
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class VictoropsConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(VictoropsConnector, self).__init__()

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
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

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
        if 'json' in r.headers.get('Content-Type', '') or 200 == r.status_code:
            return self._process_json_response(r, action_result)
            # Added custom handling as only the alerts API does not respond with JSON header

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

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", json=None):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = ""
        if "https://" in endpoint:
            url = endpoint
            # special handling for alerts API that uses a different request format
        else:
            url = "https://api.victorops.com/api-public" + endpoint
            # standard request format

        auth_headers = {
            'X-VO-Api-Id': self._api_id,
            'X-VO-Api-Key': self._api_key,
            'Accept': 'application/json'
        }
        try:
            r = request_func(
                            url,
                            data=data,
                            headers=auth_headers,
                            json=json,
                            verify=config.get('verify_server_cert', True),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to /v1/team endpoint to test connectivity")
        # make rest call
        ret_val, response = self._make_rest_call('/v1/team', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")

        if self._integration_url:
            self.save_progress("Connecting to integration_url to test connectivity")
            body = {"message_type": "INFO", "state_message": "Test integration_url connectivity"}
            # make rest call
            ret_val, response = self._make_rest_call(self._integration_url, action_result, params=None, headers=None, json=body, method="post")
            if (phantom.is_fail(ret_val)):
                self.save_progress("Test Connectivity for integration_url Failed")
                return action_result.get_status()
            # Return success
            self.save_progress("Test Connectivity for integration_url Passed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_teams(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._make_rest_call('/v1/team', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        for item in response:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_teams'] = len(response)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_users(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call('/v1/user', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        users = response.get('users', [])
        try:
            for user in users[0]:
                action_result.add_data(user)
            # Add a dictionary that is made up of the most important values from data into the summary
            summary = action_result.update_summary({})
            summary['num_users'] = len(users[0])
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Could not retrieve users")

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_incidents(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call('/v1/incidents', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        data = response.get('incidents', [])
        for item in data:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_incidents'] = len(data)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_oncalls(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call('/v1/oncall/current', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        data = response.get('teamsOnCall', [])
        for item in data:
            action_result.add_data(item)

        # action_result.add_data({})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_teams_oncall'] = len(data)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_policies(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call('/v1/policies', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        data = response.get('policies', [])
        for item in data:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_policies'] = len(data)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_routing(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call('/v1/org/routing-keys', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        data = response.get('routingKeys')
        for item in data:
            action_result.add_data(item)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['num_routing_keys'] = len(data)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_incident(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # gather REST integration URL as it is unique per customer
        endpoint = ''
        if self._integration_url:
            routing = param.get('routing_key', None)
            if routing:
                routing = '/' + routing.strip('/')
                endpoint = self._integration_url + routing
            else:
                endpoint = self._integration_url
        else:
            summary = action_result.update_summary({})
            summary['message'] = INTEGRATION_URL_MISSING
            return action_result.set_status(phantom.APP_ERROR, INTEGRATION_URL_MISSING)

        param_type = param.get('message_type')
        param_name = param.get('entity_display_name')
        param_message = param.get('state_message')
        param_entity_id = param.get('entity_id')
        param_time = param.get('state_start_time', "")

        body = {
            "message_type": param_type,
            "state_start_time": param_time,
            "entity_id": param_entity_id,
            "entity_display_name": param_name,
            "state_message": param_message
        }

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, data=None, json=body, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        if response['result'] == 'failure':
            return action_result.set_status(phantom.APP_ERROR, response.get('message', UPDATE_INCIDENT_ERROR))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['entity_id'] = response['entity_id']

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

        elif action_id == 'list_teams':
            ret_val = self._handle_list_teams(param)

        elif action_id == 'list_users':
            ret_val = self._handle_list_users(param)

        elif action_id == 'list_incidents':
            ret_val = self._handle_list_incidents(param)

        elif action_id == 'create_incident':
            ret_val = self._handle_update_incident(param)

        elif action_id == 'list_oncalls':
            ret_val = self._handle_list_oncalls(param)

        elif action_id == 'list_policies':
            ret_val = self._handle_list_policies(param)

        elif action_id == 'list_routing':
            ret_val = self._handle_list_routing(param)

        elif action_id == 'update_incident':
            ret_val = self._handle_update_incident(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._api_id = config.get('api_id')
        self._api_key = config.get('api_key')
        self._integration_url = config.get('integration_url', '').rstrip('/')

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
            print("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = VictoropsConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
