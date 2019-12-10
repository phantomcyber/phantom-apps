# File: canary_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CanaryConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CanaryConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._api_key = None

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

    def _make_rest_call(self, endpoint, action_result, method, params=None, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()
        domain = config.get('domain')

        parameters = {'auth_token': self._api_key}
        if params:
            parameters = parameters.update(params)

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = "https://" + domain + ".canary.tools/api/v1" + endpoint

        try:
            r = request_func(
                            url,
                            # auth=(username, password),  # basic authentication
                            params=parameters,
                            verify=True,
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

        ret_val, response = self._make_rest_call('/ping', action_result, headers=None, method="get")

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        if response:
            if response.get('result') == "success":
                return action_result.set_status(phantom.APP_SUCCESS)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Error while communicating with Canary API")
        else:
            return action_result.set_status(phantom.APP_ERROR, "Error while communicating with Canary API")

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_list_incidents(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        incidentState = param['incident_state']
        if incidentState == "acknowledged":
            endpoint = "/incidents/acknowledged"
        if incidentState == "unacknowledged":
            endpoint = "/incidents/unacknowledged"

        self.save_progress("Connecting to endpoint")
        # make rest call

        ret_val, response = self._make_rest_call(endpoint, action_result, headers=None, method="get")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if response:
            action_result.add_data(response)
            summary = action_result.update_summary({})
            summary['count'] = len(response['incidents'])

            if response.get('result') == "success":
                return action_result.set_status(phantom.APP_SUCCESS)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Error while communicating with Canary API")
        else:
            return action_result.set_status(phantom.APP_ERROR, "Error while communicating with Canary API")

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_on_poll(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = "/incidents/unacknowledged"

        self.save_progress("Connecting to endpoint")

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, headers=None, method="get")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Processing JSON Incident List")
        for incident in response["incidents"]:
            self.save_progress("Processing Incident")
            container = {"description": "Container added by Canary API",
                        "run_automation": False }
            container['name'] = incident["summary"]
            container['source_data_identifier'] = incident["id"]
            container['artifacts'] = []
            artifact = {"label": "report",
                        "type": "incident",
                        "name": "incident report",
                        "description": "Artifact added by Canary App"
                        }
            rawFields = {}
            rawFields['sourceAddress'] = incident["description"]["src_host"]
            rawFields['sourcePort'] = incident["description"]["src_port"]
            rawFields['destinationAddress'] = incident["description"]["dst_host"]
            rawFields['destinationPort'] = incident["description"]["dst_port"]
            rawFields['message'] = incident["description"]["description"]
            rawFields['startTime'] = incident["description"]["created_std"]
            rawFields['deviceHostname'] = incident["description"]["name"]
            rawFields['deviceExternalId'] = incident["description"]["node_id"]
            rawFields['externalId'] = incident["id"]
            artifact['cef'] = rawFields
            # artifact['cef_types'] = {'id': [ "threatstream incident id" ],
            #             'organization_id': [ "threatstream organization id" ]
            #                          }
            container['artifacts'].append(artifact)
            if len(incident["description"]["events"]) >= 1:
                for event in incident["description"]["events"]:
                    self.save_progress("Processing Event in Incident")
                    artifact = {"label": "report",
                                "type": "incident",
                                "name": "incident event",
                                "description": "Artifact added by Canary App"
                                }
                    artifact['cef'] = event
                    container['artifacts'].append(artifact)
            self.save_progress("Saving container and adding artifacts...")
            ret_val, message, container_id = self.save_container(container)

            self.save_progress("message: " + str(message))
            self.save_progress("container_id: " + str(container_id))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['count'] = len(response['incidents'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_update_incident(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident = param['incident']
        params = {'incident': incident}

        incidentState = param['incident_state']
        if incidentState == "acknowledge":
            endpoint = "/incident/acknowledge"
        if incidentState == "unacknowledge":
            endpoint = "/incident/unacknowledge"

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=params, headers=None, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section

        if response:
            action_result.add_data(response)
            summary = action_result.update_summary({})
            summary['result'] = response.get('result')

            if response.get('result') == "success":
                return action_result.set_status(phantom.APP_SUCCESS)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Error while communicating with Canary API")
        else:
            return action_result.set_status(phantom.APP_ERROR, "Error while communicating with Canary API")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        elif action_id == 'update_incident':
            ret_val = self._handle_update_incident(param)

        elif action_id == 'list_incidents':
            ret_val = self._handle_list_incidents(param)

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
        self._api_key = config.get('api_key')

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
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CanaryConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
