# File: dossier_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from dossier_consts import *
import json
import requests
from requests.auth import HTTPBasicAuth
# from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class DossierConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(DossierConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _make_rest_call(self, endpoint):

        base_url = "https://api.activetrust.net:8000/api/services/intel/lookup"

        config = self.get_config()
        api_key = config["api_key"].encode('utf-8')

        headers = {"Content-Type": "application/json"}

        url = "{}{}".format(base_url, endpoint)
        r = requests.get(url, headers=headers, auth=HTTPBasicAuth(api_key, ""))

        return r.json(), r.status_code

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        _, status_code = self._make_rest_call("/targets")

        if status_code == 200:
            self.save_progress("Successfully connected and authenticated")
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            self.save_progress("Could not connect to service")
            return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_domain(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        domain = param['domain']

        # format our url
        url = "/indicator/host?value={}&source=atp&wait=true".format(domain)

        # make rest call
        response, status_code = self._make_rest_call(url)

        if status_code == 200:
            # Add the response into the data section
            action_result.add_data(response["results"])
            threat_level = 0
            threat_confidence = 0

            # this gets the highest theat level and confidence score for the summary
            for i in response["results"][0]["data"]["threat"]:

                if i["threat_level"] > threat_level:
                    threat_level = i["threat_level"]

                if "confidence" in i and i["confidence"] > threat_confidence:
                    self.debug_print(i['confidence'])

            # Add a dictionary that is made up of the most important values from data into the summary
            summary = action_result.update_summary({})
            summary['threat_level'] = threat_level
            summary['threat_confidence'] = threat_confidence

            # Return success, no need to set the message, only the status
            # BaseConnector will create a textual message based off of the summary dictionary
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Error fetching data")

    def _handle_lookup_hash(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        hash = param['hash']

        # format our url
        url = "/indicator/hash?value={}&source=malware_analysis&wait=true".format(hash)
        # make rest call
        response, status_code = self._make_rest_call(url)

        if status_code == 200:
            # Add the response into the data section
            action_result.add_data(response.get("results"))

            # Add a dictionary that is made up of the most important values from data into the summary
            summary = action_result.update_summary({})
            if response.get("results"):
                if response["results"][0]["data"].get("details", {}).get("av_match_count"):
                    summary['results'] = response["results"][0]["data"].get("details", {}).get("av_match_count")
                else:
                    summary['results'] = 0

            # Return success, no need to set the message, only the status
            # BaseConnector will create a textual message based off of the summary dictionary
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Error fetching data")

    def _handle_lookup_url(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        # submitted_url comes from phantom. not the best name, i know.
        submitted_url = param['url']

        # format our url
        url = "/indicator/url?value={}&source=atp&wait=true".format(submitted_url)

        # make rest call
        response, status_code = self._make_rest_call(url)

        if status_code == 200:
            # Add the response into the data section
            action_result.add_data(response["results"])

            # Add a dictionary that is made up of the most important values from data into the summary
            summary = action_result.update_summary({})
            if response.get("results"):
                summary['results'] = response["results"][0]["data"]["record_count"]

            # Return success, no need to set the message, only the status
            # BaseConnector will create a textual message based off of the summary dictionary
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Error fetching data")

    def _handle_lookup_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        ip = param['ip']

        # format our url
        url = "/indicator/ip?value={}&source=atp&wait=true".format(ip)

        # make rest call
        response, status_code = self._make_rest_call(url)
        if status_code == 200:
            # Add the response into the data section
            action_result.add_data(response.get("results"))

            # Add a dictionary that is made up of the most important values from data into the summary
            summary = action_result.update_summary({})
            if response.get("results"):
                if response["results"][0]["data"].get("record_count"):
                    summary['results'] = response["results"][0]["data"]["record_count"]
                else:
                    summary['results'] = 0

            # Return success, no need to set the message, only the status
            # BaseConnector will create a textual message based off of the summary dictionary
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Error fetching data")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'lookup_domain':
            ret_val = self._handle_lookup_domain(param)

        elif action_id == 'lookup_hash':
            ret_val = self._handle_lookup_hash(param)

        elif action_id == 'lookup_url':
            ret_val = self._handle_lookup_url(param)

        elif action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)

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
            login_url = DossierConnector._get_phantom_base_url() + '/login'

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

        connector = DossierConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
