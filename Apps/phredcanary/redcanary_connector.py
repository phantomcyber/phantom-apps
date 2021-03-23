# File: redcanary_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from RedCanary.detections import RCDetections

from redcanary_consts import *
from datetime import datetime
import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class RedCanaryConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(RedCanaryConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

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
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing the error message")
            error_text = PARSE_ERR_MSG

        return error_text

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Status code: {}. Empty response and no information in the header".format(response.status_code)
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
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        if status_code != 200:
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        return RetVal(action_result.set_status(phantom.APP_SUCCESS, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(err_msg)
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

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
            self.save_progress("FOUND NO TEXT")
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        self.set_status("APP ERROR: {}".format(phantom.APP_ERROR))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        try:
            r = request_func(
                endpoint,
                verify=self.config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(err_msg)
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _generate_base_api_url(self, string=""):
        """
        Returns base url for Red Canary API
        """

        self.debug_print("Config: {}".format(self.config))

        return "{}/openapi/v3/{}".format(self.config.get('URL').rstrip("/"), string)

    def _build_url_list(self, base_url):
        """
        Generates list of all URLs to poll for detections

        Parameters:
            :baseurl:   String of base url (up to parameter)
            :args:      Tuple list of arguments and values to include with the URL
        Returns:
            :return: list of urls
        """
        count = 1
        urls_list = []

        while ((count - 1) * MAX_PER_PAGE) <= self._detection_count:

            # If first time running don't pass since param
            if self._first_run:
                params = [
                    (STR_PER_PAGE, str(MAX_PER_PAGE)),
                    (STR_PAGE, str(count))
                ]
            # Not first run and need to incldue since param
            else:
                params = [
                    (STR_PER_PAGE, str(MAX_PER_PAGE)),
                    (STR_PAGE, str(count)),
                    (STR_SINCE, self._state.get(STR_LAST_RUN))
                ]

            urls_list.append(
                self._generate_full_url(base_url, params)
            )
            count += 1

        return urls_list

    def _generate_full_url(self, base_url, param_list):
        """
        Generates full URLS for API polls

        Parameters:
            :baseurl:   String of base url (up to parameter)
            :args:      Tuple list of arguments and values to include with the URL
        Returns:
            :return: string value of the url to query
        """
        full_url = base_url
        self.debug_print("Arguments passed: {}".format(param_list))
        for variable, value in param_list:
            full_url = "{}&{}{}".format(full_url, variable, value)

        return full_url

    def _generate_headers(self):
        """
        Returns dictionary for headers used in Red Canary API request
        """
        return {'X-Api-Key': self.config.get("API Key")}

    def _find_detection_count(self, json_response):
        """
        Identifies how many new detections should be ingested

        Parameters:
            :json_response: json response from detections API
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), int(count of detections)
        """
        self.debug_print("Inside find detection count function")

        self._detection_count = json_response.get(STR_META, {}).get(STR_TOTAL_ITEMS, STR_NOT_FOUND)

        # If we failed to find the count
        if self._detection_count == STR_NOT_FOUND:

            return phantom.APP_ERROR, "Failed to find detection count"

        self.debug_print("Found {0} detections".format(self._detection_count))

        return phantom.APP_SUCCESS, int(self._detection_count)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to Red Canary")
        # make rest call
        url = self._generate_base_api_url("docs/index.html")

        self.save_progress("Testing Connection to: {0}".format(url))

        headers = self._generate_headers()

        ret_val, _ = self._make_rest_call(
            url, action_result, params=None, headers=headers
        )

        self.debug_print("Return value: {}".format(ret_val))

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")

            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):
        """
        Performs the on poll function

        Parameters:
            :param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Add action result object
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Create global dictionary of users
        self._global_user_dict = dict()

        self._poll_action_start = datetime.now().strftime(RC_DATE_TIME_FORMAT)
        # Base API URL
        base_url = self._generate_base_api_url("detections?")

        if self._first_run:
            self.save_progress("First run found will pull all detections")
            self.debug_print("Did not find last run sate, pulling all detections")

            params = [
                (STR_PER_PAGE, str(MAX_PER_PAGE))
            ]
            full_url = self._generate_full_url(base_url, params)
        # This is not the first run
        else:
            self.save_progress("Starting poll {0}".format(self._poll_action_start))
            self.debug_print("Starting iteractive poll {0}: Last poll occurred at: {1}".format(
                self._poll_action_start,
                self._last_run
            ))

            params = [
                (STR_PER_PAGE, str(MAX_PER_PAGE)),
                (STR_SINCE, self._last_run)
            ]

            full_url = self._generate_full_url(base_url, params)

        # Make initial URL call
        ret_val, response = self._make_rest_call(
            full_url, action_result, params=None, headers=self._generate_headers()
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, count = self._find_detection_count(response)

        # Failure to parse count
        if phantom.is_fail(ret_val):
            self.save_progress("Failed to parse detection count")
            self.debug_print("Failed to parse detection count", response)

            return action_result.set_status(ret_val)

        # If there are no detections stop
        if count == 0:
            self.save_progress("No new detections found")
            return action_result.set_status(phantom.APP_SUCCESS)

        # Now that we know the count and page size we can build the list of URLs to query
        self._urls = self._build_url_list(base_url)

        self.save_progress("Found {0} API URLs to query".format(len(self._urls)))
        self.debug_print("Full URL list: {0}".format(self._urls))

        # Build initial container
        container = dict()
        container.update({
            "name": "RC Poll: {}".format(datetime.utcnow().strftime(RC_DATE_TIME_FORMAT)),
            "artifacts": []
        })
        ret_val, message, cid = self.save_container(container)
        self.debug_print(f"save_container (with artifacts) returns, value: {ret_val}, reason: {message}, id: {cid}")

        if phantom.is_fail(ret_val):
            self.save_progress("Failed to create container {}".format(ret_val))
            action_result.set_status(phantom.APP_ERROR, "Failed to create container")
            return action_result.get_status()

        detections = []
        for full_url in self._urls:

            self.save_progress(f"Querying URL {full_url}")

            # Make API request
            ret_val, response = self._make_rest_call(
                full_url, action_result, params=None, headers=self._generate_headers()
            )

            if phantom.is_fail(ret_val):
                self.save_progress("Failed to connect received return value {}".format(ret_val))
                self.debug_print("Failed to query for total number of new detections", response)
                return action_result.get_status()

            # Add detections to list
            detections.extend(response.get('data'))

        self.save_progress(f"Found {len(detections)} new detections")
        self.save_progress("Enriching detection data. This can take a long time.")

        obj_detections = RCDetections(detections, self.config.get("API Key"))
        self.save_progress("Pulling user details")
        obj_detections.get_user_details()
        self.save_progress("Pulling detector details")
        obj_detections.get_detector_details()
        self.save_progress("Pulling detection timelines")
        obj_detections.get_detection_timeline()
        self.save_progress("Pulling endpoint details")
        obj_detections.get_endpoint_details()

        for detection in obj_detections.Detections:
            ret_val, message, cid = self._save_artifacts(detection, cid)

            if phantom.is_fail(ret_val):
                self.save_progress("Failed to save artifacts {}".format(ret_val))
                action_result.set_status(phantom.APP_ERROR, "Failed to save artifacts")
                return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _save_artifacts(self, detection, cid):
        """
        Saves artifacts to container id

        Parameters:
            :json_response: Data section of the web response
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), message, cid
        """
        artifacts = []
        # Add container id to detection
        artifact = {
            'name': detection.get('attributes', {}).get('headline'),
            'container_id': cid,
            'label': "Red Canary Detection",
            'type': "host",
            'cef': detection,
            'data': detection
        }
        artifacts.append(artifact)

        ret_val, message, _ = self.save_artifacts(artifacts)

        return ret_val, message, cid

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif (action_id == 'on_poll'):
            ret_val = self._on_poll(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions

        self._state = self.load_state()

        self.debug_print("state file path {0}".format(self.get_state_file_path()))

        # Check if the app ran before
        if not self._state.get(STR_LAST_RUN):
            self._first_run = True
        else:
            self._first_run = False
            self._last_run = self._state.get(STR_LAST_RUN)

        # get the asset config
        self.config = self.get_config()
        """
        # Access values in asset config by the name

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = self.config.get('base_url')

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades

        # If polling action was run save start time to the state file if no errors were encountered
        if self.get_action_identifier() == "on_poll" and self.get_status() != phantom.APP_ERROR:
            self._state[STR_LAST_RUN] = self._poll_action_start

        self.save_state(self._state)
        # self.save_progress("Final State: {0}".format(self._state))
        return phantom.APP_SUCCESS


def main():
    import pudb  # pylint: disable=import-error
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

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = RedCanaryConnector._get_phantom_base_url() + '/login'

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

        connector = RedCanaryConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
