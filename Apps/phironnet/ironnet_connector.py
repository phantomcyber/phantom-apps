# -----------------------------------------
# IronNet Phantom Connector
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
import re
from bs4 import BeautifulSoup
from bs4 import UnicodeDammit

severity_mapping = {
    "undecided": "SEVERITY_UNDECIDED",
    "benign": "SEVERITY_BENIGN",
    "suspicious": "SEVERITY_SUSPICIOUS",
    "malicious": "SEVERITY_MALICIOUS"
}

expectation_mapping = {
    "expected": "EXP_EXPECTED",
    "unexpected": "EXP_UNEXPECTED",
    "unknown": "EXP_UNKNOWN"
}

status_mapping = {
    "awaiting review": "STATUS_AWAITING_REVIEW",
    "under review": "STATUS_UNDER_REVIEW",
    "closed": "STATUS_CLOSED"
}

# Phantom ts format
phantom_ts = re.compile('^(\\d+-\\d+-\\d+) (\\d+:\\d+\\d+:\\d+\\.\\d+\\+\\d+)$')


def fix_timestamp(timestamp):
    # Attempts to reformat the given timestamp as RFC3339
    match = phantom_ts.match(timestamp)
    if(match):
        return match.group(1) + "T" + match.group(2) + ":00"
    return timestamp


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class IronnetConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(IronnetConnector, self).__init__()

        self._state = None

        self._base_url = None
        self._username = None
        self._password = None
        self._verify_server_cert = None

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

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
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))),
                None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        self.save_progress("Received response: Code:{}, Data:{}".format(r.status_code, r.text))

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

    def _make_post(self, endpoint, action_result, method="post", data={}, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts
        if kwargs['headers'] is None:
            kwargs['headers'] = {'Content-Type': 'application/json'}

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = UnicodeDammit(self._base_url).unicode_markup.encode('utf-8') + endpoint

        self.save_progress("Issuing {} request on {} w/ content: {}".format(method, url, data))
        try:
            r = request_func(
                url,
                auth=(self._username, self._password),  # basic authentication
                verify=self._verify_server_cert,
                data=json.dumps(data),
                **kwargs)
        except Exception as e:
            if e.message:
                if isinstance(e.message, basestring):
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('UTF-8')
                else:
                    try:
                        error_msg = str(e.message)
                    except:
                        error_msg = "Unknown error occurred. Please check the asset configuration parameters."
            else:
                error_msg = "Unknown error occurred. Please check the asset configuration parameters."
            self.save_progress("Error while issuing REST call - {}".format(error_msg))
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_msg)),
                resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Attempting to connect to IronAPI")

        # make rest call
        ret_val, response = self._make_post('/Login', action_result, data=None, headers=None)

        if phantom.is_success(ret_val):
            return action_result.set_status(phantom.APP_SUCCESS, "Test Connectivity to IronAPI Passed")
        else:
            self.save_progress("Error occurred in Test Connectivity: {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Test Connectivity to IronAPI Failed")

    def _handle_irondefense_rate_alert(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Received param: {0}".format(param))

        # Access action parameters passed in the 'param' dictionary
        request = {
            'alert_id': param['alert_id'],
            'comment': param['comment'],
            'share_comment_with_irondome': param['share_comment_with_irondome'],
            'analyst_severity': severity_mapping[param.get('analyst_severity', '')],
            'analyst_expectation': expectation_mapping[param.get('analyst_expectation', '')]
        }

        # make rest call
        ret_val, response = self._make_post('/RateAlert', action_result, data=request, headers=None)

        # Add the response into the data section
        action_result.add_data(response)

        if phantom.is_success(ret_val):
            self.debug_print("Alert rating was successful")
            return action_result.set_status(phantom.APP_SUCCESS, "Alert rating was successful")
        else:
            self.debug_print("Alert rating failed. Error: {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Alert rating failed. Error: {}".format(action_result.get_message()))

    def _handle_irondefense_set_alert_status(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Received param: {0}".format(param))

        # Access action parameters passed in the 'param' dictionary
        request = {
            'alert_id': param['alert_id'],
            'comment': param['comment'],
            'share_comment_with_irondome': param['share_comment_with_irondome'],
            'status': status_mapping[param['alert_status']]
        }

        # make rest call
        ret_val, response = self._make_post('/SetAlertStatus', action_result, data=request, headers=None)

        # Add the response into the data section
        action_result.add_data(response)

        if phantom.is_success(ret_val):
            self.debug_print("Setting alert staus was successful")
            return action_result.set_status(phantom.APP_SUCCESS, "Setting alert staus was successful")
        else:
            self.debug_print("Settings alert status failed. Error: {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Settings alert status failed. Error: {}".format(action_result.get_message()))

    def _handle_irondefense_comment_on_alert(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Received param: {0}".format(param))

        # Access action parameters passed in the 'param' dictionary
        request = {
            'alert_id': param['alert_id'],
            'comment': param['comment'],
            'share_comment_with_irondome': param['share_comment_with_irondome']
        }

        # make rest call
        ret_val, response = self._make_post('/CommentOnAlert', action_result, data=request, headers=None)

        # Add the response into the data section
        action_result.add_data(response)

        if phantom.is_success(ret_val):
            self.debug_print("Adding comment to alert was successful")
            return action_result.set_status(phantom.APP_SUCCESS, "Adding comment to alert was successful")
        else:
            self.debug_print("Adding comment failed. Error: {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Adding comment failed. Error: {}".format(action_result.get_message()))

    def _handle_irondefense_report_observed_bad_activity(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Received param: {0}".format(param))

        # Access action parameters passed in the 'param' dictionary
        request = {
            'name': param['name'],
            'description': param.get('description', ''),
            'domain': param.get('domain', ''),
            'ip': param.get('ip', ''),
            'activity_start_time': fix_timestamp(param['activity_start_time']),
            'activity_end_time': fix_timestamp(param.get('activity_end_time', param['activity_start_time'])),
        }

        self.save_progress("Request: {0}".format(request))

        # make rest call
        ret_val, response = self._make_post('/ReportObservedBadActivity', action_result, data=request, headers=None)

        # Add the response into the data section
        action_result.add_data(response)

        if phantom.is_success(ret_val):
            self.debug_print("Reporting bad activity to IronDefense was successful")
            return action_result.set_status(phantom.APP_SUCCESS, "Reporting bad activity to IronDefense was successful")
        else:
            self.debug_print("Reporting bad activity to IronDefense failed. Error: {}".format(action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, "Reporting bad activity to IronDefense failed. Error: {}".format(action_result.get_message()))

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'irondefense_rate_alert':
            ret_val = self._handle_irondefense_rate_alert(param)
        elif action_id == 'irondefense_set_alert_status':
            ret_val = self._handle_irondefense_set_alert_status(param)
        elif action_id == 'irondefense_comment_on_alert':
            ret_val = self._handle_irondefense_comment_on_alert(param)
        elif action_id == 'irondefense_report_observed_bad_activity':
            ret_val = self._handle_irondefense_report_observed_bad_activity(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config.get('base_url')
        self._username = config.get('username')
        self._password = config.get('password')
        self._verify_server_cert = config.get('verify_server_cert')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':
    import sys

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = IronnetConnector()
        connector.print_progress_message = True

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
