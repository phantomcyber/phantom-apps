# File: arborsightline_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from arborsightline_consts import *

import requests
import json
import datetime
import urllib
import urlparse

from bs4 import BeautifulSoup
from bs4 import UnicodeDammit


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ArborSightlineConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ArborSightlineConnector, self).__init__()

        self._state = {}

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
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        error_text = UnicodeDammit(error_text).unicode_markup.encode('utf-8')

        message = " Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

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
            r.status_code, UnicodeDammit(r.text.replace('{', '{{').replace('}', '}}')).unicode_markup.encode('UTF-8') if r.text else r.text.replace('{', '{{').replace('}', '}}'))

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
            r.status_code, UnicodeDammit(r.text.replace('{', '{{').replace('}', '}}')).unicode_markup.encode('UTF-8') if r.text else r.text.replace('{', '{{').replace('}', '}}'))

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

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs)
        except Exception as e:
            try:
                if e.message:
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('UTF-8')
                else:
                    error_msg = ARBORSIGHTLINE_GENERIC_ERROR_MSG
            except:
                error_msg = ARBORSIGHTLINE_GENERIC_ERROR_MSG

            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error occurred while connecting to the Arbor Sightline server. Error Message:{0}".format(error_msg)), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.
        request_headers = {
            'X-Arbux-APIToken': '{}'.format(self.get_config().get('auth_token')),
            'Accept': 'application/json'
        }

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(ARBORSIGHTLINE_API_URL, action_result,
                                                 method="get", params=None, headers=request_headers)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        self.save_progress("API {0} v.{1}".format(
            response.get("meta", {}).get("api"), response.get("meta", {}).get("api_version")))

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _parse_alerts(self, action_result, alerts):
        """ Parse alerts to create containers and artifacts """
        alerts_cnt = 0

        # What happens if you do not have alerts returned?
        # data = [] --> returns alerts_cnt = 0
        if alerts.get('data') is None:
            action_result.set_status(phantom.APP_ERROR, ARBORSIGHTLINE_ALERTS_DATA_KEY_UNAVAILABLE_MSG)
            return action_result.get_status(), None

        try:
            for data in alerts['data']:
                alert_id = data['id']
                target_address = data['attributes']['subobject']['host_address']
                impact_bps = data['attributes']['subobject']['impact_bps']
                impact_pps = data['attributes']['subobject']['impact_pps']
                victim_router = data['attributes']['subobject']['impact_boundary']
                classification = data['attributes']['classification']
                description = ""

                for include in alerts['included']:
                    if include['relationships']['parent']['data']['type'] == 'alert' and include['relationships']['parent']['data']['id'] == alert_id:
                        description = include['attributes']['text']
                        break

                # Creating container
                c = {
                    'data': {},
                    'description': 'Ingested from Arbor Sightline',
                    'source_data_identifier': alert_id,
                    'name': '{0} {1}'.format(classification, target_address)
                }

                # self.send_progress('Saving container for alert id {0}...'.format(alert_id))
                status, msg, id_ = self.save_container(c)
                # self.save_progress("Container id : {}, {}, {}".format(id_, status, msg))
                if status == phantom.APP_ERROR:
                    action_result.set_status(phantom.APP_ERROR, ARBORSIGHTLINE_CREATE_CONTAINER_FAILED_MSG.format(msg))
                    return action_result.get_status(), None

                # Creating artifacts
                cef = {
                    'targetAddress': target_address,
                    'impactBps': impact_bps,
                    'impactPps': impact_pps,
                    'victimRouter': victim_router,
                    'classification': classification,
                    'description': description
                }
                art = {
                    'container_id': id_,
                    'name': 'Event Artifact',
                    'label': 'event',
                    'source_data_identifier': c['source_data_identifier'],
                    'cef': cef,
                    'run_automation': True
                }

                # self.send_progress('Saving artifact...')
                status, msg, id_ = self.save_artifact(art)
                if status == phantom.APP_ERROR:
                    action_result.set_status(phantom.APP_ERROR, ARBORSIGHTLINE_CREATE_ARTIFACT_FAILED_MSG.format(msg))
                    return action_result.get_status(), None

                alerts_cnt += 1
        except Exception as e:
            try:
                if e.message:
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('UTF-8')
                else:
                    error_msg = "Error message unavailable"
            except:
                error_msg = "Unable to parse error message"

            action_result.set_status(phantom.APP_ERROR, '{}. Error message: {}'.format(ARBORSIGHTLINE_PARSE_ALERTS_FAILED_MSG, error_msg))
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, alerts_cnt

    def _get_alerts(self, action_result, url, paging_obj):
        """ Fetch alerts via REST """
        request_headers = {
            'X-Arbux-APIToken': '{}'.format(self.get_config().get('auth_token')),
            'Accept': 'application/json'
        }

        msg = ARBORSIGHTLINE_GET_ALERTS_PROGRESS_MSG.format(
            alerts_no=paging_obj['alerts_per_page'], page_no=paging_obj['page_cnt'])
        self.send_progress('{0} of {1}..'.format(
            msg, paging_obj['total_pages']) if paging_obj['total_pages'] is not None else msg)

        # make rest call
        ret_val, response = self._make_rest_call(
            url, action_result, method="get", headers=request_headers)

        if (phantom.is_fail(ret_val)):
            self.error_print(ARBORSIGHTLINE_GET_ALERTS_FAILED_MSG)
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, response

    def _poll_now(self, action_result, param):
        """ Poll data """
        max_containers = param[phantom.APP_JSON_CONTAINER_COUNT]
        disable_max_containers = self.get_config().get('max_containers')
        single_page = False
        paging_data = {
            "page_cnt": 1,
            "alerts_per_page": 50,
            "total_pages": None
        }
        self.save_progress("start_time:{0}".format(param[phantom.APP_JSON_START_TIME]))
        # Convert from epoch tIf an ingestion is already in progresso ISO 8601 format
        dt_start = datetime.datetime.utcfromtimestamp(
            param[phantom.APP_JSON_START_TIME] / 1000)
        dt_start_formatted = datetime.datetime.strftime(
            dt_start, "%Y-%m-%dT%H:%M:%S")
        self.save_progress(
            "Fetching alerts from {0} to now".format(dt_start_formatted))

        filter_value = (ARBORSIGHTLINE_GET_ALERTS_FILTER.format(
            time=dt_start_formatted))
        # Percent-encode our filter query.
        filter_value = urllib.quote(filter_value, safe='')

        # Add query params
        filter_param = "filter={0}".format(filter_value)
        other_param = "include=annotations"
        params = [filter_param, other_param]

        # Filtering the amount of results per page
        if not disable_max_containers and max_containers < paging_data['alerts_per_page']:
            paging_data['alerts_per_page'] = max_containers
            page_param = "perPage={0}".format(paging_data['alerts_per_page'])
            params.append(page_param)
            single_page = True

        url = "{0}?{1}".format(
            ARBORSIGHTLINE_GET_ALERTS_ENDPOINT, "&".join(params))
        self.save_progress("Url={0}".format(url))

        # Fetch alerts
        ret_val, response = self._get_alerts(action_result, url, paging_data)
        if (phantom.is_fail(ret_val)):
            try:
                self.error_print(action_result.get_status_message())
                self.save_progress(action_result.get_status_message())
            except:
                self.error_print(ARBORSIGHTLINE_GET_ALERTS_FAILED_MSG)
                self.save_progress(ARBORSIGHTLINE_GET_ALERTS_FAILED_MSG)
            return action_result.get_status()

        # Parse returned alerts
        ret_val, total_alerts = self._parse_alerts(action_result, response)
        if (phantom.is_fail(ret_val)):
            try:
                self.error_print(action_result.get_status_message())
                self.save_progress(action_result.get_status_message())
            except:
                self.error_print(ARBORSIGHTLINE_PARSE_ALERTS_FAILED_MSG)
                self.save_progress(ARBORSIGHTLINE_PARSE_ALERTS_FAILED_MSG)
            return action_result.get_status()

        # Handle case of no alerts found
        if total_alerts < 1:
            self.save_progress(ARBORSIGHTLINE_GET_ALERTS_EMPTY_MSG)
            action_result.set_status(
                phantom.APP_SUCCESS, ARBORSIGHTLINE_GET_ALERTS_EMPTY_MSG)
            return action_result.get_status()

        # Handle paging to fetch next alerts
        try:
            if not single_page:
                last_page_link = urllib.unquote(
                    response['links']['last']).replace("&amp;", "&")
                paging_data['total_pages'] = int(urlparse.parse_qs(
                    urlparse.urlparse(last_page_link).query)['page'][0])
                paging_data['page_cnt'] += 1

                while paging_data['page_cnt'] <= paging_data['total_pages']:
                    # Exit strategy with max containers
                    if not disable_max_containers:
                        remaining_alerts = max_containers - total_alerts
                        if remaining_alerts <= 0:
                            self.save_progress(
                                "Maximum amount of containers reached: leaving..")
                            break

                    page_param = "page={0}".format(paging_data['page_cnt'])
                    params = [filter_param, other_param, page_param]
                    url = "{0}?{1}".format(
                        ARBORSIGHTLINE_GET_ALERTS_ENDPOINT, "&".join(params))

                    ret_val, response = self._get_alerts(
                        action_result, url, paging_data)
                    if (phantom.is_fail(ret_val)):
                        try:
                            self.error_print(action_result.get_status_message())
                            self.save_progress(action_result.get_status_message())
                        except:
                            self.error_print(ARBORSIGHTLINE_GET_ALERTS_FAILED_MSG)
                            self.save_progress(ARBORSIGHTLINE_GET_ALERTS_FAILED_MSG)
                        return action_result.get_status()

                    # Eventually reduce amount of alerts to speed up processing
                    if not disable_max_containers and remaining_alerts < paging_data['alerts_per_page']:
                        response['data'] = response['data'][:remaining_alerts]

                    ret_val, page_alerts = self._parse_alerts(
                        action_result, response)
                    if (phantom.is_fail(ret_val)):
                        try:
                            self.error_print(action_result.get_status_message())
                            self.save_progress(action_result.get_status_message())
                        except:
                            self.error_print(ARBORSIGHTLINE_PARSE_ALERTS_FAILED_MSG)
                            self.save_progress(ARBORSIGHTLINE_PARSE_ALERTS_FAILED_MSG)
                        return action_result.get_status()

                    # Update counters
                    paging_data['page_cnt'] += 1
                    total_alerts += page_alerts
        except Exception as e:
            try:
                if e.message:
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('UTF-8')
                else:
                    error_msg = "Error message unavailable"
            except:
                error_msg = "Unable to parse error message"

            return action_result.set_status(phantom.APP_ERROR, '{}. Error message: {}'.format(ARBORSIGHTLINE_GET_ALERTS_PAGINATION_FAILED_MSG, error_msg))

        # if single-page closure

        # Save checkpoint
        self._state['last_ingested_epoch'] = param[phantom.APP_JSON_END_TIME]
        self.debug_print("Got new checkpoint: {}".format(
            self._state['last_ingested_epoch']))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self.is_poll_now():
            self.debug_print("DEBUGGER: Starting polling now")
            # Want to filter alerts with start_time > now - 1day ago? Uncomment below.
            # init_start_time = param[phantom.APP_JSON_END_TIME]
            # param[phantom.APP_JSON_START_TIME] = 1000 * ((init_start_time / 1000) - 86400)
            return self._poll_now(action_result, param)

        # handling scheduled on poll action
        if int(self._state.get('last_ingested_epoch', 0)) > 0:
            self.debug_print("DEBUGGER: Poll already executed. Found checkpoint : {}".format(
                self._state['last_ingested_epoch']))

            param[phantom.APP_JSON_START_TIME] = self._state['last_ingested_epoch']

        return self._poll_now(action_result, param)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

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

        self._base_url = UnicodeDammit(config.get('base_url')).unicode_markup.encode('utf-8')

        if self._base_url.endswith('/'):
            self._base_url = self._base_url[:-1]

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
            login_url = ArborSightlineConnector._get_phantom_base_url() + '/login'

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
            r2 = requests.post(login_url, verify=False,
                               data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ArborSightlineConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
