# --
# File: chronicle_connector.py
#
# Copyright (c) 2020-2021 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import re
import time
import requests
import json
import httplib2
from bs4 import BeautifulSoup
from collections import defaultdict
from datetime import datetime, timedelta
from hashlib import sha256

# Usage of the consts file is recommended
from chronicle_consts import *      # noqa

from google.oauth2 import service_account
from googleapiclient import _auth


class ChronicleConnector(BaseConnector):
    """Represent a connector module that implements the actions that are provided by the app. ChronicleConnector is a class that is derived from the BaseConnector class."""

    def __init__(self):
        """Initialize global variables."""
        # Call the BaseConnectors init first
        super(ChronicleConnector, self).__init__()

        # State file variable initialization
        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

        # Other variable initialization
        self._scopes = None
        self._key_dict = None
        self._wait_timeout_period = None
        self._no_of_retries = None

        # Reputation variable initialization
        self._malicious_category = None
        self._malicious_severity = None
        self._malicious_str_confidence = None
        self._malicious_int_confidence = None
        self._suspicious_category = None
        self._suspicious_severity = None
        self._suspicious_str_confidence = None
        self._suspicious_int_confidence = None

        # Ingestion variable initialization
        self._run_mode = None
        self._is_poll_now = None
        self._max_results = None
        self._max_artifacts = None
        self._alerts_severity = None
        self._run_automation = False

        # First Run Dictionary of the form {'run_mode': False}
        self._is_first_run = {
            GC_RM_IOC_DOMAINS: False,
            GC_RM_ASSET_ALERTS: False,
            GC_RM_USER_ALERTS: False,
            GC_RM_ALERTING_DETECTIONS: False,
            GC_RM_NOT_ALERTING_DETECTIONS: False
        }

        # Use this dictionary to maintain the hash for the fetched results
        self._last_run_hash_digests = dict()
        # Ingestion time dictionary initialization
        self._time_dict = dict()

    def _process_empty_response(self, response, action_result):
        """Process empty response.

        Parameters:
            :param response: response data
            :param action_result: object of ActionResult class
        Returns:
            :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), response
        """
        # Check for valid status code
        if response[0].status == 200:
            return phantom.APP_SUCCESS, {}

        return action_result.set_status(phantom.APP_ERROR, f"Status code: {response[0].status}. Empty response and no information in the header"), None

    def _process_html_response(self, response, action_result):
        """Process html response.

        Parameters:
            :param response: response data
            :param action_result: object of ActionResult class
        Returns:
            :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), response
        """
        # An html response, treat it like an error
        try:
            # Parse error response
            soup = BeautifulSoup(response[1], "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception as e:
            self.debug_print(f"Error occurred while processing html response. Error: {str(e)}")
            error_text = f"Cannot parse error details. Response: {response[1]}"

        message = f"Status Code: {response[0].status}. Cannot parse error details. Data from server:\n{error_text}\n"

        message = message.replace('{', '{{').replace('}', '}}')

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _process_json_response(self, response, action_result):
        """Process json response.

        Parameters:
            :param response: response data
            :param action_result: object of ActionResult class
        Returns:
            :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), response
        """
        # Check for valid status code
        if 200 <= response[0].status < 399:
            # try to fetch successful response
            try:
                response = json.loads(response[1])
                return phantom.APP_SUCCESS, response
            except json.decoder.JSONDecodeError:
                # Invalid JSON received
                return action_result.set_status(phantom.APP_ERROR, GC_INVALID_RESPONSE_FORMAT), None
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, f"{GC_INVALID_RESPONSE_FORMAT} Error: {str(e)}"), None

        # Parse error message
        err_message = self._parse_error_message(action_result, response[1])

        return action_result.set_status(phantom.APP_ERROR, err_message), None

    def _process_response(self, r, action_result):
        """Process API response.

        Parameters:
            :param r: response data
            :param action_result: object of ActionResult class
        Returns:
            :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), response
        """
        # Store the response_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'response_status_code': r[0].status})
            action_result.add_debug_data({'response_text': r[1]})
            action_result.add_debug_data({'response_http': r[0]})

        # Check for the response status code
        if r[0].status == 500:
            return action_result.set_status(phantom.APP_ERROR, f"Status code: {r[0].status}. {GC_INTERNAL_SERVER_ERROR}"), None

        # Process each 'Content-Type' of response separately
        content_type = r[0].get('content-type')

        # handle an empty response and check that response is available
        if not r[1]:
            return self._process_empty_response(r, action_result)

        # Process a json response
        if 'json' in content_type:
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in content_type:
            return self._process_html_response(r, action_result)

        # everything else is actually an error at this point
        err_resp = r[1].replace('{', '{{').replace('}', '}}') if r[1] else "Response error text not found"
        message = f"Can't process response from server. Status Code: {r[0].status} Data from server: {err_resp}"

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _make_rest_call(self, action_result, client, endpoint, method="GET"):
        """Make the REST call to the app.

        Parameters:
            :param action_result: object of ActionResult class
            :param client: object of HTTP client
            :param endpoint: REST endpoint that needs to appended to the service address
            :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        Returns:
            :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), response obtained by making an API call
        """
        # Create a URL to connect to Chronicle
        url = f"{self._base_url}{endpoint}"
        action_identifier = self.get_action_identifier()

        self.debug_print("Making a REST call with provided request parameters")
        self.debug_print(f"Request URL: {url}")
        self.debug_print(f"Request method: {method}")

        for _ in range(self._no_of_retries + 1):
            try:
                response = client.request(url, method)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, f"Error connecting to server. Error: {str(e)}"), None

            # Check for the response is present or not
            if not response:
                return action_result.set_status(phantom.APP_ERROR, GC_TECHNICAL_ERROR), None

            try:
                if len(response) != 2:
                    return action_result.set_status(phantom.APP_ERROR, GC_RESPONSE_ERROR), None
                # Expectation of response format is tuple::(<object of httplib2.Response>, response)
                self.debug_print(f"Received httplib2 response object: {response[0]}")
                self.debug_print(f"Received original response: {response[1]}")
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, f"{GC_RESPONSE_ERROR}. Error while checking response. Error: {str(e)}"), None

            # Expectation of response format (<object of httplib2.Response>, JSON response)
            if not isinstance(response[0], httplib2.Response):
                return action_result.set_status(phantom.APP_ERROR, GC_RESPONSE_ERROR), None

            if response[0].status == 429:
                # Retrying REST call in case of RESOURCE_EXHAUSTED Error
                self.save_progress(f"Received RESOURCE_EXHAUSTED (Status code: 429) Error for the {action_identifier} action.")
                self.debug_print(f"Received RESOURCE_EXHAUSTED (Status code: 429) Error for the {action_identifier} action.")
                self.save_progress(f"Retrying API call after {self._wait_timeout_period} seconds")
                self.debug_print(f"Retrying API call after {self._wait_timeout_period} seconds")

                # add time sleep
                time.sleep(self._wait_timeout_period)
                continue

            return self._process_response(response, action_result)
        else:
            # API rate limit exceeded
            return action_result.set_status(phantom.APP_ERROR, GC_RATE_LIMIT_EXCEEDED), None

    def _check_timerange(self, value):
        """Check that given time range value is in the correct format or not.

        Parameters:
            :param value: value of time range
        Returns:
            :return: status(True/False)
        """
        # Check for format
        match = re.match(GC_TIME_RANGE_PATTERN, value)
        if match is None:
            return False
        return True

    def _check_invalid_since_utc_time(self, action_result, time):
        """Determine that given time is not before 1970-01-01T00:00:00Z.

        Parameters:
            :param action_result: object of ActionResult class
            :param time: object of time
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Check that given time must not be before 1970-01-01T00:00:00Z.
        if time < datetime.strptime("1970-01-01T00:00:00Z", GC_DATE_FORMAT):
            return action_result.set_status(phantom.APP_ERROR, GC_UTC_SINCE_TIME_ERROR)
        return phantom.APP_SUCCESS

    def _derive_time_period(self, action_result, value):
        """Derive the time period using value of time range given in the action parameters.

        Parameters:
            :param action_result: object of ActionResult class
            :param value: value of time range action parameter
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), start date, end date
        """
        # Initialize time period
        start_time = None
        end_time = None

        # Convert string
        digit = self._validate_integers(action_result, value[:-1], "Time Range")
        if not digit:
            return action_result.set_status(phantom.APP_ERROR, GC_TIME_RANGE_VALIDATION_MSG), start_time, end_time

        # Take current time as end time
        end_time = datetime.utcnow()

        # Calculate start time as per given time range value
        if "d" in value:
            start_time = end_time - timedelta(days=digit)
        elif "h" in value:
            start_time = end_time - timedelta(hours=digit)
        elif "m" in value:
            start_time = end_time - timedelta(minutes=digit)
        elif "s" in value:
            start_time = end_time - timedelta(seconds=digit)

        # Check for start time
        ret_val = self._check_invalid_since_utc_time(action_result, start_time)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None, None

        return phantom.APP_SUCCESS, start_time.strftime(GC_DATE_FORMAT), end_time.strftime(GC_DATE_FORMAT)

    def _validate_time_range(self, action_result, time_range):
        """Validate the value of time range given in the action parameters.

        Parameters:
            :param action_result: object of ActionResult class
            :param time_range: value of time range action parameter
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), start date, end date
        """
        # Initialize time period
        start_date = None
        end_date = None
        try:
            # Check for the valid time range value
            if self._check_timerange(time_range):
                # Derive time period using time range
                ret_val, start_date, end_date = self._derive_time_period(action_result, time_range)
                if phantom.is_fail(ret_val):
                    return action_result.get_status(), None, None

                # Return time period
                return phantom.APP_SUCCESS, start_date, end_date
            else:
                return action_result.set_status(phantom.APP_ERROR, GC_TIME_RANGE_VALIDATION_MSG), None, None
        except OverflowError:
            return action_result.set_status(phantom.APP_ERROR, GC_UTC_SINCE_TIME_ERROR), None, None
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"{GC_TIME_RANGE_VALIDATION_MSG} . Error: {str(e)}"), None, None

    def _check_date_format(self, date):
        """Validate the value of time parameter given in the action parameters.

        Parameters:
            :param date: value of time(start/end/reference) action parameter
        Returns:
            :return: status(True/False), time
        """
        # Initialize time for given value of date
        time = None
        try:
            # Check for the time is in valid format or not
            time = datetime.strptime(date, GC_DATE_FORMAT)
        except Exception as e:
            self.debug_print(f"Invalid date string received. Error occurred while checking date format. Error: {str(e)}")
            return False, None
        return True, time

    def _validate_end_date(self, action_result, start_time, end_date, today):
        """Validate the end time parameter given in the action parameters.

        Parameters:
            :param action_result: object of ActionResult class
            :param start_time: object of start time
            :param end_date: string of end time action parameter
            :param today: object of current time
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), end time
        """
        # Checking date format
        e_check, end_time = self._check_date_format(end_date)
        if not e_check:
            return action_result.set_status(phantom.APP_ERROR, GC_INVALID_TIME_ERR.format("end time")), None

        # Checking future date
        if end_time > today:
            return action_result.set_status(phantom.APP_ERROR, GC_GREATER_TIME_ERR.format("end time")), None

        # Checking end date must be lower than start date
        if start_time >= end_time:
            return action_result.set_status(phantom.APP_ERROR, GC_INVALID_TIME_PERIOD), None

        return phantom.APP_SUCCESS, end_time

    def _validate_start_date(self, action_result, start_date, today):
        """Validate the start time parameter given in the action parameters.

        Parameters:
            :param action_result: object of ActionResult class
            :param start_date: value of start time action parameter
            :param today: object of current time
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), start time
        """
        # Checking start time format
        s_check, start_time = self._check_date_format(start_date)
        if not s_check:
            return action_result.set_status(phantom.APP_ERROR, GC_INVALID_TIME_ERR.format("start time")), None

        if start_time > today:
            return action_result.set_status(phantom.APP_ERROR, GC_GREATER_TIME_ERR.format("start time")), None

        # Check for start time
        ret_val = self._check_invalid_since_utc_time(action_result, start_time)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, start_time

    def _validate_time_params(self, action_result, start_date, end_date=None):
        """Validate the time(start/end) parameters given in the action parameters.

        Parameters:
            :param action_result: object of ActionResult class
            :param start_date: value of start time action parameter
            :param end_date: value of end time action parameter
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), start date, end date
        """
        # Initialize time period
        start_time = None
        end_time = None

        if not start_date:
            return action_result.set_status(phantom.APP_ERROR, GC_TIME_PARAM_ERROR), None, None

        if self.get_action_identifier() != "list_iocs" and not end_date:
            return action_result.set_status(phantom.APP_ERROR, GC_TIME_PARAM_ERROR), None, None

        # Checking for future date
        today = datetime.utcnow()

        # Validate start time
        ret_val, start_time = self._validate_start_date(action_result, start_date, today)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None, None

        # Update start date for valid input
        start_date = start_time.strftime(GC_DATE_FORMAT)

        if end_date:
            # Validate end time
            ret_val, end_time = self._validate_end_date(action_result, start_time, end_date, today)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None, None
            # Update end date for valid input
            end_date = end_time.strftime(GC_DATE_FORMAT)

        return phantom.APP_SUCCESS, start_date, end_date

    def _validate_time_related_params(self, action_result, param, flag=False):
        """Validate the time related parameters given in the action parameters.

        Parameters:
            :param action_result: object of ActionResult class
            :param param: Dictionary of input parameters
            :param flag: Indicator for reference time that whether it to be set or not
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), time parameters dictionary
        """
        # Initialize time parameter dictionary
        start_date = str()
        end_date = str()
        time_param = dict()
        time_param.update({
            GC_START_TIME_KEY: None,
            GC_END_TIME_KEY: None,
            GC_REFERENCE_TIME_KEY: None
        })

        start_time = param.get(GC_START_TIME_KEY)
        end_time = param.get(GC_END_TIME_KEY)
        reference_time = param.get(GC_REFERENCE_TIME_KEY)
        time_range = param.get(GC_TIME_RANGE_KEY)

        # If any of the time related params not given, then, time period will be consider as last three days.
        if not any([start_time, end_time, time_range]):
            # Set default time range to last three days
            time_range = "3d"

        # Calculate time period based on provided time related parameters
        if time_range:
            ret_val, start_date, end_date = self._validate_time_range(action_result, time_range.lower())
        elif start_time or end_time:
            ret_val, start_date, end_date = self._validate_time_params(action_result, start_time, end_time)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), time_param

        # Updating time period
        time_param.update({
            GC_START_TIME_KEY: start_date,
            GC_END_TIME_KEY: end_date
        })

        # Flag will be checked for whether reference time will be needed to the caller method or not
        if not flag:
            return phantom.APP_SUCCESS, time_param

        # Add reference time to time dict if given
        if reference_time:
            ret_val, reference_time = self._check_date_format(reference_time)
            if not ret_val:
                # NOTE: This will be update if the reference time will not impact on the output results.
                # And set the start time as reference time.
                # Or we can set expectations as if parameter is given, it must be validated.
                return action_result.set_status(phantom.APP_ERROR, "Please provide valid reference time in the action parameters"), time_param
            time_param.update({GC_REFERENCE_TIME_KEY: reference_time.strftime(GC_DATE_FORMAT)})
            return phantom.APP_SUCCESS, time_param

        # Otherwise update reference time as start time
        time_param.update({GC_REFERENCE_TIME_KEY: start_date})
        return phantom.APP_SUCCESS, time_param

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """Validate the provided input parameter value is a non-zero positive integer and returns the integer value of the parameter itself.

        Parameters:
            :param action_result: object of ActionResult class
            :param parameter: input parameter
            :param key: string value of parameter name
            :param allow_zero: indicator for given parameter that whether zero value is allowed or not
        Returns:
            :return: integer value of the parameter
        """
        try:
            parameter = int(parameter)

            if parameter <= 0:
                if allow_zero:
                    if parameter < 0:
                        action_result.set_status(phantom.APP_ERROR, GC_LIMIT_VALIDATION_ALLOW_ZERO_MSG.format(parameter=key))
                        return None
                else:
                    action_result.set_status(phantom.APP_ERROR, GC_LIMIT_VALIDATION_MSG.format(parameter=key))
                    return None
        except Exception as e:
            self.debug_print(f"Integer validation failed. Error occurred while validating integer value. Error: {str(e)}")
            error_text = GC_LIMIT_VALIDATION_ALLOW_ZERO_MSG.format(parameter=key) if allow_zero else GC_LIMIT_VALIDATION_MSG.format(parameter=key)
            action_result.set_status(phantom.APP_ERROR, error_text)
            return None

        return parameter

    def _validate_comma_separated(self, action_result, comma_separated_int, key, is_date=False):
        """Validate the comma-separated integer values which indication minimum and maximumm value.

        Parameters:
            :param action_result: object of ActionResult class
            :param comma_separated_int: string value of comma-separted integer values
            :param key: string value of parameter name
            :param is_date: check for value is date string or not (by default work for integer)
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), list of values
        """
        # Extract values by splitting with comma
        comma_separated_list = [x.strip() for x in comma_separated_int.split(',')]
        comma_separated_list = list(filter(None, comma_separated_list))

        # Check for the values that it must specify only minimum and maximum value (means length 2)
        if len(comma_separated_list) != 2:
            if is_date:
                return action_result.set_status(phantom.APP_ERROR, GC_ON_POLL_INVALID_TIME_ERROR), None
            return action_result.set_status(phantom.APP_ERROR, GC_INT_RANGE_CONFIDENCE_ERROR.format(key)), None

        if is_date:
            # Works for comma-separated string date values
            ret_val, start_date, end_date = self._validate_time_params(action_result, comma_separated_list[0], comma_separated_list[1])
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            return phantom.APP_SUCCESS, [start_date, end_date]

        # Works for comma-separated integers values
        int_value = list(map(lambda a: self._validate_integers(action_result, a, key, allow_zero=True), comma_separated_list))

        if None in int_value:
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, int_value

    def _validate_json(self, action_result, parameter, key, is_dict=False, is_lower=True):
        """Validate the provided input parameter value is a valid JSON formatted list/dictionary or not.

        Parameters:
            :param action_result: object of ActionResult class
            :param parameter: input parameter
            :param key: string value of parameter name
            :param is_dict: indicator for json that whether it should validate as valid JSON list or dictionary
                Default is False means it will work for list type by validating it.
            :param is_lower: indicator for JSON formatted list that all string values of list should be in lower case or not
                Default is True means it will always return lower case string values in list type.
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), list
        """
        # Initialize value
        value = []
        if is_dict:
            value = {}

        # Try to load the JSON
        try:
            if parameter:
                if is_dict:
                    # Load the json value
                    value = json.loads(parameter, strict=False)
                    # Check for valid JSON dictionary if is_dict is set to True
                    if not isinstance(value, dict):
                        return action_result.set_status(phantom.APP_ERROR, GC_INVALID_DICT_JSON_ERR.format(key)), None
                else:
                    # Load the json value
                    value = json.loads(parameter)
                    # Check for valid JSON formatted list if is_dict is not set
                    if not isinstance(value, list):
                        return action_result.set_status(phantom.APP_ERROR, GC_INVALID_LIST_JSON_ERR.format(key)), None
                    # Remove empty values from the list
                    value = list(filter(None, value))
                    # Convert whole list of strings to lowercase if is_lower is set to True
                    if is_lower:
                        value = list(map(lambda x: x.lower(), value))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, GC_JSON_ERROR.format(key, f"Error : {str(e)}")), None

        return phantom.APP_SUCCESS, value

    def _validate_reputation_config(self, action_result):
        """Validate the configuration parameters which specified for the reputation actions.

        Parameters:
            :param action_result: object of ActionResult class
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), error message if created else None
        """
        # Initialize variables
        error_int = str()
        error_list = str()
        error_msg = str()
        error_msg_list = list()
        error_int_score = list()

        # Get the asset config
        config = self.get_config()

        susp_int_confidence = config.get("suspicious_int_confidence_score")
        mal_int_confidence = config.get("malicious_int_confidence_score")

        ret_val, self._malicious_category = self._validate_json(action_result, config.get("malicious_category"), GC_CONFIG_MALICIOUS_CATEGORY)
        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            error_msg_list.append("malicious_category")

        ret_val, self._malicious_severity = self._validate_json(action_result, config.get("malicious_severity"), GC_CONFIG_MALICIOUS_SEVERITY)
        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            error_msg_list.append("malicious_severity")

        ret_val, self._malicious_str_confidence = self._validate_json(action_result, config.get("malicious_str_confidence_score"), GC_CONFIG_MALICIOUS_STR_CONFIDENCE)
        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            error_msg_list.append("malicious_str_confidence_score")

        if mal_int_confidence:
            ret_val, self._malicious_int_confidence = self._validate_comma_separated(action_result, mal_int_confidence, GC_CONFIG_MALICIOUS_INT_CONFIDENCE)
            if phantom.is_fail(ret_val):
                self.debug_print(action_result.get_message())
                error_int_score.append("malicious_int_confidence_score")

        ret_val, self._suspicious_category = self._validate_json(action_result, config.get("suspicious_category"), GC_CONFIG_SUSPICIOUS_CATEGORY)
        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            error_msg_list.append("suspicious_category")

        ret_val, self._suspicious_severity = self._validate_json(action_result, config.get("suspicious_severity"), GC_CONFIG_SUSPICIOUS_SEVERITY)
        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            error_msg_list.append("suspicious_severity")

        ret_val, self._suspicious_str_confidence = self._validate_json(action_result, config.get("suspicious_str_confidence_score"), GC_CONFIG_SUSPICIOUS_STR_CONFIDENCE)
        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            error_msg_list.append("suspicious_str_confidence_score")

        if susp_int_confidence:
            ret_val, self._suspicious_int_confidence = self._validate_comma_separated(action_result, susp_int_confidence, GC_CONFIG_SUSPICIOUS_INT_CONFIDENCE)
            if phantom.is_fail(ret_val):
                self.debug_print(action_result.get_message())
                error_int_score.append("suspicious_int_confidence_score")

        # Join all the keys which have incorrect format value
        if error_msg_list:
            error_list = GC_INVALID_LIST_JSON_ERR.format(", ".join(error_msg_list))
            error_msg = f"{error_msg} {error_list}"

        if error_int_score:
            error_int = GC_INT_RANGE_CONFIDENCE_ERROR.format(", ".join(error_int_score))
            error_msg = f"{error_msg} {error_int}"

        # Any of the given reputation asset config parameter values has incorrect format
        if error_msg:
            return phantom.APP_ERROR, error_msg

        return phantom.APP_SUCCESS, None

    def _check_malicious_reputation(self, source):
        """Check for the malicious reputation type using received IoC source.

        Parameters:
            :param source: dictionary of received IoC source
        Returns:
            :return: reputation
        """
        # Initialize variables
        reputation = None
        str_confidence = None
        int_confidence = None
        confidence_score = source.get("confidenceScore", {}).get("strRawConfidenceScore", '').lower()

        # Fetch reputation definition details from the source
        category = source.get("category", '').lower()
        severity = source.get("rawSeverity", '').lower()
        if not confidence_score.isdigit():
            str_confidence = confidence_score
        else:
            int_confidence = confidence_score

        # Check for malicious reputation type
        check = list()
        check.append(category in self._malicious_category)
        check.append(severity in self._malicious_severity)
        check.append(str_confidence in self._malicious_str_confidence)
        if self._malicious_int_confidence:
            check.append(int_confidence and min(self._malicious_int_confidence) <= int(int_confidence) <= max(self._malicious_int_confidence))

        # Check for any of the above condition is true or not
        if any(check):
            reputation = "Malicious"

        return reputation

    def _check_suspicious_reputation(self, source):
        """Check for the suspicious reputation type using received IoC source.

        Parameters:
            :param source: dictionary of received IoC source
        Returns:
            :return: reputation
        """
        # Initialize variables
        reputation = None
        str_confidence = None
        int_confidence = None
        confidence_score = source.get("confidenceScore", {}).get("strRawConfidenceScore", '').lower()

        # Fetch reputation definition details from the source
        category = source.get("category", '').lower()
        severity = source.get("rawSeverity", '').lower()
        if not confidence_score.isdigit():
            str_confidence = confidence_score
        else:
            int_confidence = confidence_score

        # Check for suspicious reputation type
        check = list()
        check.append(category in self._suspicious_category)
        check.append(severity in self._suspicious_severity)
        check.append(str_confidence in self._suspicious_str_confidence)
        if self._suspicious_int_confidence:
            check.append(int_confidence and min(self._suspicious_int_confidence) <= int(int_confidence) <= max(self._suspicious_int_confidence))

        # Check for any of the above condition is true or not
        if any(check):
            reputation = "Suspicious"

        return reputation

    def _define_reputation_type(self, action_result, reputation_resp):
        """Validate the configuration parameters which specified for the reputation actions.

        Parameters:
            :param action_result: object of ActionResult class
            :param reputation_resp: response of make rest call with sources
        Returns:
            :return: reputation
        """
        # IoC sources
        sources = reputation_resp.get("sources")
        reputation = "Unknown"

        for source in sources:
            # Check for malicious reputation
            value = self._check_malicious_reputation(source)
            if value:
                reputation = value
                break
            # Check for suspicious reputation
            value = self._check_suspicious_reputation(source)
            if value:
                reputation = value
                break

        return reputation

    def _create_client(self, action_result):
        """Create an HTTP client using supplied service account credentials and Chronicle API Scope.

        Parameters:
            :param action_result: object of ActionResult class
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), an HTTP client
        """
        # Initialize credentials and http client
        credentials = None
        http_client = None

        self.save_progress("Creating Chronicle API client...")
        # Create a credential using Google Developer Service Account Credential and Chronicle API Scope.
        try:
            credentials = service_account.Credentials.from_service_account_info(self._key_dict, scopes=self._scopes)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Unable to create load the key json. Error: {str(e)}"), None

        # Build an HTTP client which can make authorized OAuth requests.
        try:
            http_client = _auth.authorized_http(credentials)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Unable to create client. Error: {str(e)}"), None

        return phantom.APP_SUCCESS, http_client

    def _parse_error_message(self, action_result, error):
        """Extract error message from error object.

        Parameters:
            :param action_result: object of ActionResult class
            :param error: error bytes response to be parsed
        Returns:
            :return: error message
        """
        # Try to load error json
        try:
            json_error = json.loads(error)
        except json.decoder.JSONDecodeError:
            self.debug_print(f'{GC_INVALID_ERR_RESPONSE_FORMAT} Response - {error}')
            return GC_INVALID_ERR_RESPONSE_FORMAT
        except Exception as e:
            return f"{GC_INVALID_ERR_RESPONSE_FORMAT} Error: {str(e)}"

        # Fetch error code
        error_code = json_error.get('error', {}).get('code')

        if error_code == 403:
            return f'Error code: {error_code}. Permission denied'

        # Create error message
        msg = json_error.get('error', {}).get('message', '')
        if error_code:
            err_msg = f"Error code: {error_code}. Error message: {msg}"
        else:
            err_msg = f"Error message: {msg}"

        return err_msg

    def _generate_event_summary(self, response):
        """Generate event summary for the response.

        Parameters:
            :param response : dictionary of response
        Returns:
            :return: response
        """
        # Derive events summary
        summary = defaultdict(lambda: 0)
        for event in response.get('events', []):
            if event.get("metadata", {}).get("eventType"):
                summary[event["metadata"]["eventType"]] += 1

        # Adding events summary to response
        response["eventsSummary"] = list()
        for key, value in list(summary.items()):
            response["eventsSummary"].append({"eventType": key, "count": value})

        return response

    def _generate_alert_assets_association(self, alerts_assets_association):
        """Generate alert assets association.

        Parameters:
            :param alerts_assets_association : dictionary of alerts assets response created from alerts response
        Returns:
            :return: alerts assets association list
        """
        alerts_assets_association_list = list()
        for alert_name, alert_asset_detail in list(alerts_assets_association.items()):
            affected_assets = dict()
            cnt = 0
            for key, value in list(alert_asset_detail.items()):
                affected_assets[key] = list(value)
                cnt += len(list(value))

            alerts_assets_association_list.append({"alert_name": alert_name, "affected_assets": affected_assets, "asset_count": cnt})
        return alerts_assets_association_list

    def _generate_alert_users_association(self, alerts_users_association):
        """Generate alert users association.

        Parameters:
            :param alerts_users_association : dictionary of alerts users response created from alerts response
        Returns:
            :return: alerts users association list
        """
        alerts_users_association_list = list()
        for alert_name, alert_user_detail in list(alerts_users_association.items()):
            affected_users = dict()
            cnt = 0
            for key, value in list(alert_user_detail.items()):
                affected_users[key] = list(value)
                cnt += len(list(value))

            alerts_users_association_list.append({"alert_name": alert_name, "affected_users": affected_users, "user_count": cnt})
        return alerts_users_association_list

    def _generate_alert_summary(self, response):
        """Generate asset alert summary and alert assets association for the asset alerts response.

        Parameters:
            :param response: dictionary of response
        Returns:
            :return: asset alerts response with summary
        """
        alerts_assets_association = defaultdict(lambda: {"hostname": set(), "assetIpAddress": set(), "mac": set(), "productId": set()})
        response_with_summary = dict()
        asset_alerts = list()

        for asset in response.get("alerts", []):
            alert_summary_asset = defaultdict(list)
            alert_summary_list = list()
            asset_key = None
            asset_value = None

            for key, value in list(asset.get("asset", {}).items()):
                asset_key = key
                asset_value = value

            for alert_info in asset.get("alertInfos", []):
                timestamp = alert_info.get("timestamp")
                timestamp_list = [timestamp] if timestamp else []
                alert_summary_asset[alert_info.get("name")].extend(timestamp_list)

                if alerts_assets_association[alert_info.get("name")].get(asset_key):
                    alerts_assets_association[alert_info.get("name")][asset_key].add(asset_value)
                else:
                    alerts_assets_association[alert_info.get("name")][asset_key] = set({asset_value})

            for key, value in list(alert_summary_asset.items()):
                alert_summary_list.append({"name": key, "occurrences": value, "count": len(value)})

            asset["alertSummary"] = alert_summary_list
            asset_alerts.append(asset)

        response_with_summary["alerts"] = asset_alerts
        response_with_summary["alerts_assets_association"] = self._generate_alert_assets_association(alerts_assets_association)

        return response_with_summary

    def _generate_user_alerts_summary(self, response):
        """Generate user alerts summary and alert users association for the user alerts response.

        Parameters:
            :param response: dictionary of response
        Returns:
            :return: user alerts response with summary
        """
        alerts_users_association = defaultdict(lambda: {"email": set(), "username": set()})
        response_with_summary = dict()
        user_alerts = list()

        for user in response.get("userAlerts", []):
            alert_summary_user = defaultdict(list)
            alert_summary_list = list()
            user_key = None
            user_value = None

            for key, value in list(user.get("user", {}).items()):
                user_key = key
                user_value = value

            for alert_info in user.get("alertInfos", []):
                timestamp = alert_info.get("timestamp")
                timestamp_list = [timestamp] if timestamp else []
                alert_summary_user[alert_info.get("name")].extend(timestamp_list)

                if alerts_users_association[alert_info.get("name")].get(user_key):
                    alerts_users_association[alert_info.get("name")][user_key].add(user_value)
                else:
                    alerts_users_association[alert_info.get("name")][user_key] = set({user_value})

            for key, value in list(alert_summary_user.items()):
                alert_summary_list.append({"name": key, "occurrences": value, "count": len(value)})

            user["userAlertSummary"] = alert_summary_list
            user_alerts.append(user)

        response_with_summary["userAlerts"] = user_alerts
        response_with_summary["alerts_users_association"] = self._generate_alert_users_association(alerts_users_association)

        return response_with_summary

    def _paginator(self, action_result, client, endpoint, end_time, limit=None):
        """Fetch results from multiple API calls using pagination for given endpoint.

        Parameters:
            :param action_result: object of ActionResult class
            :param client: object of HTTP client
            :param endpoint: REST endpoint that needs to appended to the service address
            :param end_time: end time for the search request
            :param limit : user specified maximum number of events to be returned

        Returns:
            :return: response
        """
        # Initialize variables
        uri = None      # Search URI variable
        first = True    # Flag to check that response is from the First API call or not
        results = list()

        fixed_endpoint = endpoint

        action_identifier = self.get_action_identifier()
        index = 1

        while True:
            endpoint = f"{fixed_endpoint}&end_time={end_time}"

            self.debug_print(f"Making {index} REST call for the {action_identifier} action")

            # Make REST call
            ret_val, response = self._make_rest_call(action_result, client, endpoint)
            if phantom.is_fail(ret_val):
                return ret_val, None, None

            events = response.get('events')
            # Only take search URI from the response of first API call
            if first:
                uri = response.get('uri', [''])[0]

            if not events:
                return phantom.APP_SUCCESS, results, uri

            end_time = events[0].get('metadata', {}).get('eventTimestamp')

            # Order the fetched events in the latest first order
            events.reverse()

            # Add new fetched events to previous events
            results.extend(events)

            if limit and len(results) >= limit:
                return phantom.APP_SUCCESS, results[:limit], uri

            # Check for next page
            if not response.get("moreDataAvailable") or not end_time:
                break

            # Mark first as False
            first = False
            index += 1

        return phantom.APP_SUCCESS, results, uri

    def _fetch_events(self, action_result, client, param, time_param):
        """Fetch events received from multiple API calls using pagination for given endpoint.

        Parameters:
            :param action_result: object of ActionResult class
            :param client: object of HTTP client
            :param param: Dictionary of input parameters
            :param time_param: time parameters dictionary which consists of time period details
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), response
        """
        # Fetch action parameters
        asset_indicator = param['asset_indicator']
        value = param['value']

        # Validate the 'limit' action parameter
        limit = self._validate_integers(action_result, param.get(GC_LIMIT_KEY, GC_DEFAULT_PAGE_SIZE), GC_LIMIT_KEY)
        if limit is None:
            return action_result.get_status(), None

        start_time = time_param[GC_START_TIME_KEY]
        end_time = time_param[GC_END_TIME_KEY]
        reference_time = time_param[GC_REFERENCE_TIME_KEY]

        # Set request parameters
        if asset_indicator == "Hostname":
            req_param = f"?asset.hostname={value}"
        elif asset_indicator == "Asset IP Address":
            req_param = f"?asset.asset_ip_address={value}"
        elif asset_indicator == "MAC Address":
            req_param = f"?asset.mac={value}"
        elif asset_indicator == "Product ID":
            req_param = f"?asset.product_id={value}"
        else:
            return action_result.set_status(phantom.APP_ERROR, "Unexpected value for the 'asset indicator' action parameter"), None

        endpoint = f"{GC_LIST_EVENTS_ENDPOINT}{req_param}&start_time={start_time}&reference_time={reference_time}&page_size=10000"

        # Call paginator
        ret_val, events, uri = self._paginator(action_result, client, endpoint, end_time, limit)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Response using pagination
        response = dict()
        response.update({'events': events})
        response.update({'uri': uri if uri else ""})

        return ret_val, response

    def _handle_test_connectivity(self, param):
        """Validate the asset configuration for connectivity using supplied configuration.

        Parameters:
            :param param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, client = self._create_client(action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(GC_UNABLE_CREATE_CLIENT_ERR)
            self.save_progress("Test Connectivity Failed")
            return ret_val

        self.save_progress("Note: Test connectivity action will not validate the other reputation and on poll related asset configuration \
            parameters for optimum performance and they are only validated in their respective actions.")
        self.save_progress("Making REST call to Chronicle for fetching the list of IoCs...")

        endpoint = "/v1/ioc/listiocs?start_time=1970-01-01T00:00:00Z&page_size=1"

        ret_val, _ = self._make_rest_call(action_result, client, endpoint)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_ioc_details(self, param):
        """Retrieve any threat intelligence associated with the specified artifact.

        Parameters:
            :param param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, client = self._create_client(action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(GC_UNABLE_CREATE_CLIENT_ERR)
            return ret_val

        # Fetch action parameters
        artifact_indicator = param['artifact_indicator']
        value = param['value']

        # Set request parameters
        if artifact_indicator == "Domain Name":
            req_param = f"?artifact.domain_name={value}"
        else:
            req_param = f"?artifact.destination_ip_address={value}"

        endpoint = f"{GC_LIST_IOC_DETAILS_ENDPOINT}{req_param}"

        ret_val, response = self._make_rest_call(action_result, client, endpoint)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add fetched data to action result object
        action_result.add_data(response)

        # try to fetch sources for the fetched IoC artifact
        try:
            sources = response.get("sources", [])
        except Exception as e:
            self.debug_print(f"Error occurred while fetching sources from response. Error: {str(e)}")
            sources = None

        # Create summary
        summary = action_result.update_summary({})
        summary['total_sources'] = len(sources) if sources else 0

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_assets(self, param):
        """Get the list of the assets associated with the artifact.

        Parameters:
            :param param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, client = self._create_client(action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(GC_UNABLE_CREATE_CLIENT_ERR)
            return ret_val

        # Fetch action parameters
        artifact_indicator = param['artifact_indicator']
        value = param['value']

        # Validate the 'limit' action parameter
        limit = self._validate_integers(action_result, param.get(GC_LIMIT_KEY, GC_DEFAULT_PAGE_SIZE), GC_LIMIT_KEY)
        if limit is None:
            return action_result.get_status()

        # Time period calculation
        ret_val, time_param = self._validate_time_related_params(action_result, param)
        if phantom.is_fail(ret_val):
            self.debug_print(GC_PARSE_TIME_PARAM_ERROR)
            return ret_val

        # Fetch time period
        start_time = time_param[GC_START_TIME_KEY]
        end_time = time_param[GC_END_TIME_KEY]

        # Set request parameters
        if artifact_indicator == "Domain Name":
            req_param = f"?artifact.domain_name={value}"
        elif artifact_indicator == "Destination IP Address":
            req_param = f"?artifact.destination_ip_address={value}"
        elif artifact_indicator == "MD5":
            req_param = f"?artifact.hash_md5={value}"
        elif artifact_indicator == "SHA1":
            req_param = f"?artifact.hash_sha1={value}"
        elif artifact_indicator == "SHA256":
            req_param = f"?artifact.hash_sha256={value}"
        else:
            return action_result.set_status(phantom.APP_ERROR, "Unexpected value for the 'artifact indicator' action parameter")

        endpoint = f"{GC_LIST_ASSETS_ENDPOINT}{req_param}&start_time={start_time}&end_time={end_time}&page_size={limit}"

        ret_val, response = self._make_rest_call(action_result, client, endpoint)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add fetched data to action result object
        action_result.add_data(response)

        # try to fetch assets for the specified IoC artifact
        try:
            assets = response.get("assets", [])
        except Exception as e:
            self.debug_print(f"Error occurred while fetching assets from the response. Error: {str(e)}")
            assets = None

        # Create summary
        summary = action_result.update_summary({})
        summary['total_assets'] = len(assets) if assets else 0

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_events(self, param):
        """List all of the events discovered within the enterprise on a particular device within the specified time range.

        Parameters:
            :param param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, client = self._create_client(action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(GC_UNABLE_CREATE_CLIENT_ERR)
            return ret_val

        # Time period calculation
        ret_val, time_param = self._validate_time_related_params(action_result, param, flag=True)
        if phantom.is_fail(ret_val):
            self.debug_print(GC_PARSE_TIME_PARAM_ERROR)
            return action_result.get_status()

        # Fetch events
        ret_val, response = self._fetch_events(action_result, client, param, time_param)
        if phantom.is_fail(ret_val):
            return ret_val

        # Generate summary for alerts response
        try:
            if response.get('events', []):
                response = self._generate_event_summary(response)
        except Exception as e:
            self.debug_print(f"Error occurred while generating events summary. Error: {str(e)}")

        # Add fetched data to action result object
        action_result.add_data(response)

        # try to fetch sources for the fetched events
        try:
            events = response.get("events", [])
        except Exception as e:
            self.debug_print(f"Error occurred while fetching events from the response. Error: {str(e)}")
            events = None

        # Create summary
        summary = action_result.update_summary({})
        summary['total_events'] = len(events) if events else 0

        return action_result.set_status(phantom.APP_SUCCESS)

    def _fetch_iocs(self, action_result, client, start_time, limit):
        """Fetch all of the IoCs discovered within the enterprise within the specified time and limit.

        Parameters:
            :param action_result: object of ActionResult class
            :param client: object of HTTP client
            :param start_time: start time for search request
            :param limit: page size for request
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), response
        """
        # Set request parameters with IoCs endpoint
        endpoint = f"{GC_LIST_IOCS_ENDPOINT}?start_time={start_time}&page_size={limit}"

        # Make REST call
        self.debug_print(f"IoCs endpoint query for search: {endpoint}")
        self.save_progress(f"IoCs endpoint query for search: {endpoint}")
        ret_val, response = self._make_rest_call(action_result, client, endpoint)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, response

    def _handle_list_iocs(self, param):
        """List of all of the IoCs discovered within the enterprise within the specified time range.

        Parameters:
            :param param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, client = self._create_client(action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(GC_UNABLE_CREATE_CLIENT_ERR)
            return ret_val

        # Fetch action parameters
        ret_val, time_param = self._validate_time_related_params(action_result, param)
        if phantom.is_fail(ret_val):
            self.debug_print(GC_PARSE_TIME_PARAM_ERROR)
            return action_result.get_status()

        # Fetch start time
        start_time = time_param[GC_START_TIME_KEY]

        # Validate the 'limit' action parameter
        limit = self._validate_integers(action_result, param.get(GC_LIMIT_KEY, GC_DEFAULT_PAGE_SIZE), GC_LIMIT_KEY)
        if limit is None:
            return action_result.get_status()

        # Fetch IoCs
        ret_val, response = self._fetch_iocs(action_result, client, start_time, limit)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add fetched data to action result object
        action_result.add_data(response)

        # try to fetch all iocs
        try:
            iocs = response.get("response", {}).get("matches", [])
        except Exception as e:
            self.debug_print(f"Error occurred while fetching IoC matches from the response. Error: {str(e)}")
            iocs = None

        # Create summary
        iocs_count = len(iocs) if iocs else 0
        summary = action_result.update_summary({})
        summary['total_iocs'] = iocs_count

        return action_result.set_status(phantom.APP_SUCCESS, f"Total IoCs: {iocs_count}")

    def _handle_domain_reputation(self, param):
        """Retrieve any threat intelligence associated with the specified domain artifact and define its reputation.

        Parameters:
            :param param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, client = self._create_client(action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(GC_UNABLE_CREATE_CLIENT_ERR)
            return ret_val

        # Validate specified reputation related asset configuration parameters
        ret_val, err = self._validate_reputation_config(action_result)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, err)

        # Fetch action parameters
        domain_name = param['domain_name']

        # Set request parameters
        req_param = f"?artifact.domain_name={domain_name}"

        endpoint = f"{GC_LIST_IOC_DETAILS_ENDPOINT}{req_param}"

        ret_val, response = self._make_rest_call(action_result, client, endpoint)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Define reputation based on sources
        if response.get("sources"):
            reputation = self._define_reputation_type(action_result, response)
            response.update({"reputation": reputation})

        # Add response data to action result object
        action_result.add_data(response)

        # Create summary
        summary = action_result.update_summary({})
        summary['reputation'] = response.get("reputation", "Unknown")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_reputation(self, param):
        """Retrieve any threat intelligence associated with the specified IP artifact and define its reputation.

        Parameters:
            :param param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, client = self._create_client(action_result)
        if phantom.is_fail(ret_val):
            self.debug_print(GC_UNABLE_CREATE_CLIENT_ERR)
            return ret_val

        # Validate specified reputation related asset configuration parameters
        ret_val, err = self._validate_reputation_config(action_result)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, err)

        # Fetch action parameters
        destination_ip_address = param['destination_ip_address']

        # Set request parameters
        req_param = f"?artifact.destination_ip_address={destination_ip_address}"

        endpoint = f"{GC_LIST_IOC_DETAILS_ENDPOINT}{req_param}"

        ret_val, response = self._make_rest_call(action_result, client, endpoint)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Define reputation based on sources
        if response.get("sources"):
            reputation = self._define_reputation_type(action_result, response)
            response.update({"reputation": reputation})

        # Add response data to action result object
        action_result.add_data(response)

        # Create summary
        summary = action_result.update_summary({})
        summary["reputation"] = response.get("reputation", "Unknown")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _fetch_alerts(self, action_result, client, start_time, end_time, limit):
        """Fetch all of the security alerts tracked within the enterprise within the specified time and limit.

        Parameters:
            :param action_result: object of ActionResult class
            :param client: object of HTTP client
            :param start_time: start time for search request
            :param end_time: end time for search request
            :param limit: page size for request
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), response
        """
        # Create endpoint with request parameters
        endpoint = f"{GC_LIST_ALERTS_ENDPOINT}?start_time={start_time}&end_time={end_time}&page_size={limit}"

        # Make REST call
        self.debug_print(f"Alerts endpoint query for search: {endpoint}")
        self.save_progress(f"Alerts endpoint query for search: {endpoint}")
        ret_val, response = self._make_rest_call(action_result, client, endpoint)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, response

    def _handle_list_alerts(self, param):
        """List all of the security alerts tracked within the enterprise on particular assets for the specified time range.

        Parameters:
            :param param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, client = self._create_client(action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(GC_UNABLE_CREATE_CLIENT_ERR)
            return ret_val

        # Validate the 'limit' action parameter
        limit = self._validate_integers(action_result, param.get(GC_LIMIT_KEY, GC_DEFAULT_PAGE_SIZE), GC_LIMIT_KEY)
        if limit is None:
            return action_result.get_status()

        # Time period calculation
        ret_val, time_param = self._validate_time_related_params(action_result, param)
        if phantom.is_fail(ret_val):
            self.debug_print(GC_PARSE_TIME_PARAM_ERROR)
            return action_result.get_status()

        # Fetch time period
        start_time = time_param[GC_START_TIME_KEY]
        end_time = time_param[GC_END_TIME_KEY]

        # Fetch alerts
        ret_val, response = self._fetch_alerts(action_result, client, start_time, end_time, limit)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        alert_type = param.get(GC_ALERT_TYPE_KEY, 'All')

        # Generate summary for alerts response
        try:
            response_data = dict()
            if alert_type in GC_ASSET_ALERTS_MODE and response.get('alerts', []):
                response_data.update(self._generate_alert_summary(response))
            if alert_type in GC_USER_ALERTS_MODE and response.get('userAlerts', []):
                response_data.update(self._generate_user_alerts_summary(response))
        except Exception as e:
            self.debug_print(f"Error occurred while generating alerts summary. Error: {str(e)}")

        # Add fetched data to action result object
        action_result.add_data(response_data)

        # try to fetch the fetched alerts
        try:
            asset_alerts = response_data.get("alerts", [])
            user_alerts = response_data.get("userAlerts", [])
        except Exception as e:
            self.debug_print(f"Error occurred while fetching alerts from the response. Error: {str(e)}")
            asset_alerts = []

        asset_alert_count = 0
        for alert in asset_alerts:
            asset_alert_count += len(alert.get('alertInfos', []))

        user_alert_count = 0
        for alert in user_alerts:
            user_alert_count += len(alert.get('alertInfos', []))

        # Create summary
        summary = action_result.update_summary({})
        if alert_type in GC_ASSET_ALERTS_MODE:
            summary['total_assets_with_alerts'] = len(asset_alerts)
            summary['total_asset_alerts'] = asset_alert_count
        if alert_type in GC_USER_ALERTS_MODE:
            summary['total_users_with_alerts'] = len(user_alerts)
            summary['total_user_alerts'] = user_alert_count

        return action_result.set_status(phantom.APP_SUCCESS)

    def _paginator_for_v2_apis(self, action_result, client, endpoint, data_subject, limit=None):
        """Fetch results using multiple API calls for v2 API endpoints.

        Parameters:
            :param action_result: object of ActionResult class
            :param client: object of HTTP client
            :param endpoint: REST endpoint that needs to appended to the service address
            :param data_subject: key to be fetched from the JSON response
            :param limit: maximum number of results to fetch

        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), response
        """
        fixed_endpoint = endpoint
        page_token = ''
        results = list()

        action_identifier = self.get_action_identifier()
        index = 1

        while True:
            endpoint = f"{fixed_endpoint}&pageToken={page_token}"

            self.debug_print(f"Making {index} REST call for the {action_identifier} action")

            # Make REST call
            ret_val, response = self._make_rest_call(action_result, client, endpoint)

            if phantom.is_fail(ret_val):
                return ret_val, results

            if not response:
                return phantom.APP_SUCCESS, results

            results.extend(response.get(data_subject, []))
            if limit and len(results) >= limit:
                return phantom.APP_SUCCESS, results[:limit]

            if response.get('nextPageToken'):
                page_token = response['nextPageToken']
            else:
                break
            index += 1

        return phantom.APP_SUCCESS, results

    def _fetch_rules(self, action_result, client, limit=None):
        """Fetch a list of all the rules discovered within your enterprise.

        Parameters:
            :param action_result: object of ActionResult class
            :param client: object of HTTP client
            :param limit: total rules to fetch
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), response
        """
        # Create list rules endpoint

        endpoint = f'{GC_LIST_RULES_ENDPOINT}?pageSize=1000'

        # Call Paginator for v2 APIs
        ret_val, rules = self._paginator_for_v2_apis(action_result, client, endpoint, data_subject='rules', limit=limit)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, rules

    def _handle_list_rules(self, param):
        """Get a list of all the rules discovered within your enterprise.

        Parameters:
            :param param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, client = self._create_client(action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(GC_UNABLE_CREATE_CLIENT_ERR)
            return action_result.get_status()

        # Validate the 'limit' action parameter
        limit = self._validate_integers(action_result, param.get(GC_LIMIT_KEY, 1000), GC_LIMIT_KEY)
        if limit is None:
            return action_result.get_status()

        # Fetch alerts
        ret_val, rules = self._fetch_rules(action_result, client, limit)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(
            {
                "rules": rules
            }
        )

        # Create summary
        summary = action_result.update_summary({})
        summary['total_rules'] = len(rules)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _fetch_detections(self, action_result, client, rule_ids, alert_state, time_param, limit=None):
        """Fetch a list of detections for the specified version of the given rule that is created in the Chronicle Detection Engine.

        Parameters:
            :param action_result: object of ActionResult class
            :param client: object of HTTP client
            :param rule_ids: rule_ids for which the detections need to be fetched
            :param alert_state: fetch ALERTING|NOT_ALERTING|ALL detections
            :param time_param: dictionary containing start_time and end_time
            :param limit: total detections to fetch
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), detections_data
        """
        start_time = time_param[GC_START_TIME_KEY]
        end_time = time_param[GC_END_TIME_KEY]

        # Create list rules endpoint
        fixed_endpoint = f'{GC_LIST_DETECTIONS_ENDPOINT}?pageSize=1000&detectionStartTime={start_time}&detectionEndTime={end_time}'

        if alert_state != 'ALL':
            fixed_endpoint += f'&alert_state={alert_state}'

        detections_data = {
            "detections_summary": list(),
            "detections": list(),
            "invalid_rule_ids": list(),
            "rule_ids_with_partial_detections": list()
        }

        all_invalid_rule_ids = True

        for rule_id in rule_ids:
            endpoint = fixed_endpoint.format(rule_id=rule_id)

            self.debug_print(f"Detections endpoint query for search: {endpoint}")
            self.save_progress(f"Detections endpoint query for search: {endpoint}")

            # Call Paginator for v2 APIs
            ret_val, detections = self._paginator_for_v2_apis(action_result, client, endpoint, data_subject='detections', limit=limit)

            if phantom.is_success(ret_val):
                all_invalid_rule_ids = False
                detections_data['detections'].extend(detections)
                detections_data['detections_summary'].append(
                    {
                        'rule_id': rule_id,
                        'detections_count': len(detections)
                    }
                )
                self.debug_print(f"{alert_state} detections fetched for the {rule_id} rule ID: {len(detections)}")
            elif GC_RATE_LIMIT_EXCEEDED in action_result.get_message():
                all_invalid_rule_ids = False
                detections_data['detections'].extend(detections)
                detections_data['detections_summary'].append(
                    {
                        'rule_id': rule_id,
                        'detections_count': len(detections)
                    }
                )
                self.debug_print(f"{alert_state} detections fetched for the {rule_id} rule ID: {len(detections)}")
                detections_data['rule_ids_with_partial_detections'].append(
                    {
                        'rule_id': rule_id
                    }
                )
            else:
                detections_data['invalid_rule_ids'].append(
                    {
                        'rule_id': rule_id
                    }
                )

        if all_invalid_rule_ids:
            self.debug_print("Provided Rule ID(s) are invalid")
            return action_result.set_status(phantom.APP_ERROR, GC_INVALID_RULE_IDS_MSG), None

        return action_result.set_status(phantom.APP_SUCCESS), detections_data

    def _handle_list_detections(self, param):
        """List the detections for the specified version of the given rule that is created in the Chronicle Detection Engine.

        Parameters:
            :param param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, client = self._create_client(action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(GC_UNABLE_CREATE_CLIENT_ERR)
            return ret_val

        # Validate the 'limit' action parameter
        limit = self._validate_integers(action_result, param.get(GC_LIMIT_KEY, 10000), GC_LIMIT_KEY)

        if limit is None:
            return action_result.get_status()

        # Time period calculation
        ret_val, time_param = self._validate_time_related_params(action_result, param)

        if phantom.is_fail(ret_val):
            self.debug_print(GC_PARSE_TIME_PARAM_ERROR)
            return action_result.get_status()

        # Generate list of Rule IDs from the comma-separated string of rule_ids
        rule_ids = [rule_id.strip() for rule_id in param[GC_RULE_IDS_KEY].split(',')]
        rule_ids = set(filter(None, rule_ids))

        # Check for the scenario where only commas and|or spaces are provided in the rule_ids
        if not rule_ids:
            return action_result.set_status(phantom.APP_ERROR, GC_INVALID_RULE_IDS_MSG)

        alert_state = param.get(GC_ALERT_STATE_KEY, 'ALL')

        # Fetch detections
        ret_val, detections_data = self._fetch_detections(action_result, client, rule_ids, alert_state, time_param, limit)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add fetched data to action result object
        action_result.add_data(detections_data)

        # Create summary
        summary = action_result.update_summary({})
        summary['total_detections'] = len(detections_data["detections"])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_on_poll_params(self, action_result, config):
        """Validate the asset configuration parameters which specified for the on poll action.

        Parameters:
            :param action_result: object of ActionResult class
            :param config: Dictionary of asset configuration parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Fetch alert severity
        if GC_RM_ASSET_ALERTS in self._run_mode:
            ret_val, self._alerts_severity = self._validate_json(action_result, config.get("alerts_severity"), GC_CONFIG_ALERT_SEVERITY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        # Fetch Max artifacts limit for single container
        self._max_artifacts = self._validate_integers(
            action_result, config.get("max_artifacts", GC_DEFAULT_PAGE_SIZE), GC_CONFIG_MAX_ARTIFACTS)
        if self._max_artifacts is None:
            return action_result.get_status()

        # Fetch max results(page size) for the manual/scheduled poll
        if self._is_poll_now:
            self._max_results = self._validate_integers(
                action_result, config.get("max_results_poll_now", GC_DEFAULT_PAGE_SIZE), GC_CONFIG_MAX_LIMIT_POLL_NOW)
            if self._max_results is None:
                return action_result.get_status()
        else:
            self._max_results = self._validate_integers(
                action_result, config.get("max_results_scheduled_poll", GC_DEFAULT_PAGE_SIZE), GC_CONFIG_MAX_LIMIT_POLL)
            if self._max_results is None:
                return action_result.get_status()

        # Fetch and update the ingestion time period
        ret_val = self._derive_on_poll_time_period(action_result, config)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _derive_end_time(self, action_result, start_time):
        """Derive the end time using given start time.

        Parameters:
            :param action_result: object of ActionResult class
            :param start_time: object of start time
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), end time
        """
        # Check for given start time is not before 1970-01-01T00:00:00Z
        ret_val = self._check_invalid_since_utc_time(action_result, start_time)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, f"{action_result.get_message()} {GC_ON_POLL_INVALID_TIME_ERROR}"), None

        # Taking current UTC time as end time
        end_time = datetime.utcnow()

        # Checking future date
        if start_time >= end_time:
            return action_result.set_status(phantom.APP_ERROR, GC_GREATER_EQUAL_TIME_ERR.format(GC_CONFIG_TIME_POLL_NOW)), None

        return phantom.APP_SUCCESS, end_time

    def _validate_time_other_format(self, action_result, value):
        """Derive the start time and end time using given time range asset configuration parameter for other possible format.

        Parameters:
            :param action_result: object of ActionResult class
            :param value: value of the time range asset config parameter
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), list of time period
        """
        # Checking date format for 'start_time' format
        check, time = self._check_date_format(value)
        if not check:
            try:
                # Check date format for '<digit><d/h/m/s>' format
                if self._check_timerange(value.lower()):
                    # Derive time period using time range
                    ret_val, start_date, end_date = self._derive_time_period(action_result, value.lower())
                    if phantom.is_fail(ret_val):
                        return action_result.set_status(phantom.APP_ERROR, GC_ON_POLL_INVALID_TIME_ERROR), None

                    # Return time period
                    return phantom.APP_SUCCESS, [start_date, end_date]
                else:
                    # Given time range value not matched with any of the possible format of date
                    return action_result.set_status(phantom.APP_ERROR, GC_ON_POLL_INVALID_TIME_ERROR), None
            except OverflowError:
                return action_result.set_status(phantom.APP_ERROR, f"{GC_UTC_SINCE_TIME_ERROR} {GC_ON_POLL_INVALID_TIME_ERROR}"), None
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, f"{GC_ON_POLL_INVALID_TIME_ERROR} Error: {str(e)}"), None

        # Derive end time
        ret_val, end_time = self._derive_end_time(action_result, time)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, [time.strftime(GC_DATE_FORMAT), end_time.strftime(GC_DATE_FORMAT)]

    def _validate_time_range_poll_now(self, action_result, value):
        """Derive the start time and end time using given time range asset configuration parameter.

        Parameters:
            :param action_result: object of ActionResult class
            :param value: value of the time range asset config parameter
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), start date, end date
        """
        if "," in value:
            # Checking date format for 'start_time, end_time' format
            ret_val, time = self._validate_comma_separated(action_result, value, GC_CONFIG_TIME_RANGE_POLL_NOW, is_date=True)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None, None
            return phantom.APP_SUCCESS, time[0], time[1]
        else:
            # Checking date format for '<digit><d/h/m/s>' or 'start_time' format
            ret_val, time = self._validate_time_other_format(action_result, value)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None, None
            return phantom.APP_SUCCESS, time[0], time[1]

    def _backdate_start_time(self, start_time, backdate_time):
        """Backdate the start_time as selected by the user.

        Parameters:
            :param start_time: Start Time calculated for a given run_mode
            :param backdate_time: Backdate Time provided by the user (in <digit>m format)
        Returns:
            :return: start_time or updated start_time
        """
        if self._check_timerange(backdate_time.lower()):
            try:
                digit = int(backdate_time[:-1])
                # Currently backdate_time is only supported in minutes
                self.debug_print(f"Backdating start time by {digit} minutes")
                start_time = datetime.strptime(start_time, GC_DATE_FORMAT)
                start_time = start_time - timedelta(minutes=digit)
                start_time = start_time.strftime(GC_DATE_FORMAT)
                self.debug_print(f"Backdated the start_time to {start_time}")
            except Exception as e:
                self.debug_print(f"Failed to parse the backdate_time asset configuration parameter. Error: {str(e)}")
                self.debug_print(f"Skipping backdate_time and using the last_run_time. Error: {str(e)}")
                return start_time
        return start_time

    def _derive_on_poll_time_period(self, action_result, config):
        """Derive the time period using given asset configuration parameters.

        Parameters:
            :param action_result: object of ActionResult class
            :param config: Dictionary of asset configuration parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), dictionary with time details of on poll
        """
        # Initialize variable
        self._time_dict.update(
            {
                GC_RM_IOC_DOMAINS: dict(),
                GC_RM_ASSET_ALERTS: dict(),
                GC_RM_USER_ALERTS: dict(),
                GC_RM_ALERTING_DETECTIONS: dict(),
                GC_RM_NOT_ALERTING_DETECTIONS: dict(),
            }
        )

        # If manual poll check only for given time range and return with calculated time range as per given asset params
        if self._is_poll_now:
            # Fetch time period
            ret_val, start_time, end_time = self._validate_time_range_poll_now(action_result, config.get("time_range_poll_now", "3d"))
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            start_time_end_time_to_update = {
                GC_START_TIME_KEY: start_time,
                GC_END_TIME_KEY: end_time
            }
            self._time_dict = dict.fromkeys(self._time_dict, start_time_end_time_to_update)
            return phantom.APP_SUCCESS

        # Fetch start time for the scheduled run and
        # Check date format for '<digit><d/h/m/s>' or 'start_time' format for given 'start_time_scheduled_poll' asset config
        # It will return list of start time and end time
        # And this time list will use whenever we have to consider run as first run
        ret_val, time = self._validate_time_other_format(action_result, config.get("start_time_scheduled_poll", "1970-01-01T00:00:00Z"))

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # For scheduled or interval
        # Format for the last run keys should be consistent and should be for the form 'last_run_<run_mode>_time' (For run_mode refer chronicle_consts file)
        last_run_keys = ["last_run_ioc_time", "last_run_alert_time", "last_run_user_alert_time", "last_run_alerting_detection_time", "last_run_not_alerting_detection_time"]

        # Check for first run
        if not list(filter(lambda x: self._state.get(x) is not None, last_run_keys)):
            # First time scheduled/interval poll
            # Update time dictionary of on poll
            self.debug_print("Scheduled run for first time for any of the provided ingestion run")
            # Set first_run as True
            self._is_first_run = dict.fromkeys(self._is_first_run, True)
            # Set time parameter for the API call
            start_time_end_time_to_update = {
                GC_START_TIME_KEY: time[0],
                GC_END_TIME_KEY: time[1]
            }
            self._time_dict = dict.fromkeys(self._time_dict, start_time_end_time_to_update)
            return phantom.APP_SUCCESS

        # This part will use only when different ingestion run mode used in consecutive scheduled run
        for last_run_key in last_run_keys:
            # Set run_mode as per the last_run_key. Use string slicing for obtaining the run_mode
            # As len("last_run_") = 9, starting index should be 9 and as len("_time") = 5, stopping index should be -5
            run_mode = last_run_key[9:-5]
            last_run_value = self._state.get(last_run_key)

            if last_run_value:
                backdate_time = config.get("backdate_time", "15m")
                start_time = self._check_last_run_context(last_run_value, time[0], backdate_time, run_mode=run_mode)
                self._time_dict.update(
                    {
                        run_mode: {
                            GC_START_TIME_KEY: start_time,
                            GC_END_TIME_KEY: time[1]
                        }
                    }
                )
            else:
                self.debug_print(f"Scheduled run for first time for {run_mode.replace('_', ' ').title()} ingestion run mode")
                self._time_dict.update(
                    {
                        run_mode: {
                            GC_START_TIME_KEY: time[0],
                            GC_END_TIME_KEY: time[1]
                        }
                    }
                )
                if run_mode in self._run_mode:
                    # Set first_run as True
                    self._is_first_run[run_mode] = True

        return phantom.APP_SUCCESS

    def _check_last_run_context(self, last_run_time, first_run_time, backdate_time, run_mode=None):
        """Check the last run context is in the correct format or not and set the start time and first run flag accordingly.

        Parameters:
            :param last_run_time: object of ActionResult class
            :param first_run_time: first run time for the on poll run mode
            :param backdate_time: Backdate time provided by the user to update the start_time of given run_mode
            :param run_mode: indicates the on poll run mode
        Returns:
            :return: start time of the search
        """
        # Initialize
        start_time = None
        first_run = False

        # Checking date format of retrieved date string from the state file
        self.debug_print(f"Check for '{run_mode.replace('_', ' ').title()}s'")
        self.debug_print(f"Check that string date value {last_run_time} fetched from the state file is in the correct format {GC_DATE_FORMAT} or not")
        # Check for date string format
        check, _ = self._check_date_format(last_run_time)
        if not check:
            self.debug_print("Considering as first run as retrieved time value from the state file is in incorrect format")
            first_run = True
            start_time = first_run_time
        else:
            self.debug_print("Considering the retrieved last_run_time value from the state file as the start_time for the next scheduled/interval poll")
            self.debug_print(f"Retrieved start_time for the {run_mode} run mode: {last_run_time}")
            # Next run for the scheduled/interval poll
            start_time = last_run_time
            # Backdate start_time to avoid late breaking in detections and alerts
            if run_mode != GC_RM_IOC_DOMAINS:
                start_time = self._backdate_start_time(last_run_time, backdate_time)

        # Set the flag for first run
        if first_run and run_mode in self._run_mode:
            self._is_first_run[run_mode] = True

        return start_time

    def _check_last_run_hash(self, last_run_hash, current_hash_to_update, response):
        """Generate the hash digest for the provided response and add it to the current hash digest list.

        Parameters:
            :param last_run_hash: List of last run hash digests
            :param current_hash_to_update: Current hash digest list to which the calculated list will be appended
            :param response: JSON response for which hash needs to be calculated
        Returns:
            :return: Status(True/False)
        """
        if not isinstance(response, dict):
            return False

        sha256_hex_digest = sha256(json.dumps(response).encode("utf-8")).hexdigest()
        current_hash_to_update.append(sha256_hex_digest)

        # If the calculated value is present in the last run hash digest, ignore it.
        if sha256_hex_digest in last_run_hash:
            self.debug_print("Response had already been ingested in the previous run")
            return True

        return False

    def _parse_user_alert_info(self, alert_infos, user):
        """Parse user_alert infos for particular user with alerts.

        Parameters:
            :param alert_infos: alert_infos list for particular user
            :param user: user details format is list type: [(<userIndicator>, <userValue>)]
        Returns:
            :return: parsed alerts
        """
        # Initialize user_alerts list
        user_alerts = list()

        last_run_user_alert_hash_digest = self._last_run_hash_digests.get(GC_RM_USER_ALERTS, list())
        curr_run_user_alert_hash_digest = list()

        for alert_info in alert_infos:
            # Create 'cef' type artifact for individual user alert by adding corresponding user infos with alert infos
            user_alert = {
                "userIndicator": user[0][0],
                "userValue": user[0][1],
                "alertName": alert_info.get("name", ""),
                "sourceProduct": alert_info.get("sourceProduct", ""),
                "timestamp": alert_info.get("timestamp", ""),
                "rawLog": alert_info.get("rawLog", ""),
                "uri": alert_info.get("uri", [""])[0],
                "udmEvent": alert_info.get("udmEvent")
            }
            # Check if the user_alert was already fetched and ingested in the previous run
            if not self._check_last_run_hash(last_run_user_alert_hash_digest, curr_run_user_alert_hash_digest, user_alert):
                user_alerts.append(user_alert)

        self._last_run_hash_digests[GC_RM_USER_ALERTS] = curr_run_user_alert_hash_digest

        return user_alerts

    def _parse_user_alerts_response(self, response):
        """Parse response of alerts with given ingestion asset configuration parameters.

        Parameters:
            :param response: object of alerts API call
        Returns:
            :return: parsed user alerts results
        """
        # Initialize alerts results
        user_alerts_results = list()

        # If response is not dictionary type
        if not isinstance(response, dict):
            return user_alerts_results

        # Fetch user_alerts from the response
        user_alerts = response.get('userAlerts', [])
        if not user_alerts:
            return user_alerts_results

        self.debug_print(f"Total user alerts fetched: {len(user_alerts)}")

        for user_alert in user_alerts:

            # Initialize results list
            results = list()
            # Fetch user information
            user = list(user_alert.get('user', {}).items())
            if not user:
                # Not received any kind of user details in the user with user_alerts dictionary
                # Hence marking userIndicator and userValue as empty string
                user = [("", "")]
            try:
                # Parse user_alerts infos for particular user
                results = self._parse_user_alert_info(user_alert.get('alertInfos', []), user)
            except Exception as e:
                self.debug_print(f"Exception occurred while parsing user_alerts response. Error: {str(e)}")
                self.debug_print(f"Ignoring user_alert infos for userIndicator: '{user[0][0]}' and userValue: '{user[0][1]}'")

            # Add user_alerts into final results
            user_alerts_results.extend(results)

        self.debug_print(f"Total parsed user alerts after deduplication: {len(user_alerts_results)}")

        return user_alerts_results

    def _parse_alert_info(self, alert_infos, asset):
        """Parse alert infos for particular asset with alerts.

        Parameters:
            :param alert_infos: alert_infos list for particular asset
            :param asset: asset details format is list type: [(<assetIndicator>, <assetValue>)]
        Returns:
            :return: parsed alerts
        """
        # Initialize alerts list
        alerts = list()

        last_run_alert_hash_digest = self._last_run_hash_digests.get(GC_RM_ASSET_ALERTS, list())
        curr_run_alert_hash_digest = list()

        for alert_info in alert_infos:
            # Ignore alerts which alert has configured severity to ingest
            if self._alerts_severity and alert_info.get('severity', '').lower() not in self._alerts_severity:
                self.debug_print(f"Ignored alert: {alert_info.get('name', '')} which has severity: {alert_info.get('severity', '')}")
                continue

            # Create 'cef' type artifact for individual alert by adding corresponding asset infos with alert infos
            alert = {
                "assetIndicator": asset[0][0],
                "assetValue": asset[0][1],
                "alertName": alert_info.get("name", ""),
                "sourceProduct": alert_info.get("sourceProduct", ""),
                "severity": alert_info.get("severity", ""),
                "timestamp": alert_info.get("timestamp", ""),
                "rawLog": alert_info.get("rawLog", ""),
                "uri": alert_info.get("uri", [""])[0],
                "udmEvent": alert_info.get("udmEvent")
            }

            # Check if the alert was already fetched and ingested in the previous run
            if not self._check_last_run_hash(last_run_alert_hash_digest, curr_run_alert_hash_digest, alert):
                alerts.append(alert)

        self._last_run_hash_digests[GC_RM_ASSET_ALERTS] = curr_run_alert_hash_digest

        return alerts

    def _parse_alerts_response(self, response):
        """Parse response of alerts with given ingestion asset configuration parameters.

        Parameters:
            :param response: object of alerts API call
        Returns:
            :return: parsed asset alerts results
        """
        # Initialize alerts results
        alerts_results = list()

        # If response is not dictionary type
        if not isinstance(response, dict):
            return alerts_results

        # Fetch alerts from the response
        alerts = response.get('alerts', [])
        if not alerts:
            return alerts_results

        self.debug_print(f"Total asset alerts fetched: {len(alerts)}")

        for alert in alerts:

            # Initialize results list
            results = list()
            # Fetch asset information
            asset = list(alert.get('asset', {}).items())
            if not asset:
                # Not received any kind of asset details in the asset with alerts dictionary
                # Hence marking assetIndicator and assetValue as empty string
                asset = [("", "")]
            try:
                # Parse alerts infos for particular asset
                results = self._parse_alert_info(alert.get('alertInfos', []), asset)
            except Exception as e:
                self.debug_print(f"Exception occurred while parsing alerts response. Error: {str(e)}")
                self.debug_print(f"Ignoring alert infos for assetIndicator: '{asset[0][0]}' and assetValue: '{asset[0][1]}'")

            # Add alerts into final results
            alerts_results.extend(results)

        self.debug_print(f"Total parsed asset alerts after deduplication: {len(alerts_results)}")

        return alerts_results

    def _parse_ioc_info(self, ioc, artifact):
        """Parse alert infos for particular asset with alerts.

        Parameters:
            :param ioc: IoC domain match
            :param artifact: asset details format is list type: [(<artifactIndicator>, <artifactValue>)]
        Returns:
            :return: parsed ioc result
        """
        # Initialize list of IoCs information
        sources = list()
        severity = list()
        category = list()
        confidence_str = list()
        confidence_int = list()

        # Parse information from received IoC sources
        for source in ioc.get('sources', []):
            sources.append(source.get('source', ''))
            confidence_str.append(source.get('confidenceScore', {}).get('normalizedConfidenceScore', 'unknown'))
            confidence_int.append(source.get('confidenceScore', {}).get('intRawConfidenceScore', 0))
            severity.append(source.get('rawSeverity', ''))
            category.append(source.get('category', ''))

        # Convert intRawConfidenceScore to str type from int type
        try:
            confidence_int = list(map(lambda x: str(x), confidence_int))
        except Exception as e:
            self.debug_print(f"Error occurred while converting intRawConfidenceScore value to 'str' type from 'int' type. Error: {str(e)}")
            self.debug_print(f"Ignoring intRawConfidenceScore value from all the sources for IoC domain: {artifact[0][1]}")
            # Ignore all the intRawConfidenceScore
            confidence_int = list()

        # Remove empty string values from the list of different sources details
        sources = list(filter(None, sources))
        confidence_str = list(filter(None, confidence_str))
        confidence_int = list(filter(None, confidence_int))
        severity = list(filter(None, severity))
        category = list(filter(None, category))

        # Create parsed IoC
        parsed_ioc = {
            'artifactIndicator': artifact[0][0],
            'artifactValue': artifact[0][1],
            'sources': ", ".join(sources),
            'normalizedConfidenceScore': ", ".join(confidence_str),
            'intRawConfidenceScore': ", ".join(confidence_int),
            'rawSeverity': ", ".join(severity),
            'category': ", ".join(category),
            'iocIngestTime': ioc.get("iocIngestTime", ""),
            'firstSeenTime': ioc.get("firstSeenTime", ""),
            'lastSeenTime': ioc.get("lastSeenTime", ""),
            'uri': ioc.get('uri', [''])[0],
            'rawJSON': json.dumps(ioc),
            'data': ioc
        }

        return parsed_ioc

    def _parse_iocs_response(self, response):
        """Parse response of iocs with given ingestion asset configuration parameters.

        Parameters:
            :param response: response dictionary of IoCs API call
        Returns:
            :return: parsed iocs results
        """
        # Initialize alerts results
        iocs_results = list()

        # If response is not dictionary type
        if not isinstance(response, dict):
            return iocs_results

        # Fetch alerts from the response
        iocs = response.get('response', {}).get('matches', [])
        if not iocs:
            return iocs_results

        self.debug_print(f"Total IoCs fetched: {len(iocs)}")

        for ioc in iocs:
            # Initialize result variable
            result = None
            # Fetch asset information
            artifact = list(ioc.get('artifact', {}).items())
            if not artifact:
                # Not received any artifact information for IoC domain matches
                # Hence marking artifactIndicator and artifactValue as empty string
                artifact = [("", "")]
            try:
                # Ingest only IoC domain matches
                if artifact[0][0] != "domainName":
                    self.debug_print("Ignore as retrieved IoCs is not domain matches")
                    self.debug_print(f"Received IoC artifactIndicator is {artifact[0][0]}")
                    continue
                # Parse IoC information
                result = self._parse_ioc_info(ioc, artifact)
            except Exception as e:
                self.debug_print(f"Exception occurred while parsing IoCs response. Error: {str(e)}")
                self.debug_print(f"Ignoring IoC match for artifactIndicator: '{artifact[0][0]}' and artifactValue: '{artifact[0][1]}'")

            # Add alerts into final results
            if result:
                iocs_results.append(result)

        self.debug_print(f"Total IoC domain matches parsed: {len(iocs_results)}")

        return iocs_results

    def _parse_collection_elements(self, collection_elements):
        """Parse Collection Elements to fetch the detections.

        Parameters:
            :param collection_elements: a list of dictionaries obtained from the detections response
        Returns:
            :return: parsed list of events
        """
        parsed_events = list()

        try:
            for element in collection_elements:
                label = element.get("label")
                refs = element.get("references")
                for ref in refs:
                    event = dict()
                    event.update(ref)
                    event['label'] = label
                    parsed_events.append(event)
        except Exception as e:
            self.debug_print(f"Error occurred while parsing the collectionEvents. Error: {str(e)}")
            self.debug_print("Returning the partially parsed events")
            return parsed_events

        return parsed_events

    def _parse_detections_response(self, response, run_mode):
        """Parse response of detections with given ingestion asset configuration parameters.

        Parameters:
            :param response: response dictionary of Detections API call
            :param run_mode: run_mode to differentiate ALERTING and NOT_ALERTING detections
        Returns:
            :return: parsed detections results
        """
        # Initialize alerts results
        parsed_detections = list()

        # If response is not dictionary type
        if not isinstance(response, dict):
            return parsed_detections

        # Fetch alerts from the response
        detections = response.get('detections', [])
        if not detections:
            return parsed_detections

        self.debug_print(f"Total {run_mode} detections fetched: {len(detections)}")

        invalid_rule_ids = response.get('invalid_rule_ids', [])
        rule_ids_with_partial_detections = response.get('rule_ids_with_partial_detections', [])

        if invalid_rule_ids:
            invalid_rule_ids_str = list(map(lambda invalid_rule: invalid_rule['rule_id'], invalid_rule_ids))
            invalid_rule_ids_str = ', '.join(invalid_rule_ids_str)
            self.debug_print(f"Following Rule ID(s) are not valid:\n{invalid_rule_ids_str}")
            self.debug_print("No detections were fetched for them")
            self.save_progress(f"Following Rule ID(s) are not valid:\n{invalid_rule_ids_str}")
            self.save_progress("No detections were fetched for them")

        if rule_ids_with_partial_detections:
            rule_ids_with_partial_detections_str = list(map(lambda rule_ids_with_partial_detection: rule_ids_with_partial_detection['rule_id'], rule_ids_with_partial_detections))
            rule_ids_with_partial_detections_str = ', '.join(rule_ids_with_partial_detections_str)
            self.debug_print(f"Detections maybe missing for the following Rule ID(s):\n{rule_ids_with_partial_detections_str}")
            self.debug_print(GC_RATE_LIMIT_EXCEEDED)
            self.save_progress(f"Detections maybe missing for the following Rule ID(s):\n{rule_ids_with_partial_detections_str}")
            self.save_progress(GC_RATE_LIMIT_EXCEEDED)

        last_run_detections_hash_digest = self._last_run_hash_digests.get(run_mode, list())
        curr_run_detections_hash_digest = list()

        for detection_info in detections:
            # Check if the detection was already fetched and ingested in the previous run
            if self._check_last_run_hash(last_run_detections_hash_digest, curr_run_detections_hash_digest, detection_info):
                continue
            collection_elements = detection_info.get("collectionElements", [])

            # Fetch asset information
            detection_details = detection_info.get('detection', [{}])[0]
            detection = {
                "detectionId": detection_info.get("id", ""),
                "detectionType": detection_info.get("type", GC_DEFAULT_DETECTION_TYPE),
                "ruleId": detection_details.get("ruleId", ""),
                "ruleName": detection_details.get("ruleName", ""),
                "versionId": detection_details.get("ruleVersion", ""),
                "alertState": detection_details.get("alertState", "").replace("_", " ").title(),
                "ruleType": detection_details.get("ruleType", ""),
                "detectionTime": detection_info.get("detectionTime", ""),
                "createdTime": detection_info.get("createdTime", ""),
                "events": self._parse_collection_elements(collection_elements),
                "uri": detection_details.get("urlBackToProduct", ""),
                "data": detection_info
            }

            # Add detections into parsed detections
            parsed_detections.append(detection)

        self._last_run_hash_digests[run_mode] = curr_run_detections_hash_digest

        self.debug_print(f"Total parsed {run_mode} detections after deduplication: {len(parsed_detections)}")

        return parsed_detections

    def _fetch_rules_and_detections(self, action_result, client, rule_ids, alert_state, time_param, limit):
        """Fetch a list of detections for the specified version of the given rule that is created in the Chronicle Detection Engine. This method will be used for On Poll action.

        Parameters:
            :param action_result: object of ActionResult class
            :param client: object of HTTP client
            :param rule_ids: rule_ids for which the detections need to be fetched
            :param alert_state: fetch ALERTING|NOT_ALERTING|ALL detections
            :param time_param: dictionary containing start_time and end_time
            :param limit: number of detections to fetch
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), response, rule_ids
        """
        config = self.get_config()
        fetch_live_rules = config.get("fetch_live_rules", True)

        # If rule_ids is an instance of set, then the rule_ids would already have been parsed
        if not isinstance(rule_ids, set):
            if fetch_live_rules:
                # fetch all rules and filter the live rules
                ret_val, response = self._fetch_rules(action_result, client)
                if phantom.is_fail(ret_val):
                    return action_result.get_status(), None, None
                filtered_rules = list(filter(lambda rule: rule.get("liveRuleEnabled") is True, response))
                rule_ids = set(map(lambda rule: rule.get("ruleId"), filtered_rules))
            else:
                # Generate list of Rule IDs from the comma-separated string of rule_ids
                rule_ids = [rule_id.strip() for rule_id in config.get("rule_ids", "").split(',')]
                rule_ids = set(filter(None, rule_ids))

        self.debug_print(f"Total rule ID(s) for which detections will be fetched: {len(rule_ids)}")

        ret_val, detections = self._fetch_detections(action_result, client, rule_ids, alert_state, time_param, limit)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None, None

        return phantom.APP_SUCCESS, detections, rule_ids

    def _fetch_results(self, action_result, client):
        """Fetch results of IoCs and alerts based on given ingestion asset configuration parameters.

        Parameters:
            :param action_result: object of ActionResult class
            :param client: object of HTTP client
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), dictionary of IoCs and alerts results
        """
        # Initialize results dictionary
        results = dict()

        results.update({
            GC_RM_IOC_DOMAINS: list(),
            GC_RM_ASSET_ALERTS: list(),
            GC_RM_USER_ALERTS: list(),
            GC_RM_ALERTING_DETECTIONS: list(),
            GC_RM_NOT_ALERTING_DETECTIONS: list()
        })

        self._last_run_hash_digests = self._state.get("last_run_hash_digests", dict())

        ret_val = phantom.APP_SUCCESS
        response = dict()

        # Fetch alerts data
        if GC_RM_ASSET_ALERTS in self._run_mode:
            start_time = self._time_dict[GC_RM_ASSET_ALERTS][GC_START_TIME_KEY]
            end_time = self._time_dict[GC_RM_ASSET_ALERTS][GC_END_TIME_KEY]
            ret_val, response = self._fetch_alerts(action_result, client, start_time, end_time, self._max_results)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Parse alerts response
        results.update({GC_RM_ASSET_ALERTS: self._parse_alerts_response(response)})
        response = dict()

        # Fetch user_alerts data
        if GC_RM_USER_ALERTS in self._run_mode:
            start_time = self._time_dict[GC_RM_ASSET_ALERTS][GC_START_TIME_KEY]
            end_time = self._time_dict[GC_RM_ASSET_ALERTS][GC_END_TIME_KEY]
            ret_val, response = self._fetch_alerts(action_result, client, start_time, end_time, self._max_results)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Parse IoCs response
        results.update({GC_RM_USER_ALERTS: self._parse_user_alerts_response(response)})
        response = dict()

        # Fetch IoCs data
        if GC_RM_IOC_DOMAINS in self._run_mode:
            start_time = self._time_dict[GC_RM_IOC_DOMAINS][GC_START_TIME_KEY]
            ret_val, response = self._fetch_iocs(action_result, client, start_time, self._max_results)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Parse IoCs response
        results.update({GC_RM_IOC_DOMAINS: self._parse_iocs_response(response)})
        response = dict()

        rule_ids = None

        # Fetch Alerting Detections data
        if GC_RM_ALERTING_DETECTIONS in self._run_mode:
            alert_state = "ALERTING"
            time_param = self._time_dict[GC_RM_ALERTING_DETECTIONS]
            ret_val, response, rule_ids = self._fetch_rules_and_detections(action_result, client, rule_ids, alert_state, time_param, self._max_results)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Parse Alerting Detections response
        results.update({GC_RM_ALERTING_DETECTIONS: self._parse_detections_response(response, run_mode=GC_RM_ALERTING_DETECTIONS)})
        response = dict()

        # Fetch Not-Alerting Detections data
        if GC_RM_NOT_ALERTING_DETECTIONS in self._run_mode:
            alert_state = "NOT_ALERTING"
            time_param = self._time_dict[GC_RM_NOT_ALERTING_DETECTIONS]
            ret_val, response, _ = self._fetch_rules_and_detections(action_result, client, rule_ids, alert_state, time_param, self._max_results)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Parse Not-Alerting Detections response
        results.update({GC_RM_NOT_ALERTING_DETECTIONS: self._parse_detections_response(response, run_mode=GC_RM_NOT_ALERTING_DETECTIONS)})

        return phantom.APP_SUCCESS, results

    def _check_for_existing_container(self, action_result, name):
        """Check for existing container and return container ID and and remaining margin count.

        Parameters:
            :param action_result: object of ActionResult class
            :param name: Name of the container to check
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), cid(container_id), count(remaining margin calculated with given _max_artifacts)
        """
        cid = None
        count = None

        url = f'{self.get_phantom_base_url()}rest/container?_filter_name__contains="{name}"&sort=start_time&order=desc'

        try:
            r = requests.get(url, verify=False)
        except Exception as e:
            self.debug_print("Error making local rest call: {0}".format(str(e)))
            self.debug_print('DB QUERY: {}'.format(url))
            return phantom.APP_ERROR, cid, count

        try:
            resp_json = r.json()
        except Exception as e:
            self.debug_print('Exception caught: {0}'.format(str(e)))
            return phantom.APP_ERROR, cid, count

        container = resp_json.get('data', [])
        if not container:
            self.debug_print("Not having any existing container")
            return phantom.APP_ERROR, cid, count

        # Consider latest container as existing container from the received list of containers
        try:
            container = container[0]
            if not isinstance(container, dict):
                self.debug_print("Invalid response received while checking for the existing container")
                return phantom.APP_ERROR, cid, count
        except Exception as e:
            self.debug_print(f"Invalid response received while checking for the existing container. Error: {str(e)}")
            return phantom.APP_ERROR, cid, count

        cid = container.get('id')
        artifact_count = container.get('artifact_count')

        self.debug_print(f"Existing Container ID: {cid}")
        self.debug_print(f"Existing Container artifacts count: {artifact_count}")

        try:
            count = int(self._max_artifacts) - int(artifact_count)
            # Not having space in latest container or exceed a configured limit for artifacts
            if count <= 0:
                self.debug_print("Not having enough space for the artifacts in the existing container")
                cid = None
                count = None
        except Exception as e:
            self.debug_print(f"Error occurred while calculating remaining container space. Error: {str(e)}")
            cid = None
            count = None

        return phantom.APP_SUCCESS, cid, count

    def _create_detection_artifacts(self, action_result, alerting_detections, not_alerting_detections):
        """Create Detections artifacts from the fetched Detections.

        Parameters:
            :param action_result: object of ActionResult class
            :param alerting_detections: list of Alerting Detections
            :param not_alerting_detections: list of Not Alerting Detections
        Returns:
            :return: list of alerting_detection artifacts, not_alerting_detection artifacts
        """
        # Initialize artifacts list
        alerting_detection_artifacts = list()
        not_alerting_detection_artifacts = list()

        for detection in alerting_detections:
            artifact = dict()
            artifact.update({
                "name": f"Alerting Detection for Rule: {detection.get('ruleName')}",
                "label": "Alerting Detection Artifact",
                "cef_types": {
                    "ruleId": GC_RULE_ID_CONTAINS,
                    "versionId": GC_RULE_ID_CONTAINS,
                    "detectionTime": GC_TIME_VALUE_CONTAINS,
                    "createdTime": GC_TIME_VALUE_CONTAINS,
                    "uri": GC_URL_CONTAINS
                },
                "data": detection.pop("data"),
                "source_data_identifier": f"{detection.get('detectionId')}_{detection.get('detectionTime')}"
            })

            # Set run_automation flag
            artifact.update({"run_automation": False})
            # Set cef for the artifact
            artifact.update({"cef": detection})
            # Append to the artifacts list
            alerting_detection_artifacts.append(artifact)

        for detection in not_alerting_detections:
            artifact = dict()
            artifact.update({
                "name": f"Not Alerting Detection for Rule: {detection.get('ruleName')}",
                "label": "Not Alerting Detection Artifact",
                "cef_types": {
                    "ruleId": GC_RULE_ID_CONTAINS,
                    "versionId": GC_RULE_ID_CONTAINS,
                    "detectionTime": GC_TIME_VALUE_CONTAINS,
                    "createdTime": GC_TIME_VALUE_CONTAINS,
                    "uri": GC_URL_CONTAINS
                },
                "data": detection.pop("data"),
                "source_data_identifier": f"{detection.get('detectionId')}_{detection.get('detectionTime')}"
            })

            # Set run_automation flag
            artifact.update({"run_automation": False})
            # Set cef for the artifact
            artifact.update({"cef": detection})
            # Append to the artifacts list
            not_alerting_detection_artifacts.append(artifact)

        return alerting_detection_artifacts, not_alerting_detection_artifacts

    def _create_user_alert_artifacts(self, action_result, user_alerts):
        """Create User Alerts artifacts from the fetched User Alerts.

        Parameters:
            :param action_result: object of ActionResult class
            :param user_alerts: list of User Alerts
        Returns:
            :return: list of artifacts
        """
        # Initialize artifacts list
        artifacts = list()

        for alert in user_alerts:
            artifact = dict()
            # Set contains(cef_types), label and name for the artifact
            artifact.update({
                "name": f"{alert.get('alertName')} for user {alert.get('userValue')}",
                "label": "User Alert Artifact",
                "cef_types": {
                    "userValue": GC_USER_VALUE_CONTAINS,
                    "uri": GC_URL_CONTAINS
                },
                "data": alert,
                "source_data_identifier": f"{alert.get('alertName')}_{alert.get('timestamp')}"
            })

            # Set run_automation flag
            artifact.update({"run_automation": False})
            # Set cef for the artifact
            artifact.update({"cef": alert})
            # Append to the artifacts list
            artifacts.append(artifact)

        return artifacts

    def _create_alert_artifacts(self, action_result, alerts):
        """Create Alert artifacts from the fetched Alerts.

        Parameters:
            :param action_result: object of ActionResult class
            :param alerts: list of Alerts
        Returns:
            :return: list of artifacts
        """
        # Initialize artifacts list
        artifacts = list()

        for alert in alerts:
            artifact = dict()
            # Set contains(cef_types), label and name for the artifact
            artifact.update({
                "name": f"{alert.get('alertName')} for asset {alert.get('assetValue')}",
                "label": "Alert Artifact",
                "cef_types": {
                    "assetValue": GC_ASSET_VALUE_CONTAINS,
                    "uri": GC_URL_CONTAINS
                },
                "data": alert,
                "source_data_identifier": f"{alert.get('alertName')}_{alert.get('timestamp')}"
            })

            # Set run_automation flag
            artifact.update({"run_automation": False})
            # Set cef for the artifact
            artifact.update({"cef": alert})
            # Append to the artifacts list
            artifacts.append(artifact)

        return artifacts

    def _create_ioc_artifacts(self, action_result, iocs):
        """Create IoC artifacts from the fetched IoCs.

        Parameters:
            :param action_result: object of ActionResult class
            :param iocs: list of IoCs
        Returns:
            :return: list of artifacts
        """
        # Initialize artifacts list
        artifacts = list()

        for ioc in iocs:
            artifact = dict()
            # Set contains(cef_types), label and name for the artifact
            # NOTE: What a value to be added for the default here for result.get('key', 'default')
            artifact.update({
                "name": f"Domain: {ioc.get('artifactValue')}",
                "label": "IoC Domain Artifact",
                "cef_types": {
                    "artifactValue": GC_ARTIFACT_VALUE_CONTAINS,
                    "iocIngestTime": GC_TIME_VALUE_CONTAINS,
                    "firstSeenTime": GC_TIME_VALUE_CONTAINS,
                    "lastSeenTime": GC_TIME_VALUE_CONTAINS,
                    "uri": GC_URL_CONTAINS
                },
                "data": ioc.pop("data", {}),
                "source_data_identifier": f"{ioc.get('artifactValue')}_{ioc.get('iocIngestTime')}"
            })

            # Set run_automation flag
            artifact.update({"run_automation": False})
            # Set cef for the artifact
            artifact.update({"cef": ioc})
            # Append to the artifacts list
            artifacts.append(artifact)

        return artifacts

    def _save_ingested(self, action_result, artifacts, key, cid=None):
        """Save the artifacts into the given container ID(cid) and if not given create new container with given key(name).

        Parameters:
            :param action_result: object of ActionResult class
            :param artifacts: list of artifacts of IoCs or alerts results
            :param key: name of the container in which data will be ingested
            :param cid: value of container ID
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), message, cid(container_id)
        """
        artifacts[-1]["run_automation"] = self._run_automation

        if cid:
            for artifact in artifacts:
                artifact['container_id'] = cid
            ret_val, message, _ = self.save_artifacts(artifacts)
            self.debug_print(f"save_artifacts returns, value: {ret_val}, reason: {message}")
        else:
            container = dict()
            container.update({
                "name": f"{key} {datetime.utcnow().strftime(GC_DATE_FORMAT)}",
                "artifacts": artifacts
            })
            ret_val, message, cid = self.save_container(container)
            self.debug_print(f"save_container (with artifacts) returns, value: {ret_val}, reason: {message}, id: {cid}")

        return ret_val, message, cid

    def _save_artifacts(self, action_result, results, run_mode, key):
        """Ingest all the given artifacts accordingly into the new or existing container.

        Parameters:
            :param action_result: object of ActionResult class
            :param results: list of artifacts of IoCs or alerts results
            :param run_mode: current run_mode for which artifacts will be saved
            :param key: name of the container in which data will be ingested
        Returns:
            :return: None
        """
        # Initialize
        cid = None
        start = 0
        count = None

        # If not results return
        if not results:
            return

        # Check for existing container only if it's a scheduled/interval poll and not first run
        if not (self._is_poll_now or self._is_first_run[run_mode]):
            ret_val, cid, count = self._check_for_existing_container(action_result, key)
            if phantom.is_fail(ret_val):
                self.debug_print("Failed to check for existing container")

        if cid and count:
            ret_val = self._ingest_artifacts(action_result, results[:count], key, cid=cid)
            if phantom.is_fail(ret_val):
                self.debug_print("Failed to save ingested artifacts in the existing container")
                return
            # One part is ingested
            start = count

        # Divide artifacts list into chunks which length equals to max_artifacts configured in the asset
        artifacts = [results[i:i + self._max_artifacts] for i in range(start, len(results), self._max_artifacts)]

        for artifacts_list in artifacts:
            ret_val = self._ingest_artifacts(action_result, artifacts_list, key)
            if phantom.is_fail(ret_val):
                self.debug_print("Failed to save ingested artifacts in the new container")
                return

    def _ingest_artifacts(self, action_result, artifacts, key, cid=None):
        """Ingest artifacts into the Phantom server.

        Parameters:
            :param action_result: object of ActionResult class
            :param artifacts: list of artifacts
            :param key: name of the container in which data will be ingested
            :param cid: value of container ID
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.debug_print(f"Ingesting {len(artifacts)} artifacts for {key} results into the {'existing' if cid else 'new'} container")
        ret_val, message, cid = self._save_ingested(action_result, artifacts, key, cid=cid)

        if phantom.is_fail(ret_val):
            self.debug_print(f"Failed to save ingested artifacts, error msg: {message}")
            return ret_val

        return phantom.APP_SUCCESS

    def _save_results(self, action_result, results):
        """Parse results and ingest results into the Phantom server.

        Parameters:
            :param action_result: object of ActionResult class
            :param results: Dictionary of IoCs and alerts results
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Initialize IoCs and alerts results
        iocs = results.get(GC_RM_IOC_DOMAINS, [])
        alerts = results.get(GC_RM_ASSET_ALERTS, [])
        user_alerts = results.get(GC_RM_USER_ALERTS, [])
        alerting_detections = results.get(GC_RM_ALERTING_DETECTIONS, [])
        not_alerting_detections = results.get(GC_RM_NOT_ALERTING_DETECTIONS, [])

        # Create artifacts from the IoCs results
        try:
            self.debug_print("Try to create artifacts for the IoC domain matches")
            iocs = self._create_ioc_artifacts(action_result, iocs)
            self.debug_print(f"Total IoC artifacts created: {len(iocs)}")
        except Exception as e:
            self.debug_print(f"Error occurred while creating artifacts for IoCs. Error: {str(e)}")
            self.save_progress(f"Error occurred while creating artifacts for IoCs. Error: {str(e)}")
            # Make iocs as empty list
            iocs = list()

        # Create artifacts from the alerts results
        try:
            self.debug_print("Try to create artifacts for the alerts")
            alerts = self._create_alert_artifacts(action_result, alerts)
            self.debug_print(f"Total Alert artifacts created: {len(alerts)}")
        except Exception as e:
            self.debug_print(f"Error occurred while creating artifacts for alerts. Error: {str(e)}")
            self.save_progress(f"Error occurred while creating artifacts for alerts. Error: {str(e)}")
            # Make alerts as empty list
            alerts = list()

        # Create artifacts from the user alerts results
        try:
            self.debug_print("Try to create artifacts for the user alerts")
            user_alerts = self._create_user_alert_artifacts(action_result, user_alerts)
            self.debug_print(f"Total User Alerts artifacts created: {len(user_alerts)}")
        except Exception as e:
            self.debug_print(f"Error occurred while creating artifacts for user alerts. Error: {str(e)}")
            self.save_progress(f"Error occurred while creating artifacts for user alerts. Error: {str(e)}")
            # Make alerts as empty list
            user_alerts = list()

        # Create artifacts from the alerting detections results
        try:
            self.debug_print("Try to create artifacts for the detections")
            alerting_detections, not_alerting_detections = self._create_detection_artifacts(action_result, alerting_detections, not_alerting_detections)
            self.debug_print(f"Total Alerting detection artifacts created: {len(alerting_detections)}")
            self.debug_print(f"Total Not-alerting detection artifacts created: {len(not_alerting_detections)}")
        except Exception as e:
            self.debug_print(f"Error occurred while creating artifacts for detections. Error: {str(e)}")
            self.save_progress(f"Error occurred while creating artifacts for detections. Error: {str(e)}")
            # Make alerts as empty list
            alerts = list()

        # Save artifacts for IoCs
        try:
            self.debug_print("Try to ingest artifacts for the IoC domain matches")
            self._save_artifacts(action_result, iocs, run_mode=GC_RM_IOC_DOMAINS, key=GC_IOC_RUN_MODE_KEY)
        except Exception as e:
            self.debug_print(f"Error occurred while saving artifacts for IoCs. Error: {str(e)}")

        # Save artifacts for alerts
        try:
            self.debug_print("Try to ingest artifacts for the alerts")
            self._save_artifacts(action_result, alerts, run_mode=GC_RM_ASSET_ALERTS, key=GC_ALERT_RUN_MODE_KEY)
        except Exception as e:
            self.debug_print(f"Error occurred while saving artifacts for alerts. Error: {str(e)}")

        # Save artifacts for user alerts
        try:
            self.debug_print("Try to ingest artifacts for the user alerts")
            self._save_artifacts(action_result, user_alerts, run_mode=GC_RM_USER_ALERTS, key=GC_USER_ALERT_RUN_MODE_KEY)
        except Exception as e:
            self.debug_print(f"Error occurred while saving artifacts for user alerts. Error: {str(e)}")

        # Save artifacts for alerting detections
        try:
            self.debug_print("Try to ingest artifacts for the alerting detections")
            self._save_artifacts(action_result, alerting_detections, run_mode=GC_RM_ALERTING_DETECTIONS, key=GC_ALERTING_DETECTION_RUN_MODE_KEY)
        except Exception as e:
            self.debug_print(f"Error occurred while saving artifacts for alerting detections. Error: {str(e)}")

        # Save artifacts for not alerting detections
        try:
            self.debug_print("Try to ingest artifacts for the not alerting detections")
            self._save_artifacts(action_result, not_alerting_detections, run_mode=GC_RM_NOT_ALERTING_DETECTIONS, key=GC_NOT_ALERTING_DETECTION_RUN_MODE_KEY)
        except Exception as e:
            self.debug_print(f"Error occurred while saving artifacts for not alerting detections. Error: {str(e)}")

        return phantom.APP_SUCCESS

    def _save_state(self, action_result):
        """Save the last run state as per the given ingestion asset configuration parameters.

        Parameters:
            :param action_result: object of ActionResult class
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Updating the last run hash digest for scheduled/interval or manual polling
        self._state["last_run_hash_digests"] = self._last_run_hash_digests

        # Check for manual poll or not
        if self._is_poll_now:
            return phantom.APP_SUCCESS

        # As end_alert_time has current time, we are saving current time as last run time for both alert and IoCs.
        for run_mode in self._run_mode:
            self._state[f"last_run_{run_mode}_time"] = self._time_dict.get(run_mode, {}).get(GC_END_TIME_KEY)

        return phantom.APP_SUCCESS

    def _perform_ingest_function(self, action_result, client, config):
        """Perform the ingest function using supplied asset configuration parameters.

        Parameters:
            :param action_result: object of ActionResult class
            :param client: object of HTTP client
            :param config: Dictionary of asset configuration parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        DEFAULT_ALL_MODE_LIST = [GC_RM_IOC_DOMAINS, GC_RM_ASSET_ALERTS, GC_RM_USER_ALERTS, GC_RM_ALERTING_DETECTIONS, GC_RM_NOT_ALERTING_DETECTIONS]

        # Fetch ingestion run mode
        self._run_mode = GC_RM_ON_POLL_DICT.get(config.get("run_mode", "All"), DEFAULT_ALL_MODE_LIST)

        # Fetch run_automation flag
        self._run_automation = config.get("run_automation", False)

        self.debug_print(f"Ingestion run mode: '{self._run_mode}'")
        self.save_progress(f"Ingestion run mode: '{self._run_mode}'")

        self.debug_print(f"Run automation flag: '{self._run_automation}'")
        self.save_progress(f"Run automation flag: '{self._run_automation}'")

        # Validate ingestion asset configuration parameters
        self.debug_print("Validate ingestion asset configuration parameters")
        self.save_progress("Validate ingestion asset configuration parameters")
        ret_val = self._validate_on_poll_params(action_result, config)
        if phantom.is_fail(ret_val):
            self.debug_print("Asset configuration parameters validation failed")
            self.save_progress("Asset configuration parameters validation failed")
            return action_result.get_status()

        # Fetch results as per the given ingestion run mode
        self.debug_print("Fetch results as per the given ingestion run mode")
        self.save_progress("Fetch results as per the given ingestion run mode")
        ret_val, results = self._fetch_results(action_result, client)
        if phantom.is_fail(ret_val):
            self.debug_print("Failed to fetch the results as per the given ingestion run mode")
            self.save_progress("Failed to fetch the results as per the given ingestion run mode")
            return action_result.get_status()

        # Parse results as per the given ingestion run mode
        self.debug_print("Ingest results as per the given ingestion run mode")
        self.save_progress("Ingest results as per the given ingestion run mode")
        ret_val = self._save_results(action_result, results)
        if phantom.is_fail(ret_val):
            self.debug_print("Failed to ingest the results as per the given ingestion run mode")
            self.save_progress("Failed to ingest the results as per the given ingestion run mode")
            return action_result.get_status()

        # Save state as per the configured ingestion run mode
        ret_val = self._save_state(action_result)
        if phantom.is_fail(ret_val):
            self.debug_print("Failed to save the last run state as per the given ingestion run mode")
            return action_result.get_status()

        # Return success
        return phantom.APP_SUCCESS

    def _handle_on_poll(self, param):
        """Perform the on poll ingest functionality.

        Parameters:
            :param param: Dictionary of input parameters
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, client = self._create_client(action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(GC_UNABLE_CREATE_CLIENT_ERR)
            self.save_progress(GC_UNABLE_CREATE_CLIENT_ERR)
            return ret_val

        # Get the asset config
        config = self.get_config()

        # Check for manual or scheduled poll
        self._is_poll_now = self.is_poll_now()

        ret_val = self._perform_ingest_function(action_result, client, config)
        if phantom.is_fail(ret_val):
            self.debug_print("Unable to perform ingest function")
            self.save_progress("Unable to perform ingest function")
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Get current action identifier and call member function of its own to handle the action.

        Parameters:
            :param param: dictionary which contains information about the actions to be executed
        Returns:
            :return: status success/failure
        """
        # Get the action that we are supposed to execute for this App Run
        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            "test_connectivity": self._handle_test_connectivity,
            "list_ioc_details": self._handle_list_ioc_details,
            "list_assets": self._handle_list_assets,
            "list_events": self._handle_list_events,
            "list_iocs": self._handle_list_iocs,
            "domain_reputation": self._handle_domain_reputation,
            "ip_reputation": self._handle_ip_reputation,
            "list_alerts": self._handle_list_alerts,
            "list_rules": self._handle_list_rules,
            "list_detections": self._handle_list_detections,
            "on_poll": self._handle_on_poll
        }

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            ret_val = action_function(param)

        return ret_val

    def initialize(self):
        """Initialize the global variables with its value and validate it.

        Initialization method that can be implemented by the AppConnector derived class.
        Since the configuration dictionary is already validated by the time this method is called, it's a good place to do any extra initialization of any internal modules.
        This method MUST return a value of either phantom.APP_SUCCESS or phantom.APP_ERROR.
        If this method returns phantom.APP_ERROR, then AppConnector::handle_action will not get called.

        Returns:
            :return: status success/failure
        """
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Reseting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            return self.set_status(phantom.APP_ERROR, GC_STATE_FILE_CORRUPT_ERROR)

        # Get the asset config
        config = self.get_config()

        # Service account json file contents initialization
        ret_val, self._key_dict = self._validate_json(self, config[GC_KEY_JSON_KEY], GC_CONFIG_KEY_DICT_KEY, is_dict=True)
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Remove API version from Base URL, e.g., /v1
        self._base_url = re.sub('/v\\d', '', config[GC_BASE_URL_KEY], count=1)

        # Scope for Google Chronicle search API
        ret_val, self._scopes = self._validate_json(self, config[GC_SCOPE_KEY], GC_CONFIG_SCOPE_KEY, is_lower=False)
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Validate the 'wait_timeout_period' config parameter
        self._wait_timeout_period = self._validate_integers(
            self, config.get(GC_WAIT_TIMEOUT_PERIOD_KEY, GC_DEFAULT_WAIT_TIMEOUT_PERIOD), GC_CONFIG_WAIT_TIMEOUT_PERIOD_KEY)
        if self._wait_timeout_period is None:
            return self.get_status()

        # Validate the 'no_of_retries' config parameter
        self._no_of_retries = self._validate_integers(
            self, config.get(GC_NO_OF_RETRIES_KEY, GC_NUMBER_OF_RETRIES), GC_CONFIG_NO_OF_RETRIES_KEY, True)
        if self._no_of_retries is None:
            return self.get_status()

        return phantom.APP_SUCCESS

    def finalize(self):
        """Perform some final operations or clean up operations.

        Returns:
            :return: status success
        """
        # Save the state, this data is saved across actions and app upgrades
        self.debug_print(f"Latest context stored in the state file: {self._state}")
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    """Use this method to debug action using input test JSON file."""
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

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = ChronicleConnector._get_phantom_base_url() + '/login'

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

        connector = ChronicleConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
