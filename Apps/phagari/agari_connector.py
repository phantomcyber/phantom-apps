# File: agari_connector.py
#
# Copyright (c) Agari, 2021
#
# This unpublished material is proprietary to Agari.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Agari.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from agari_consts import *
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import json
import pytz
from dateutil.parser import isoparse
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup


class RetVal(tuple):
    """Represent a class to create a tuple."""

    def __new__(cls, val1, val2=None):
        """Create a tuple from the provided values."""
        return tuple.__new__(RetVal, (val1, val2))


class AgariConnector(BaseConnector):
    """Represent a connector module that implements the actions that are provided by the app. AgariConnector is a class that is derived from the BaseConnector class."""

    def __init__(self):
        """Initialize global variables."""
        # Call the BaseConnectors init first
        super(AgariConnector, self).__init__()

        self._state = {}
        self._access_token = None
        self._client_id = None
        self._client_secret = None
        self._current_utc_time = None

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.

        :param e: Exception object
        :return: error message
        """
        error_code = ERR_CODE_MSG
        error_msg = ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
        except:
            pass

        try:
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {}".format(error_msg)
            else:
                error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """
        Validate an integer.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, AGARI_VALID_INT_MSG.format(param=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, AGARI_VALID_INT_MSG.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, AGARI_NON_NEG_INT_MSG.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, AGARI_NON_NEG_NON_ZERO_INT_MSG.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _filter_comma_seperated_fields(self, action_result, field, key):
        """
        Filter the comma seperated values in the field. This method operates in 3 steps:

        1. Get list with comma as the seperator
        2. Filter empty values from the list
        3. Re-create the string with non-empty values.

        :param action_result: Action result object
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, filtered string or None in case of failure
        """
        if field:
            fields_list = [value.strip() for value in field.split(',') if value.strip()]
            if not fields_list:
                return action_result.set_status(phantom.APP_ERROR, AGARI_ERR_INVALID_FIELDS.format(field=key)), None
            return phantom.APP_SUCCESS, ','.join(fields_list)
        return phantom.APP_SUCCESS, field

    def _remove_empty_values(self, params):
        """
        Remove empty values from the parameter dictionary.

        :param params: parameter dictionary
        :return: updated dictionary without empty values
        """
        return {key: value for (key, value) in params.items() if value is not None}

    def _paginator(self, action_result, params, endpoint, key, offset, max_results):
        """
        Fetch all the results using pagination logic.

        :param action_result: object of ActionResult class
        :param params: params to be passed while calling the API
        :param endpoint: REST endpoint that needs to appended to the service address
        :param key: response key that needs to fetched
        :param offset: starting index of the results to be fetched
        :param max_results: maximum number of results to be fetched
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, successfully fetched results or None in case of failure
        """
        items_list = list()

        params['offset'] = offset
        params['limit'] = AGARI_DEFAULT_LIMIT

        while True:
            ret_val, items = self._make_rest_call_helper(action_result, endpoint, headers=self._headers, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            items_list.extend(items.get(key, []))

            # Max results fetched. Hence, exit the paginator.
            if len(items_list) >= max_results:
                return phantom.APP_SUCCESS, items_list[:max_results]

            # Items fetched is less than the default limit, which means there is no more data to be processed
            if len(items.get(key, [])) < AGARI_DEFAULT_LIMIT:
                break

            params['offset'] += AGARI_DEFAULT_LIMIT

        return phantom.APP_SUCCESS, items_list

    def _validate_paginator_parameters(self, action_result, param):
        """
        Validate pagination parameters.

        :param action_result: object of Action Result
        :parar param: parameter/configuration dictionary
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), offset, max_results
        """
        # Integer validation for 'offset' parameter
        ret_val, offset = self._validate_integer(action_result, param.get('offset', 0), 'offset', True)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None, None

        # Integer validation for 'max_results' parameter
        ret_val, max_results = self._validate_integer(action_result, param.get('max_results', AGARI_DEFAULT_MAX_RESULTS), 'max_results')
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None, None

        return phantom.APP_SUCCESS, offset, max_results

    def _parse_datetime(self, action_result, date, key):
        """
        Validate and parse the datetime string as per ISO format.

        :param action_result: object of Action Result
        :param sort: input sort string
        :param key: input parameter message key
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        sort or None in case of failure
        """
        # Check date is in valid ISO format
        try:
            date_time_object = isoparse(date)
        except:
            return action_result.set_status(phantom.APP_ERROR, AGARI_ERR_PARSE_DATE.format(param=key)), None

        # Check date is within the max range
        if date_time_object.utcoffset():
            date_time_object = date_time_object.replace(tzinfo=pytz.UTC) - date_time_object.utcoffset()
        else:
            date_time_object = date_time_object.replace(tzinfo=pytz.UTC)

        if self.get_action_identifier() == 'on_poll' and date_time_object < (self._current_utc_time - timedelta(days=AGARI_MAX_DAYS)).replace(tzinfo=pytz.UTC):
            return action_result.set_status(phantom.APP_ERROR, AGARI_ERR_DATE_NOT_IN_RANGE.format(key=key)), None

        return phantom.APP_SUCCESS, date_time_object

    def _validate_sort_parameter(self, action_result, sort, key):
        """
        Validate the sort parameter (comma-seperated string).

        :param action_result: object of Action Result
        :param sort: input sort string
        :param key: input parameter message key
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        sort or None in case of failure
        """
        if sort:
            try:
                # Stripping and splitting with seperator as comma
                sort_list = [value.strip() for value in sort.split(',') if value.strip()]

                # No element found, return error
                if not sort_list:
                    return action_result.set_status(phantom.APP_ERROR, AGARI_ERR_INVALID_SORT.format(param=key)), None

                # Check each sort element is in valid format
                for element in sort_list:
                    sort_type = element.split()[-1]
                    if sort_type not in AGARI_SORT_VALUE_LIST:
                        return action_result.set_status(phantom.APP_ERROR, AGARI_ERR_INVALID_SORT_TYPE), None
                return phantom.APP_SUCCESS, ','.join(sort_list)
            except:
                return action_result.set_status(phantom.APP_ERROR, AGARI_ERR_INVALID_SORT.format(param=key)), None
        return phantom.APP_SUCCESS, sort

    def _validate_value_list_parameter(self, action_result, parameter, key, value_list):
        """
        Check whether the specified value is present in the value list.

        :param action_result: object of Action Result
        :param parameter: input parameter
        :param key: input parameter message key
        :param value_list: list of valid values
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        parameter or None in case of failure
        """
        if parameter:
            # Check parameter is in value list
            if parameter not in value_list:
                value_list_string = "', '".join(value_list)
                return action_result.set_status(
                    phantom.APP_ERROR,
                    AGARI_ERR_INVALID_VALUE_LIST_PARAMETER.format(param=key, value_list=value_list_string)
                ), None
            return phantom.APP_SUCCESS, parameter
        return phantom.APP_SUCCESS, parameter

    def _validate_datetime_parameters(self, action_result, start_date, end_date):
        """
        Validate datetime parameters.

        :param action_result: object of Action Result
        :param start_date: start date
        :param end_date: end date
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), start_date, end_date
        """
        start_date_object = None
        end_date_object = None

        # Parse start date
        if start_date:
            ret_val, start_date_object = self._parse_datetime(action_result, start_date, 'start_date')
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None, None
            start_date = start_date_object.strftime(AGARI_API_SUPPORT_DATE_FORMAT)

        # Parse end date
        if end_date:
            ret_val, end_date_object = self._parse_datetime(action_result, end_date, 'end_date')
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None, None
            end_date = end_date_object.strftime(AGARI_API_SUPPORT_DATE_FORMAT)

        # Check end date is not less than start date
        if start_date_object and end_date_object and end_date_object < start_date_object:
            return action_result.set_status(phantom.APP_ERROR, AGARI_ERR_END_DATE_LESS_THAN_START_DATE), None, None

        return phantom.APP_SUCCESS, start_date, end_date

    def _validate_fields_parameters(self, action_result, param):
        """
        Validate fields parameters.

        :param action_result: object of Action Result
        :parar param: parameter dictionary
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        fields, add_fields, rem_fields
        """
        ret_val, fields = self._filter_comma_seperated_fields(action_result, param.get('fields'), 'fields')
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None, None, None

        ret_val, rem_fields = self._filter_comma_seperated_fields(action_result, param.get('rem_fields'), 'rem_fields')
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None, None, None

        ret_val, add_fields = self._filter_comma_seperated_fields(action_result, param.get('add_fields'), 'add_fields')
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None, None, None

        return phantom.APP_SUCCESS, fields, add_fields, rem_fields

    def _validate_list_policy_events_parameter(self, action_result, param):
        """
        Validate list policy events parameter.

        :param action_result: object of Action Result
        :parar param: parameter dictionary
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        updated_param or empty dictionary in case of failure
        """
        # Comma-seperated validation for fields parameters
        ret_val, fields, add_fields, rem_fields = self._validate_fields_parameters(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}

        # Validate date time parameters
        ret_val, start_date, end_date = self._validate_datetime_parameters(action_result, param.get('start_date'), param.get('end_date'))
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}

        # Validate paginator parameters
        ret_val, offset, max_results = self._validate_paginator_parameters(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}

        # Validate sort parameter
        ret_val, sort = self._validate_sort_parameter(action_result, param.get('sort'), 'sort')
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}

        # Value list validation for 'policy_action'
        ret_val, policy_action = self._validate_value_list_parameter(action_result, param.get('policy_action'),
                                                                     'policy_action', AGARI_POLICY_ACTION_VALUE_LIST)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}
        if policy_action == 'all':
            policy_action = None

        # Value list validation for 'exclude_alert_types'
        ret_val, exclude_alert_types = self._validate_value_list_parameter(action_result, param.get('exclude_alert_types'),
                                                                           'exclude_alert_types', AGARI_EXCLUDE_ALERT_TYPES_VALUE_LIST)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}
        if exclude_alert_types == 'None':
            exclude_alert_types = None

        # Value list validation for 'policy_enabled'
        ret_val, policy_enabled = self._validate_value_list_parameter(action_result, param.get('policy_enabled'),
                                                                      'policy_enabled', AGARI_POLICY_ENABLED_VALUE_LIST)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}
        policy_enabled = self._map_policy_enabled(policy_enabled)

        policy_name = param.get('policy_name')
        filter_to_apply = param.get('filter')

        # Creating updated parameter dictionary
        params = {
            'max_results': max_results,
            'limit': AGARI_DEFAULT_LIMIT,
            'offset': offset,
            'fields': fields,
            'add_fields': add_fields,
            'rem_fields': rem_fields,
            'start_date': start_date,
            'end_date': end_date,
            'policy_enabled': policy_enabled,
            'policy_action': policy_action,
            'policy_name': policy_name,
            'filter': filter_to_apply,
            'exclude_alert_types': exclude_alert_types,
            'sort': sort
        }

        # Remove empty values from dictionary
        updated_params = self._remove_empty_values(params)

        return phantom.APP_SUCCESS, updated_params

    def _validate_list_messages_parameter(self, action_result, param):
        """
        Validate list messages parameter.

        :param action_result: object of Action Result
        :parar param: parameter dictionary
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        updated_param or empty dictionary in case of failure
        """
        # Comma-seperated validation for fields parameter
        ret_val, fields, add_fields, rem_fields = self._validate_fields_parameters(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}

        # Validate date time parameters
        ret_val, start_date, end_date = self._validate_datetime_parameters(action_result, param.get('start_date'), param.get('end_date'))
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}

        # Validate paginator parameters
        ret_val, offset, max_results = self._validate_paginator_parameters(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}

        # Validate sort parameter
        ret_val, sort = self._validate_sort_parameter(action_result, param.get('sort'), 'sort')
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}

        search_filter = param.get('search')

        # Creating updated parameter dictionary
        params = {
            'max_results': max_results,
            'limit': AGARI_DEFAULT_LIMIT,
            'offset': offset,
            'fields': fields,
            'add_fields': add_fields,
            'rem_fields': rem_fields,
            'start_date': start_date,
            'end_date': end_date,
            'search': search_filter,
            'sort': sort
        }

        # Remove empty values from dictionary
        updated_params = self._remove_empty_values(params)

        return phantom.APP_SUCCESS, updated_params

    def _process_empty_response(self, response, action_result):
        """
        Process empty response.

        :param response: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, AGARI_ERR_EMPTY_RESPONSE.format(code=response.status_code)
            ), None
        )

    def _process_html_response(self, response, action_result):
        """
        Process html response.

        :param response: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
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
            error_text = AGARI_UNABLE_TO_PARSE_ERR_DETAIL

        if not error_text:
            error_text = "Empty response and no information received"
        message = "Status Code: {}. Data from server:\n{}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        """
        Process json response.

        :param r: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        status_code = r.status_code
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, AGARI_ERR_UNABLE_TO_PARSE_JSON_RESPONSE.format(error=error_msg)
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        if resp_json.get('error') or resp_json.get('error_description'):
            error = resp_json.get('error', 'Unavailable')
            error_details = resp_json.get('error_description', 'Unavailable')
            message = "Error from server. Status Code: {}. Error: {}. Error Details: {}".format(status_code, error, error_details)
        else:
            # You should process the error returned in the json
            error_text = r.text.replace("{", "{{").replace("}", "}}")
            message = "Error from server. Status Code: {}. Data from server: {}".format(status_code, error_text)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        """
        Process API response.

        :param r: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
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
        error_text = r.text.replace('{', '{{').replace('}', '}}')
        message = "Can't process response from server. Status Code: {} Data from server: {}".format(r.status_code, error_text)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _generate_access_token(self, action_result):
        """
        Generate a new access token.

        :param action_result: object of ActionResult class
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret
        }

        url = "{0}{1}".format(AGARI_BASE_URL, AGARI_TOKEN_ENDPOINT)

        ret_val, resp_json = self._make_rest_call(url, action_result, data=data, method="post")

        if phantom.is_fail(ret_val):
            # Failed to generate new token. Delete the previously generated token in case the credentials are changed.
            self._state.pop(AGARI_OAUTH_TOKEN_STRING, {})
            return action_result.get_status()

        self._state[AGARI_OAUTH_TOKEN_STRING] = resp_json
        self._access_token = resp_json[AGARI_OAUTH_ACCESS_TOKEN_STRING]
        self.save_state(self._state)

        return action_result.set_status(phantom.APP_SUCCESS)

    def requests_retry_session(self, retries, backoff_factor, status_forcelist=[429], session=None):
        """
        Create and return a session object

        :param retries: Maximum number of retries to attempt
        :param backoff_factor: Backoff factor used to calculate time between retries.
        :param status_forcelist: A tuple containing the response status codes that should trigger a retry.
        :param session: Session object
        :return: Session Object
        """
        session = session or requests.Session()

        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )

        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        session.headers.update(self._headers)

        return session

    def _make_rest_call(self, url, action_result, headers=None, params=None, data=None, json=None, method="get"):
        """
        Make the REST call to the app.

        :param url: URL of the resource
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        resp_json = None

        try:
            request_func = getattr(self._session, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {}".format(method)),
                resp_json
            )

        try:
            r = request_func(url, verify=True, json=json, data=data, headers=headers, params=params)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, AGARI_ERR_CONNECTING_TO_SERVER.format(error=error_msg)
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _make_rest_call_helper(self, action_result, endpoint, headers=None, params=None, data=None, json=None, method="get"):
        """
        Help setting a REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        url = "{}{}".format(AGARI_BASE_URL, endpoint)
        if headers is None:
            headers = {}

        token = self._state.get(AGARI_OAUTH_TOKEN_STRING, {})
        if not token.get(AGARI_OAUTH_ACCESS_TOKEN_STRING):
            ret_val = self._generate_access_token(action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            headers.update({
                'Authorization': AGARI_AUTHORIZATION_HEADER.format(token=self._access_token)
            })

        ret_val, resp_json = self._make_rest_call(url, action_result, headers, params, data, json, method)

        # If token is expired, generate a new token
        msg = action_result.get_message()

        if msg and ('403' in msg or '401' in msg):
            self.debug_print("Refreshing Agari API and re-trying request to [{}] because API token was expired or invalid with error code [{}]".format(url, msg))
            ret_val = self._generate_access_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            headers.update({
                'Authorization': AGARI_AUTHORIZATION_HEADER.format(token=self._access_token)
            })

            ret_val, resp_json = self._make_rest_call(url, action_result, headers, params, data, json, method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _handle_test_connectivity(self, param):
        """
        Validate the asset configuration for connectivity using supplied configuration.

        :param param: dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        # generate new access token
        ret_val = self._generate_access_token(action_result=action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(AGARI_ERR_TEST_CONN_FAILED)
            return action_result.get_status()

        self.save_progress("Access token received")

        self._headers.update({'Authorization': AGARI_AUTHORIZATION_HEADER.format(token=self._access_token)})

        url = "{}{}".format(AGARI_BASE_URL, AGARI_LIST_POLICY_EVENTS_ENDPOINT)

        param = {
            "limit": 1
        }

        # make rest call
        ret_val, _ = self._make_rest_call(url, action_result, params=param, headers=self._headers)

        if phantom.is_fail(ret_val):
            self.save_progress(AGARI_ERR_TEST_CONN_FAILED)
            return action_result.get_status()

        # Return success
        self.save_progress(AGARI_SUCC_TEST_CONN_PASSED)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_policy_event(self, param):
        """
        Fetch a single policy event based on the provided ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(AGARI_ACTION_HANDLER_MSG.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, policy_event_id = self._validate_integer(action_result, param['id'], 'id', True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, fields, add_fields, rem_fields = self._validate_fields_parameters(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = {
            'fields': fields,
            'rem_fields': rem_fields,
            'add_fields': add_fields
        }

        updated_params = self._remove_empty_values(params)

        # make rest call
        ret_val, response = self._make_rest_call_helper(action_result, AGARI_GET_POLICY_EVENT_ENDPOINT.format(id=policy_event_id), headers=self._headers, params=updated_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, AGARI_SUCC_GET_POLICY_EVENT)

    def _handle_get_message(self, param):
        """
        Fetch a single message based on the provided ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(AGARI_ACTION_HANDLER_MSG.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        message_id = param['id']

        ret_val, fields, add_fields, rem_fields = self._validate_fields_parameters(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        params = {
            'fields': fields,
            'rem_fields': rem_fields,
            'add_fields': add_fields
        }

        updated_params = self._remove_empty_values(params)

        # make rest call
        ret_val, response = self._make_rest_call_helper(action_result, AGARI_GET_MESSAGE_ENDPOINT.format(id=message_id), headers=self._headers, params=updated_params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, AGARI_SUCC_GET_MESSAGE)

    def _handle_remediate_message(self, param):
        """
        Remediate a single message based on the provided ID.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        message_id = param['id']

        payload = {
            'operation': param['remediation_operation']
        }

        # make rest call
        ret_val, response = self._make_rest_call_helper(action_result, AGARI_REMEDIATE_MESSAGE_ENDPOINT.format(id=message_id),
                                                        headers=self._headers, data=payload, method='post')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, AGARI_SUCC_REMEDIATE_MESSAGE)

    def _handle_list_policy_events(self, param):
        """
        Retrieve the policy events that match the specified parameters from Agari Platform.

        :param param: Dictionary of input parameter(s)
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(AGARI_ACTION_HANDLER_MSG.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, updated_params = self._validate_list_policy_events_parameter(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        max_results = updated_params.pop('max_results')

        # make rest call
        ret_val, alert_events = self._paginator(
            action_result, updated_params, AGARI_LIST_POLICY_EVENTS_ENDPOINT,
            'alert_events', updated_params['offset'], max_results
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for alert_event in alert_events:
            action_result.add_data(alert_event)
        action_result.update_summary({"total_policy_events": len(alert_events)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_messages(self, param):
        """
        Retrieve the messages that match the specified parameters from Agari Platform.

        :param param: Dictionary of input parameter(s)
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.save_progress(AGARI_ACTION_HANDLER_MSG.format(identifier=self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, updated_params = self._validate_list_messages_parameter(action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        max_results = updated_params.pop('max_results')

        # make rest call
        ret_val, messages = self._paginator(
            action_result, updated_params, AGARI_LIST_MESSAGES_ENDPOINT,
            'messages', updated_params['offset'], max_results
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for message in messages:
            action_result.add_data(message)
        action_result.update_summary({"total_messsages": len(messages)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_on_poll_filter(self, filter_to_apply):
        """
        Update filter based on polling.

        :param filter_to_apply: existing filter
        :return: updated filter to apply
        """
        if not self._is_poll_now:
            last_fetched_id = self._state.get(AGARI_LAST_INGESTED_POLICY_EVENT_ID)
            if last_fetched_id:
                if not filter_to_apply:
                    filter_to_apply = 'id.gt({})'.format(last_fetched_id)
                else:
                    filter_to_apply = '{} and id.gt({})'.format(filter_to_apply, last_fetched_id)
        return filter_to_apply

    def _map_policy_enabled(self, policy_enabled):
        """
        Map the policy enabled field.

        :param policy_enabled: current policy enabled value
        :return: updated policy enabled value
        """
        if policy_enabled == 'True':
            policy_enabled = True
        elif policy_enabled == 'False':
            policy_enabled = False
        else:
            policy_enabled = None
        return policy_enabled

    def _remap_cef(self, cef, cef_mapping):
        """
        Remap the cef field.

        :param cef: old cef
        :param cef_mapping: mapping between the old and the new cef
        :return: remapped cef
        """
        # If cef not found, return empty dict
        if not cef:
            return dict()

        # if cef_mapping not found, return original cef
        if not cef_mapping:
            return cef.copy()

        # Recursive call for parsing cef dict
        newcef = dict()
        for key, value in list(cef.items()):
            if isinstance(value, dict):
                value = self._remap_cef(value, cef_mapping)
            newkey = cef_mapping.get(key, key)
            newcef[newkey] = value

        return newcef

    def _validate_ingestion_params(self, action_result, config):
        """
        Validate ingestion parameter.

        :param action_result: object of Action Result
        :parar config: configuration dictionary
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        updated_param or empty dictionary in case of failure
        """
        # Comma-seperated validation for 'add_fields'
        ret_val, add_fields = self._filter_comma_seperated_fields(action_result, config.get('add_fields'), 'Fields to add')
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}

        sort = 'created_at ASC, id ASC' if config['sort'] == 'oldest_first' else 'created_at DESC, id ASC'

        # Initialize 'start_date' based on type of polling
        start_date_default = str(self._current_utc_time - timedelta(days=AGARI_DEFAULT_DAYS))
        if self._is_poll_now:
            start_date = config.get('start_date', start_date_default)
        else:
            start_date = self._state.get(AGARI_LAST_INGESTED_POLICY_EVENT_DATE, config.get('start_date', start_date_default))

        end_date = str(self._current_utc_time)

        # Validate date time parameters
        ret_val, start_date, end_date = self._validate_datetime_parameters(action_result, start_date, end_date)
        if phantom.is_fail(ret_val):
            action_result_message = action_result.get_message()
            if 'end_date' in action_result_message:
                end_date_message = "The 'end_date' for the On Poll action is current UTC time ({}).".format(self._current_utc_time.strftime(AGARI_API_SUPPORT_DATE_FORMAT))
                message = "{} {}".format(action_result_message, end_date_message)
                return action_result.set_status(phantom.APP_ERROR, message), {}
            return action_result.get_status(), {}

        # Value list validation for 'policy_action'
        ret_val, policy_action = self._validate_value_list_parameter(action_result, config.get('policy_action'),
                                                                     'policy_action', AGARI_POLICY_ACTION_VALUE_LIST)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}
        if policy_action == 'all':
            policy_action = None

        # Value list validation for 'exclude_alert_types'
        ret_val, exclude_alert_types = self._validate_value_list_parameter(action_result, config.get('exclude_alert_types'),
                                                                           'exclude_alert_types', AGARI_EXCLUDE_ALERT_TYPES_VALUE_LIST)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}
        if exclude_alert_types == 'None':
            exclude_alert_types = None

        # Value list validation for 'policy_enabled'
        ret_val, policy_enabled = self._validate_value_list_parameter(action_result, config.get('policy_enabled'),
                                                                      'policy_enabled', AGARI_POLICY_ENABLED_VALUE_LIST)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), {}

        policy_enabled = self._map_policy_enabled(policy_enabled)
        policy_name = config.get('policy_name')
        filter_to_apply = self._get_on_poll_filter(config.get('filter'))

        # Validate 'cef_mapping' parameter
        cef_mapping = config.get('cef_mapping')
        if cef_mapping:
            try:
                cef_mapping = json.loads(cef_mapping)
            except:
                return action_result.set_status(phantom.APP_ERROR, AGARI_ERR_INVALID_JSON), {}

        # Creating updated parameter dictionary
        params = {
            'limit': AGARI_DEFAULT_LIMIT,
            'offset': 0,
            'add_fields': add_fields,
            'start_date': start_date,
            'end_date': end_date,
            'policy_enabled': policy_enabled,
            'policy_action': policy_action,
            'policy_name': policy_name,
            'filter': filter_to_apply,
            'exclude_alert_types': exclude_alert_types,
            'sort': sort,
            'update_state_after': AGARI_DEFAULT_UPDATE_STATE_AFTER,
            'cef_mapping': cef_mapping
        }

        # Remove empty values from parameters
        updated_params = self._remove_empty_values(params)

        return phantom.APP_SUCCESS, updated_params

    def _get_results_helper(self, alert_event, action_result, message_params):
        policy_event_id = alert_event.get('id')
        try:
            ret_val, policy_event = self._make_rest_call_helper(action_result, AGARI_GET_POLICY_EVENT_ENDPOINT.format(id=policy_event_id), headers=self._headers)
            if phantom.is_fail(ret_val):
                error_msg = action_result.get_message()
                self.debug_print("Failed to fetch policy event ID {}. {}".format(policy_event_id, error_msg))
                self.debug_print(AGARI_ERR_SKIP_POLICY_EVENT.format(policy_event_id))
                self.save_progress(AGARI_ERR_SKIP_POLICY_EVENT.format(policy_event_id))
                return {}

            message_id = policy_event.get('alert_event', {}).get('collector_message_id')
            if not message_id:
                self.debug_print("Failed to fetch message ID as message ID was not found")
                self.debug_print(AGARI_ERR_SKIP_POLICY_EVENT.format(policy_event_id))
                self.save_progress(AGARI_ERR_SKIP_POLICY_EVENT.format(policy_event_id))
                return {}

            ret_val, message = self._make_rest_call_helper(action_result, AGARI_GET_MESSAGE_ENDPOINT.format(id=message_id), headers=self._headers, params=message_params)
            if phantom.is_fail(ret_val):
                error_msg = action_result.get_message()
                self.debug_print("Failed to fetch message ID {}. {}".format(message_id, error_msg))
                self.debug_print(AGARI_ERR_SKIP_POLICY_EVENT.format(policy_event_id))
                self.save_progress(AGARI_ERR_SKIP_POLICY_EVENT.format(policy_event_id))
                return {}

            policy_event_updated = alert_event.copy()
            policy_event_updated['conditions'] = policy_event.get('alert_event', {}).get('conditions')

            data = {
                'policy_event': policy_event_updated,
                'message': message.get('message', {})
            }
            return data
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.error_print("Failed to fetch policy event ID {}. {}".format(policy_event_id, error_msg))
            self.error_print(AGARI_ERR_SKIP_POLICY_EVENT.format(policy_event_id))
            self.save_progress(AGARI_ERR_SKIP_POLICY_EVENT.format(policy_event_id))
            return {}

    def _get_results(self, action_result, updated_params, max_results):
        """
        Fetch the policy events and messages.

        :param action_result: object of ActionResult class
        :param updated_param: parameter dictionary
        :param max_results: max results to fetch
        :return: phantom.APP_SUCCESS
        """
        message_params = None
        # Add fields parameter will be applied to 'get message' API call. Hence, popping it from params.
        if updated_params.get('add_fields'):
            add_fields = updated_params.pop('add_fields')
            message_params = {
                'add_fields': add_fields
            }

        # make rest call
        ret_val, alert_events = self._paginator(
            action_result, updated_params, AGARI_LIST_POLICY_EVENTS_ENDPOINT,
            'alert_events', updated_params['offset'], max_results
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status(), []

        if not alert_events:
            self.save_progress(AGARI_SUCC_NO_POLICY_EVENT_TO_INGEST)
            return action_result.set_status(phantom.APP_SUCCESS), []

        non_ingested_policy_ids = []
        # Validate 'add_fields' parameter for 'get message' and check if there are any valid events for ingestion.
        for alert_event in alert_events:
            policy_event_id = alert_event.get('id')
            try:
                ret_val, policy_event = self._make_rest_call_helper(action_result, AGARI_GET_POLICY_EVENT_ENDPOINT.format(id=policy_event_id), headers=self._headers)
                if phantom.is_fail(ret_val):
                    non_ingested_policy_ids.append(str(policy_event_id))
                    continue

                message_id = policy_event.get('alert_event', {}).get('collector_message_id')
                if not message_id:
                    non_ingested_policy_ids.append(str(policy_event_id))
                    continue

                ret_val, _ = self._make_rest_call_helper(action_result, AGARI_GET_MESSAGE_ENDPOINT.format(id=message_id), headers=self._headers, params=message_params)
                if phantom.is_fail(ret_val):
                    non_ingested_policy_ids.append(str(policy_event_id))
                    error_msg = action_result.get_message()
                    if AGARI_ERR_ADD_FIELDS in error_msg:
                        return action_result.get_status(), []
                    continue
                break
            except:
                non_ingested_policy_ids.append(str(policy_event_id))
                continue
        else:
            # Nothing to ingest. Hence, returning with the policy event IDs.
            return action_result.set_status(phantom.APP_ERROR, AGARI_ERR_NO_POLICY_EVENT_INGESTED.format(', ID: '.join(non_ingested_policy_ids))), []

        fetched_data = []
        action_result_list = [ActionResult() for _ in range(len(alert_events))]
        message_params_list = [message_params] * len(alert_events)
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            fetched_data = executor.map(self._get_results_helper, alert_events, action_result_list, message_params_list)

        filtered_fetched_data = [data for data in fetched_data if data]

        return phantom.APP_SUCCESS, filtered_fetched_data

    def _get_severity_from_message_trust_score(self, message_trust_score):
        """
        Decide the severity based on the message trust score.

        :param message_trust_score: message trust score
        :return: severity
        """
        severity = 'Low'
        try:
            message_trust_score = float(message_trust_score)
            if message_trust_score <= 1:
                severity = 'High'
            elif message_trust_score > 1 and message_trust_score <= 5:
                severity = 'Medium'
            else:
                severity = 'Low'
        except:
            pass
        return severity

    def _get_container_data(self, policy_event, severity):
        """
        Add data to the container.

        :param policy_event: policy event data
        :param severity: severity
        :return: container dictionary
        """
        policy_event_id = policy_event.get('id')
        policy_name = policy_event.get('alert_definition_name')
        created_at = policy_event.get('created_at')
        # Add container data
        container = {
            "name": "{} - {}[{}]".format(created_at, policy_name, policy_event_id),
            "source_data_identifier": "{} {}".format(policy_event_id, policy_name),
            "severity": severity
        }

        return container

    def _get_message_artifact_data(self, message, cef_mapping, severity):
        """
        Add message data to the artifact.

        :param message: message data
        :param cef_mapping: mapping between the existing and new keys
        :param severity: severity
        :return: message artifact dictionary
        """
        # Construct artifact
        message_id = message.get('id')
        cef = self._remap_cef(message, cef_mapping)
        artifact = {
            "source_data_identifier": message_id,
            "name": "Message Artifact",
            "cef": cef,
            "severity": severity
        }

        return artifact

    def _get_policy_event_artifact_data(self, policy_event):
        """
        Add policy event data to the artifact.

        :param policy_event: policy event data
        :return: policy event artifact dictionary
        """
        # Construct artifact
        policy_event_id = policy_event.get('id')
        artifact = {
            "source_data_identifier": policy_event_id,
            "name": "Policy Event Artifact",
            "cef": policy_event,
            "severity": 'Low'
        }

        return artifact

    def _save_results(self, action_result, results, update_state_after, cef_mapping, sort):
        """
        Ingest policy events as container and messages as artifact.

        :param action_result: object of ActionResult class
        :param results: data to ingest
        :param update_state_after: threshold after which state file will be updated
        :param cef_mapping: mapping between the old and the new cef
        :param sort: sort direction
        :return: phantom.APP_SUCCESS
        """
        self.save_progress("Ingesting the data")
        self.debug_print("Ingesting the data")
        count = 1

        for data in results:
            policy_event_id = data.get('policy_event', {}).get('id')
            policy_event = data.get('policy_event', {})
            message = data.get('message', {})
            severity = self._get_severity_from_message_trust_score(message.get('message_trust_score', '0'))
            container = self._get_container_data(policy_event, severity)
            message_artifact = self._get_message_artifact_data(message, cef_mapping, severity)
            policy_event_artifact = self._get_policy_event_artifact_data(policy_event)

            status, message, container_id = self.save_container(container)
            if phantom.is_fail(status):
                self.debug_print("Error occurred while saving the container: ID {}: {}".format(container_id, message))
                continue

            policy_event_artifact['container_id'] = container_id
            message_artifact['container_id'] = container_id
            status, message, _ = self.save_artifacts([policy_event_artifact, message_artifact])
            if phantom.is_fail(status):
                self.debug_print("Error occurred while saving the artifact: {}".format(message))
                continue

            # Update state if the required number of container are ingested as per 'update_state_after'
            if count == update_state_after and not self._is_poll_now and sort == "oldest_first":
                self._state[AGARI_LAST_INGESTED_POLICY_EVENT_DATE] = policy_event.get("created_at")
                self._state[AGARI_LAST_INGESTED_POLICY_EVENT_ID] = policy_event_id
                self.save_state(self._state)
                self.debug_print(AGARI_INGESTION_STATUS_UPDATED)
                count = 0

            count += 1

            self.save_progress("Policy event ID ({}) is ingested in container ID ({})".format(policy_event_id, container_id))
            self.debug_print("Policy event ID ({}) is ingested in container ID ({})".format(policy_event_id, container_id))

        if not self._is_poll_now:
            # Index will be 0 for latest first as we are fetching the data in descending order
            index = 0 if sort == "latest_first" else -1

            # Update state after polling cycle is complete
            if results:
                self._state[AGARI_LAST_INGESTED_POLICY_EVENT_DATE] = results[index].get('policy_event', {}).get('created_at')
                self._state[AGARI_LAST_INGESTED_POLICY_EVENT_ID] = results[index].get('policy_event', {}).get('id')
                self.save_state(self._state)
                self.debug_print(AGARI_INGESTION_STATUS_UPDATED)
                self.save_progress(AGARI_INGESTION_STATUS_UPDATED)

        return phantom.APP_SUCCESS

    def _handle_on_poll(self, param):
        """
        Perform the on poll ingest functionality.

        :param param: Dictionary of input parameters
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()

        self._is_poll_now = self.is_poll_now()

        # Validate ingestion asset configuration parameters
        self.debug_print("Validate ingestion asset configuration parameters")
        self.save_progress("Validate ingestion asset configuration parameters")
        ret_val, updated_params = self._validate_ingestion_params(action_result, config)
        if phantom.is_fail(ret_val):
            self.debug_print("Asset configuration parameters validation failed")
            self.save_progress("Asset configuration parameters validation failed")
            return action_result.get_status()

        update_state_after = updated_params.pop('update_state_after')
        cef_mapping = None
        if updated_params.get('cef_mapping'):
            cef_mapping = updated_params.pop('cef_mapping')

        if self._is_poll_now:
            max_results = param.get('container_count', config.get('max_results', AGARI_DEFAULT_MAX_RESULTS))
        else:
            max_results = config.get('max_results', AGARI_DEFAULT_MAX_RESULTS)
        # Integer validation for 'max_results' parameter
        ret_val, max_results = self._validate_integer(action_result, max_results, 'max_results')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Fetch results
        self.debug_print("Fetch results")
        self.save_progress("Fetch results")
        ret_val, results = self._get_results(action_result, updated_params, max_results)
        if phantom.is_fail(ret_val):
            self.debug_print("Failed to fetch the results")
            self.save_progress("Failed to fetch the results")
            return action_result.get_status()

        # Save fetched results
        self.debug_print("Saving the results")
        self.save_progress("Saving the results")
        ret_val = self._save_results(action_result, results, update_state_after, cef_mapping, config['sort'])
        if phantom.is_fail(ret_val):
            self.debug_print("Failed to save the results")
            self.save_progress("Failed to save the results")
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """
        Get current action identifier and call member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """
        # Get the action that we are supposed to execute for this App Run
        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS

        self.debug_print("action_id: {}".format(self.get_action_identifier()))

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            "test_connectivity": self._handle_test_connectivity,
            "get_policy_event": self._handle_get_policy_event,
            "get_message": self._handle_get_message,
            "remediate_message": self._handle_remediate_message,
            "list_policy_events": self._handle_list_policy_events,
            "list_messages": self._handle_list_messages,
            "on_poll": self._handle_on_poll,
        }

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            ret_val = action_function(param)

        return ret_val

    def initialize(self):
        """
        Initialize the global variables with its value and validate it.

        This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            return self.set_status(phantom.APP_ERROR, AGARI_STATE_FILE_CORRUPT_ERR)

        # get the asset config
        config = self.get_config()

        self._client_id = config.get('client_id')
        self._client_secret = config.get('client_secret')
        self._access_token = self._state.get(AGARI_OAUTH_TOKEN_STRING, {}).get(AGARI_OAUTH_ACCESS_TOKEN_STRING)
        self._current_utc_time = datetime.utcnow()

        ret_val, self._max_workers = self._validate_integer(self, config.get('max_workers_for_polling', AGARI_DEFAULT_MAX_WORKERS), 'max workers for polling')
        if phantom.is_fail(ret_val):
            return self.get_status()

        self._headers = {
            "Accept": "application/json",
            "User-Agent": AGARI_USER_AGENT.format(product_version=self.get_product_version()),
            "Authorization": AGARI_AUTHORIZATION_HEADER.format(token=self._access_token)
        }

        # get the session object
        try:
            self._session = self.requests_retry_session(retries=AGARI_DEFAULT_NUM_RETRIES, backoff_factor=AGARI_DEFAULT_BACKOFF_FACTOR)
        except:
            return self.set_status(phantom.APP_ERROR, AGARI_ERR_CREATING_SESSION_OBJECT)

        return phantom.APP_SUCCESS

    def finalize(self):
        """
        Perform some final operations or clean up operations.

        This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
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
            login_url = AgariConnector._get_phantom_base_url() + '/login'

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

        connector = AgariConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
