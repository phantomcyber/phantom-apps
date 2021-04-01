# File: passivetotal_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.utils as ph_utils

# THIS Connector imports
from passivetotal_consts import *

from datetime import datetime
from datetime import timedelta
from bs4 import UnicodeDammit
import requests
import json
import ipaddress
import sys


class PassivetotalConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(PassivetotalConnector, self).__init__()

    def initialize(self):

        # Base URL
        self._base_url = PASSIVETOTAL_REST_API_URL
        if self._base_url.endswith('/'):
            self._base_url = self._base_url[:-1]

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR,
                                   "Error occurred while fetching the Phantom server's Python major version")

        self._host = ph_utils.get_host_from_url(self._base_url)
        self._params = {}
        self._headers = {'Content-Type': 'application/json'}

        return phantom.APP_SUCCESS

    def _handle_py_ver_compat_for_input_str(self, input_str, always_encode=False):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :param always_encode: Used if the string needs to be encoded for python 3
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and (self._python_version == 2 or always_encode):
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

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
                    error_code = PASSIVETOTAL_ERR_CODE_UNAVAILABLE
                    error_msg = e.args[0]
            else:
                error_code = PASSIVETOTAL_ERR_CODE_UNAVAILABLE
                error_msg = PASSIVETOTAL_ERR_MSG_UNAVAILABLE
        except:
            error_code = PASSIVETOTAL_ERR_CODE_UNAVAILABLE
            error_msg = PASSIVETOTAL_ERR_MSG_UNAVAILABLE

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = PASSIVETOTAL_UNICODE_DAMMIT_TYPE_ERR_MSG
        except:
            error_msg = PASSIVETOTAL_ERR_MSG_UNAVAILABLE

        try:
            if error_code in PASSIVETOTAL_ERR_CODE_UNAVAILABLE:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(PASSIVETOTAL_PARSE_ERR_MSG)
            error_text = PASSIVETOTAL_PARSE_ERR_MSG

        return error_text

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address

        try:
            ipaddress.ip_address(str(ip_address_input))
        except:
            return False

        return True

    def _is_date(self, candidate):
        """Checks if a given string can be parsed into a date"""
        try:
            datetime.strptime(candidate, '%Y-%m-%d')
            return True
        except ValueError:
            return False

    def _is_from_to_valid_date(self, from_date, to_date):
        """Checks if a given 'from date' should not greater than the 'to date'"""
        from_date = datetime.strptime(from_date, '%Y-%m-%d')
        to_date = datetime.strptime(to_date, '%Y-%m-%d')
        if from_date <= to_date:
            return True
        return False

    def _validate_integer(self, action_result, parameter, key):
        """ This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: action parameter key
        :return: integer value of the parameter or None in case of failure
        """

        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(key)), None
        return phantom.APP_SUCCESS, parameter

    def _make_rest_call(self, endpoint, request_params, action_result):

        # init the return values
        resp_json = None
        status_code = None

        # update params
        params = dict(self._params)
        params.update(request_params)

        # get config
        config = self.get_config()

        # make the call
        try:
            r = requests.get('{}{}'.format(self._base_url, endpoint),
                             auth=(self._handle_py_ver_compat_for_input_str(config[PASSIVETOTAL_JSON_KEY], True), config[PASSIVETOTAL_JSON_SECRET]),
                             params=params,
                             headers=self._headers)
        except Exception as exc:
            return (action_result.set_status(phantom.APP_ERROR, "{}. {}".format(PASSIVETOTAL_ERR_SERVER_CONNECTION,
                                                                                self._get_error_message_from_exception(
                                                                                    exc))), resp_json, status_code)

        # It's ok if r.text is None, dump that
        action_result.add_debug_data({'r_text': r.text if r else 'r is None'})

        # get the status code, use from here on
        status_code = r.status_code

        # Try parsing the result as a json
        try:
            resp_json = r.json()
        except:
            # not a json, dump whatever was returned into the action result
            details = self._handle_py_ver_compat_for_input_str(r.text.replace('{', '').replace('}', ''))
            action_result.set_status(phantom.APP_ERROR,
                                     PASSIVETOTAL_ERR_FROM_SERVER.format(status=r.status_code, message=details))
            return phantom.APP_ERROR, resp_json, status_code

        # Check if it's a success
        if 200 <= status_code <= 299:
            # Success
            return phantom.APP_SUCCESS, resp_json, status_code

        # Error, dump the cleansed json into the details
        details = json.dumps(resp_json).replace('{', '').replace('}', '')
        action_result.set_status(phantom.APP_ERROR,
                                 PASSIVETOTAL_ERR_FROM_SERVER.format(status=r.status_code, message=details))
        return phantom.APP_ERROR, resp_json, status_code

    def _test_connectivity(self, param):

        # Progress
        self.save_progress(PASSIVETOTAL_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        endpoint = '/enrichment'

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress(PASSIVETOTAL_MSG_GET_DOMAIN_TEST)

        ret_val, response, status_code = self._make_rest_call(endpoint, {'query': 'phantomcyber.com'}, action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            self.save_progress(PASSIVETOTAL_ERR_CONNECTIVITY_TEST)
            return action_result.get_status()

        self.save_progress(PASSIVETOTAL_SUCC_CONNECTIVITY_TEST)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_domain(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param[PASSIVETOTAL_JSON_DOMAIN]
        start_time = param.get(PASSIVETOTAL_JSON_FROM)
        end_time = param.get(PASSIVETOTAL_JSON_TO)

        if start_time and not self._is_date(start_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "Incorrect date format for 'From' parameter, it should be YYYY-MM-DD")
        if end_time and not self._is_date(end_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "Incorrect date format for 'To' parameter, it should be YYYY-MM-DD")

        if start_time and end_time and not self._is_from_to_valid_date(start_time, end_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "'From' date should not be greater than the 'To' date")

        # Progress
        self.save_progress(PASSIVETOTAL_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Add the extra data that will include info about this domain
        extra_data = action_result.add_data({})
        summary = action_result.update_summary({})

        ret_val = self._get_common_info(domain, extra_data, summary, action_result, param)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Dynamic
        self.save_progress('Querying Dynamic domain information')
        ret_val, response, status_code = self._make_rest_call('/dynamic', {'query': domain}, action_result)

        if ret_val and response:
            results = response.get('results')
            if results:
                extra_data[PASSIVETOTAL_JSON_DYNAMIC] = results

        # Subdomains
        self.save_progress('Getting Sub-domain list')
        ret_val, response, status_code = self._make_rest_call('/subdomains', {'query': domain}, action_result)

        if ret_val and response:
            results = response.get('results')
            if results:
                extra_data[PASSIVETOTAL_JSON_SUBDOMAINS] = results

        if (not extra_data) and (phantom.is_fail(ret_val)):
            # We don't seem to have any data _and_ the last call failed
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_common_info(self, query_param, data, summary, action_result, param={}):

        # Metadata
        self.save_progress('Querying Metadata')
        ret_val, response, status_code = self._make_rest_call('/enrichment', {'query': query_param}, action_result)

        if not ret_val:
            if isinstance(response.get('error'), dict):
                message = self._handle_py_ver_compat_for_input_str(response.get('error', {}).get('message', ''))
            elif isinstance(response.get('error'), str):
                message = "{} {}".format(self._handle_py_ver_compat_for_input_str(response.get('error')),
                                         self._handle_py_ver_compat_for_input_str(response.get('message')))
            else:
                message = self._handle_py_ver_compat_for_input_str(str(response))

            if QUOTA_EXCEEDED_MSG in message.lower() or QUOTA_EXCEEDED_MSG_API in message.lower():
                return action_result.get_status()

        if ret_val and response:

            data[PASSIVETOTAL_JSON_METADATA] = response

            if 'everCompromised' in response:
                summary.update({PASSIVETOTAL_JSON_EVER_COMPROMISED: response['everCompromised']})

            if 'autonomousSystemName' in response:
                summary.update({PASSIVETOTAL_JSON_AS_NAME: response['autonomousSystemName']})

            if 'country' in response:
                summary.update({PASSIVETOTAL_JSON_COUNTRY: response['country']})

            if 'dynamicDns' in response:
                summary.update({PASSIVETOTAL_JSON_DYNAMIC_DOMAIN: response['dynamicDns']})

        # Take care of passive calls
        request_params = {'query': query_param}
        start_time = param.get(PASSIVETOTAL_JSON_FROM)
        end_time = param.get(PASSIVETOTAL_JSON_TO)

        if start_time:
            request_params.update({'start': start_time})
        else:
            request_params.update({'start': (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")})

        if end_time:
            request_params.update({'end': end_time})

        # Passive
        self.save_progress('Querying Passive information')
        ret_val, response, status_code = self._make_rest_call('/dns/passive', request_params, action_result)

        if ret_val and response:
            data[PASSIVETOTAL_JSON_PASSIVE] = response
            summary.update({PASSIVETOTAL_JSON_FIRST_SEEN: response.get('firstSeen', ''),
                            PASSIVETOTAL_JSON_LAST_SEEN: response.get('lastSeen', '')})

        # Unique
        self.save_progress('Querying for Unique domain info')
        ret_val, response, status_code = self._make_rest_call('/dns/passive/unique', request_params, action_result)

        if ret_val and response:
            results = response.get('results')
            if results:
                data[PASSIVETOTAL_JSON_UNIQUE] = results
                summary.update({PASSIVETOTAL_JSON_TOTAL_UNIQUE_DOMAINS: len(results)})

        # Classification
        self.save_progress('Querying Classification')
        ret_val, response, status_code = self._make_rest_call('/actions/classification', {'query': query_param},
                                                              action_result)

        if ret_val and response:
            classification = response.get('classification', '')
            data[PASSIVETOTAL_JSON_CLASSIFICATION] = response
            summary.update({PASSIVETOTAL_JSON_CLASSIFICATION: classification})

        # Tags
        self.save_progress('Querying Tags')
        ret_val, response, status_code = self._make_rest_call('/actions/tags', {'query': query_param}, action_result)

        if ret_val and response:
            tags = response.get('tags')
            if tags:
                data[PASSIVETOTAL_JSON_TAGS] = tags

        # Sinkhole
        self.save_progress('Querying Sinkhole information')
        ret_val, response, status_code = self._make_rest_call('/actions/sinkhole', {'query': query_param},
                                                              action_result)

        if ret_val and response:
            if 'sinkhole' in response:
                data[PASSIVETOTAL_JSON_SINKHOLE] = response['sinkhole']
                summary.update({PASSIVETOTAL_JSON_SINKHOLE: response['sinkhole']})

        # Ever Compromised
        self.save_progress('Querying Compromising information')
        ret_val, response, status_code = self._make_rest_call('/actions/ever-compromised', {'query': query_param},
                                                              action_result)

        if ret_val and response:
            if 'everCompromised' in response:
                data[PASSIVETOTAL_JSON_EVER_COMPROMISED] = response['everCompromised']
                summary.update({PASSIVETOTAL_JSON_EVER_COMPROMISED: response['everCompromised']})

        """
        # Watching
        self.save_progress('Querying Watchlist information')
        ret_val, response, status_code = self._make_rest_call('/watching', {'query': query_param}, action_result)

        if (ret_val) and (response):
            results = response.get('results')
            if (results):
                data[PASSIVETOTAL_JSON_WATCHING] = results
                summary.update({PASSIVETOTAL_JSON_BEING_WATCHED: results.get('watching', '')})
        """

        return phantom.APP_SUCCESS

    def _whois_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param[PASSIVETOTAL_JSON_IP]

        # Validation for checking valid IP or not (IPV4 as well as IPV6)
        if not self._is_ip(ip):
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid IPV4 or IPV6 address')

        # Progress
        self.save_progress(PASSIVETOTAL_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Whois info
        ret_val, response, status_code = self._make_rest_call('/whois', {'query': ip}, action_result)

        if phantom.is_fail(ret_val):
            # We don't seem to have any data _and_ the last call failed
            return action_result.get_status()

        if not response:
            # return with a message
            return action_result.set_status(phantom.APP_SUCCESS, "No registrant info found")

        action_result.add_data(response)
        registrant = response.get('registrant')

        if not registrant:
            # return with a message
            return action_result.set_status(phantom.APP_SUCCESS, "No registrant info found")

        action_result.update_summary({
            'city': registrant.get('city'),
            'country': registrant.get('country'),
            'organization': registrant.get('organization')})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _whois_domain(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param[PASSIVETOTAL_JSON_DOMAIN]

        # Progress
        self.save_progress(PASSIVETOTAL_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Whois info
        ret_val, response, status_code = self._make_rest_call('/whois', {'query': domain}, action_result)

        if phantom.is_fail(ret_val):
            # We don't seem to have any data _and_ the last call failed
            return action_result.get_status()

        if not response:
            # return with a message
            return action_result.set_status(phantom.APP_SUCCESS, "No registrant info found")

        action_result.add_data(response)
        registrant = response.get('registrant')

        if not registrant:
            # return with a message
            return action_result.set_status(phantom.APP_SUCCESS, "No registrant info found")

        action_result.update_summary({
            'city': registrant.get('city'),
            'country': registrant.get('country'),
            'organization': registrant.get('organization')})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param[PASSIVETOTAL_JSON_IP]
        start_time = param.get(PASSIVETOTAL_JSON_FROM)
        end_time = param.get(PASSIVETOTAL_JSON_TO)

        # Validation for checking valid IP or not (IPV4 as well as IPV6)
        if not self._is_ip(ip):
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid IPV4 or IPV6 address')

        if start_time and not self._is_date(start_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "Incorrect date format for 'From' parameter, it should be YYYY-MM-DD")

        if end_time and not self._is_date(end_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "Incorrect date format for 'To' parameter, it should be YYYY-MM-DD")

        if start_time and end_time and not self._is_from_to_valid_date(start_time, end_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "'From' date should not be greater than the 'To' date")

        # Progress
        self.save_progress(PASSIVETOTAL_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Add the extra data that will include info about this ip
        extra_data = action_result.add_data({})
        summary = action_result.update_summary({})

        ret_val = self._get_common_info(ip, extra_data, summary, action_result, param)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # SSL Certificates
        ret_val, response, status_code = self._make_rest_call('/ssl-certificate/history', {'query': ip}, action_result)

        try:
            if ret_val and response:
                if response['results']:
                    extra_data[PASSIVETOTAL_JSON_SSL_CERTIFICATES] = response['results']
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, PASSIVETOTAL_RESPONSE_ERR_MSG)

        if (not extra_data) and (phantom.is_fail(ret_val)):
            # We don't seem to have any data _and_ the last call failed
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_certificate_hash(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        query = param[PASSIVETOTAL_JSON_QUERY]

        if len(query) != 40:
            # Superficial input validation whether the input is a potential SHA1 hash to catch common errors
            return action_result.set_status(phantom.APP_ERROR, 'Please provide a valid SHA1 Hash')

        extra_data = action_result.add_data({})
        summary = action_result.update_summary({})

        self.save_progress('Querying Certificate by Hash')
        ret_val, response, status_code = self._make_rest_call('/ssl-certificate', {'query': query}, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            if ret_val and response:
                extra_data[PASSIVETOTAL_JSON_SSL_CERTIFICATE] = response["results"]
                summary.update({PASSIVETOTAL_JSON_TOTAL_RECORDS: len(response['results'])})
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, PASSIVETOTAL_RESPONSE_ERR_MSG)

        self.save_progress('Querying Certificate History by Hash')
        ret_val, response, status_code = self._make_rest_call('/ssl-certificate/history', {'query': query},
                                                              action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            if ret_val and response:
                extra_data[PASSIVETOTAL_JSON_SSL_CERTIFICATES] = response["results"]
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, PASSIVETOTAL_RESPONSE_ERR_MSG)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_certificate(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param[PASSIVETOTAL_JSON_QUERY]
        field = param[PASSIVETOTAL_JSON_FIELD]
        if field not in PASSIVETOTAL_FIELD_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, PASSIVETOTAL_VALUE_LIST_VALIDATION_MSG.format(PASSIVETOTAL_FIELD_VALUE_LIST, 'field'))

        params = {
            "query": query,
            "field": field
        }

        extra_data = action_result.add_data({})
        summary = action_result.update_summary({})

        ret_val, response, status_code = self._make_rest_call('/ssl-certificate/search', params, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            if ret_val and response:
                extra_data[PASSIVETOTAL_JSON_SSL_CERTIFICATES] = response["results"]
                summary.update({PASSIVETOTAL_JSON_TOTAL_RECORDS: len(response['results'])})
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, PASSIVETOTAL_RESPONSE_ERR_MSG)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_host_components(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param[PASSIVETOTAL_JSON_QUERY]
        start_time = param.get(PASSIVETOTAL_JSON_FROM)
        end_time = param.get(PASSIVETOTAL_JSON_TO)

        # Check the 'page' parameter
        ret_val, page = self._validate_integer(action_result, param.get(PASSIVETOTAL_JSON_PAGE, '0'), PAGE_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if start_time and not self._is_date(start_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "Incorrect date format for 'From' parameter, it should be YYYY-MM-DD")

        if end_time and not self._is_date(end_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "Incorrect date format for 'To' parameter, it should be YYYY-MM-DD")

        if start_time and end_time and not self._is_from_to_valid_date(start_time, end_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "'From' date should not be greater than the 'To' date")

        params = {
            "query": query,
            "start": start_time,
            "end": end_time,
            "page": page
        }
        extra_data = action_result.add_data({})
        summary = action_result.update_summary({})

        ret_val, response, status_code = self._make_rest_call('/host-attributes/components', params, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            if ret_val and response:
                extra_data[PASSIVETOTAL_JSON_COMPONENTS] = response["results"]
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, PASSIVETOTAL_RESPONSE_ERR_MSG)

        if 'totalRecords' in response:
            summary.update({PASSIVETOTAL_JSON_TOTAL_RECORDS: response['totalRecords']})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_host_pairs(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        query = param[PASSIVETOTAL_JSON_QUERY]
        direction = param[PASSIVETOTAL_JSON_DIRECTION]
        start_time = param.get(PASSIVETOTAL_JSON_FROM)
        end_time = param.get(PASSIVETOTAL_JSON_TO)

        # Check the 'page' parameter
        ret_val, page = self._validate_integer(action_result, param.get(PASSIVETOTAL_JSON_PAGE, '0'), PAGE_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if direction not in PASSIVETOTAL_DIRECTION_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, PASSIVETOTAL_VALUE_LIST_VALIDATION_MSG.format(PASSIVETOTAL_DIRECTION_VALUE_LIST, 'direction'))

        if start_time and not self._is_date(start_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "Incorrect date format for 'From' parameter, it should be YYYY-MM-DD")

        if end_time and not self._is_date(end_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "Incorrect date format for 'To' parameter, it should be YYYY-MM-DD")

        if start_time and end_time and not self._is_from_to_valid_date(start_time, end_time):
            return action_result.set_status(phantom.APP_ERROR,
                                            "'From' date should not be greater than the 'To' date")

        params = {
            "query": query,
            "direction": direction,
            "start": start_time,
            "end": end_time,
            "page": page
        }

        extra_data = action_result.add_data({})
        summary = action_result.update_summary({})

        ret_val, response, status_code = self._make_rest_call('/host-attributes/pairs', params, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        try:
            if ret_val and response:
                extra_data[PASSIVETOTAL_JSON_PAIRS] = response["results"]
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, PASSIVETOTAL_RESPONSE_ERR_MSG)

        if 'totalRecords' in response:
            summary.update({PASSIVETOTAL_JSON_TOTAL_RECORDS: response['totalRecords']})

        return action_result.set_status(phantom.APP_SUCCESS)

    def validate_parameters(self, param):
        # Disable BaseConnector's validate functionality, since this App supports unicode domains and the validation
        # routines don't
        return phantom.APP_SUCCESS

    def handle_action(self, param):
        """Function that handles all the actions

            Args:

            Return:
                A status code
        """

        # Get the action that we are supposed to carry out, set it in the connection result object
        action = self.get_action_identifier()

        ret_val = phantom.APP_SUCCESS

        if action == ACTION_ID_LOOKUP_CERTIFICATE_HASH:
            ret_val = self._lookup_certificate_hash(param)
        elif action == ACTION_ID_LOOKUP_CERTIFICATE:
            ret_val = self._lookup_certificate(param)
        elif action == ACTION_ID_LOOKUP_IP:
            ret_val = self._lookup_ip(param)
        elif action == ACTION_ID_LOOKUP_DOMAIN:
            ret_val = self._lookup_domain(param)
        elif action == ACTION_ID_WHOIS_IP:
            ret_val = self._whois_ip(param)
        elif action == ACTION_ID_WHOIS_DOMAIN:
            ret_val = self._whois_domain(param)
        elif action == ACTION_ID_GET_HOST_COMPONENTS:
            ret_val = self._get_host_components(param)
        elif action == ACTION_ID_GET_HOST_PAIRS:
            ret_val = self._get_host_pairs(param)
        elif action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)

        return ret_val


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
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = PassivetotalConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        res = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(res), indent=4))

    exit(0)
