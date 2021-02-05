# File: dnsdb_connector.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
from dnsdb_consts import *

import requests
import json
import re
from bs4 import BeautifulSoup
import socket


class DnsdbConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnector's init first
        super(DnsdbConnector, self).__init__()
        self._api_key = None
        return

    # Overriding domain validation for dnsdb
    # to allow wildcard domain search
    def _validate_domain(self, param):

        if len(param) > 255:
            return False
        if phantom.is_ip(param):
            return False
        if param[-1] == '.':
            param = param[:-1]
        allowed = re.compile("(?!-)[A-Z\\d\-\_]{1,63}(?<!-')$", re.IGNORECASE)
        l = param.split('.')

        # Wildcard serch '*' is allowed in the first and
        # last subdomain only
        for idx, x in enumerate(l):
            if idx == 0 or idx == (len(l) - 1):
                if not (x == '*' or allowed.match(x)):
                    return False
            elif not allowed.match(x):
                    return False
        return True

    def initialize(self):

        config = self.get_config()
        self._api_key = config[DNSDB_JSON_API_KEY]
        self.set_validator('domain', self._validate_domain)
        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, action_result, params=None, method="get"):
        """ Function that makes the REST call to the device,
            generic function that can be called from various action handlers
        """

        rest_res = None

        error_resp_dict = {
            DNSDB_REST_RESP_RESOURCE_INCORRECT: DNSDB_REST_RESP_RESOURCE_INCORRECT_MSG,
            DNSDB_REST_RESP_ACCESS_DENIED: DNSDB_REST_RESP_ACCESS_DENIED_MSG,
            DNSDB_REST_RESP_LIC_EXCEED: DNSDB_REST_RESP_LIC_EXCEED_MSG,
            DNSDB_REST_RESP_OVERLOADED: DNSDB_REST_RESP_OVERLOADED_MSG
        }

        """Get or post or put, whatever the caller asked us to use,
        if not specified the default will be 'get' """

        try:
            request_func = getattr(requests, method)
        except:
            """handle the error in case the caller specified
            a non-existent method"""
            self.debug_print(DNSDB_ERR_API_UNSUPPORTED_METHOD.format(method=method))

            # set the action_result status to error, the handler function
            # will most probably return as is
            return (action_result.set_status(phantom.APP_ERROR, DNSDB_ERR_API_UNSUPPORTED_METHOD),
                    rest_res)

        # Headers to be supplied
        headers = {
            'X-API-Key': self._api_key,
            'Accept': 'application/json'
        }

        # Make the call
        try:
            r = request_func(
                DNSDB_BASE_URL + endpoint,
                headers=headers, params=params)
        except Exception as e:
            self.debug_print(DNSDB_ERR_SERVER_CONNECTION)
            # set the action_result status to error, the handler function
            # will most probably return as is
            return (action_result.set_status(phantom.APP_ERROR, DNSDB_ERR_SERVER_CONNECTION, e),
                    rest_res)

        if r.status_code in error_resp_dict.keys():
            self.debug_print(DNSDB_ERR_FROM_SERVER.format(status=r.status_code, detail=error_resp_dict[r.status_code]))
            # set the action_result status to error, the handler function
            # will most probably return as is
            return (action_result.set_status(phantom.APP_ERROR, DNSDB_ERR_FROM_SERVER, status=r.status_code,
                                             detail=error_resp_dict[r.status_code]),
                    rest_res)

        # Return code 404 is not considered as failed action.
        # The requested resource is unavailable
        if r.status_code == DNSDB_REST_RESP_RESOURCE_NOT_FOUND:
            return (phantom.APP_SUCCESS, {DNSDB_REST_RESP_RESOURCE_NOT_FOUND_MSG: True})

        # Try parsing the json, even in the case of an HTTP error
        # the data might contain a json of details 'message'
        content_type = r.headers['content-type']
        if content_type.find('json') != -1:
            try:
                # The reponse returned can have multiple json seperated
                # by newline character
                resp_arr = ((r.text).encode('utf-8')).splitlines()
                rest_res = []
                for res in resp_arr:
                    res = res.rstrip()
                    if res:
                        rest_res.append(json.loads(res))
            except Exception as e:
                # r.text is guaranteed to be not None,
                # it will be empty, but not None
                msg_string = DNSDB_ERR_JSON_PARSE.format(
                    raw_text=r.text)
                self.debug_print(msg_string)
                # set the action_result status to error, the handler function
                # will most probably return as is
                return (action_result.set_status(phantom.APP_ERROR,
                                                 msg_string, e), rest_res)

        else:
            rest_res = r.text

        if r.status_code == DNSDB_REST_RESP_SUCCESS:
            return (phantom.APP_SUCCESS, {DNSDB_JSON_RESPONSE: rest_res})

        # see if an error message is present
        message = self._normalize_reply(rest_res) if rest_res else DNSDB_REST_RESP_OTHER_ERROR_MSG

        # All other response codes from Rest call are failures
        self.debug_print(DNSDB_ERR_FROM_SERVER.format(status=r.status_code, detail=message))
        # set the action_result status to error, the handler function
        # will most probably return as is
        return (action_result.set_status(phantom.APP_ERROR, DNSDB_ERR_FROM_SERVER, status=r.status_code,
                                         detail=message),
                rest_res)

    def _test_connectivity(self, param):

        action_result = ActionResult()
        self.save_progress(DNSDB_TEST_CONNECTIVITY_MSG)

        ret_val, json_resp = self._make_rest_call(
            (DNSDB_ENDPOINT_DOMAIN).format(
                domain=DNSDB_TEST_CONN_DOMAIN),
            action_result)

        # Forcefully set the status of the BaseConnector to failure, since
        # action_result is not added to the BaseConnector.
        if (phantom.is_fail(ret_val)):
            self.save_progress(action_result.get_message())
            self.set_status(
                phantom.APP_ERROR, DNSDB_TEST_CONN_FAIL)
            return action_result.get_status()

        self.set_status_save_progress(
            phantom.APP_SUCCESS, DNSDB_TEST_CONN_SUCC)
        return action_result.get_status()

    def _is_ipv6(self, address):

        try:
            socket.inet_pton(socket.AF_INET6, address)

        except socket.error:  # not a valid v6 address
            return False

        return True

    def _lookup_domain(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Getting mandatory input parameters
        domain = param[DNSDB_JSON_DOMAIN]
        # Getting optional input parameters
        record_type = param.get(DNSDB_JSON_TYPE, 'ANY')
        zone = param.get(DNSDB_JSON_ZONE)

        summary_data = action_result.update_summary({})

        # Constructing request parameters based on input
        # Validating the input parameters provided
        # Would be used during REST call
        ret_val, url_params = self._get_url_params(param, action_result)

        # Something went wrong while validing input parameters
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Endpoint as per parameter given
        if zone:
            endpoint = (DNSDB_ENDPOINT_DOMAIN_TYPE_ZONE).format(domain=domain, type=record_type, zone=zone)
        else:
            endpoint = (DNSDB_ENDPOINT_DOMAIN_TYPE).format(domain=domain, type=record_type)

        ret_val, response = self._make_rest_call(endpoint, action_result, params=url_params)

        # Something went wrong with the request
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # No data is considered as app success
        if (response.get(DNSDB_REST_RESP_RESOURCE_NOT_FOUND_MSG)):
            return action_result.set_status(phantom.APP_SUCCESS, DNSDB_DATA_NOT_AVAILABLE_MSG)

        json_resp = response.get(DNSDB_JSON_RESPONSE)

        for resp in json_resp:

            rdata = resp.get('rdata', [])

            for i, curr_rdata in enumerate(rdata):

                # if type is SOA, split the data and strip it, even if . is not present, this
                # will still execute without an error
                if resp.get('rrtype') == 'SOA':
                    temp_res = curr_rdata.split(' ')
                    temp_res = [x.rstrip('.') for x in temp_res]
                    temp_header = ['rdata_origin', 'rdata_mail_addr',
                                   'rdata_serial', 'rdata_refresh',
                                   'rdata_retry', 'rdata_expire',
                                   'rdata_minimum']
                    rdata[i] = dict(zip(temp_header, temp_res))

                # if type is MX, split the data and strip it, even if . is not present, this
                # will still execute without an error
                elif resp.get('rrtype') == 'MX':
                    temp_res = curr_rdata.split(' ')
                    temp_res = [x.rstrip('.') for x in temp_res]
                    temp_header = ['rdata_preference', 'rdata_mail_exchange']
                    rdata[i] = dict(zip(temp_header, temp_res))

                # for other types, first strip it, even if . is not present, this
                # will still execute without an error
                else:
                    curr_rdata = curr_rdata.rstrip('.')
                    rdata[i] = curr_rdata

            if ('rrname' in resp):
                resp['rrname'] = resp['rrname'].rstrip('.')

            if ('bailiwick' in resp):
                resp['bailiwick'] = resp['bailiwick'].rstrip('.')

            # Response from the API is list of rrset.
            # Adding Each data of list to action_result
            action_result.add_data(resp)

        summary_data['total_items'] = len(json_resp)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Getting mandatory input parameter
        ip = param[DNSDB_JSON_IP]
        # Getting optional input parameter
        network_prefix = param.get(DNSDB_JSON_NETWORK_PREFIX)

        summary_data = action_result.update_summary({})

        if network_prefix:
            # Validate network prefix
            # network prefix valid if between 0 and 32 for ipv4
            if phantom.is_ip(ip):
                net_prefix_valid = 0 <= int(network_prefix) <= 32
            else:
                # network prefix valid if between 0 and 128 for ipv6
                net_prefix_valid = 0 <= int(network_prefix) <= 128

            if not net_prefix_valid:
                self.debug_print(DNSDB_ERR_INVALID_NETWORK_PREFIX.format(prefix=network_prefix))
                return action_result.set_status(
                    phantom.APP_ERROR,
                    DNSDB_ERR_INVALID_NETWORK_PREFIX.format(prefix=network_prefix))

        # Endpoint as per parameter given
        if network_prefix:
            endpoint = (DNSDB_ENDPOINT_IP_PREFIX).format(ip=ip, prefix=network_prefix)
        else:
            endpoint = (DNSDB_ENDPOINT_IP).format(ip=ip)

        # Constructing request parameters based on input
        # Validating the input parameters provided
        # Would be used during REST call
        ret_val, url_params = self._get_url_params(param, action_result)

        # Something went wrong while validing input parameters
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, response = self._make_rest_call(endpoint, action_result, params=url_params)

        # Something went wrong with the request
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # No data is considered as app success
        if (response.get(DNSDB_REST_RESP_RESOURCE_NOT_FOUND_MSG)):
            return action_result.set_status(phantom.APP_SUCCESS, DNSDB_DATA_NOT_AVAILABLE_MSG)

        json_resp = response.get(DNSDB_JSON_RESPONSE)
        # To display count of domains in summary data
        count_domain = set()

        for resp in json_resp:

            if ('rrname' in resp):
                resp['rrname'] = resp['rrname'].rstrip('.')
                count_domain.add(resp['rrname'])

            # Response from the API is list of rdata.
            # Adding Each data of list to action_result
            action_result.add_data(resp)

        summary_data['total_domains'] = len(count_domain)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_url_params(self, param, action_result):
        """ Function to get input parameters and return error in case of
            validation fails
        """

        url_params = {}
        # Getting optional input parameter
        limit = param.get(DNSDB_JSON_LIMIT, 200)
        record_seen_before = param.get(DNSDB_JSON_RECORD_SEEN_BEFORE)
        record_seen_after = param.get(DNSDB_JSON_RECORD_SEEN_AFTER)

        if record_seen_before:
            # Validating the input for time format(YYYY-MM-DDThh:mm:ssZ or epoch)
            if not self._is_valid_time(record_seen_before):
                return (action_result.set_status(phantom.APP_ERROR,
                                                 (DNSDB_ERR_INVALID_TIME_FORMAT).format(time=record_seen_before)),
                        None)

        if record_seen_after:
            # Validating the input for time format(YYYY-MM-DDThh:mm:ssZ or epoch)
            if not self._is_valid_time(record_seen_after):
                return (action_result.set_status(phantom.APP_ERROR,
                                                 (DNSDB_ERR_INVALID_TIME_FORMAT).format(time=record_seen_after)),
                        None)

        if limit:
            limit_valid = int(limit) > 0
            if not limit_valid:
                return (action_result.set_status(phantom.APP_ERROR,
                                                 (DNSDB_ERR_INVALID_LIMIT).format(limit=limit)),
                        None)

            url_params[DNSDB_JSON_LIMIT] = limit

        if record_seen_before and record_seen_after:
            url_params['time_first_after'] = record_seen_after
            url_params['time_last_before'] = record_seen_before
        else:
            if record_seen_before:
                url_params['time_first_before'] = record_seen_before
            elif record_seen_after:
                url_params['time_last_after'] = record_seen_after

        return (phantom.APP_SUCCESS, url_params)

    def _is_valid_time(self, time):
        """ Function that validates given time,
            time can be epoch time or UTC ISO format.
            e.g.1380139330 or 2016-07-12T00:00:00Z
        """

        if len(time) == 10:
            # regular expression to validate epoch time
            reg_exp = re.compile("[0-9]{10}")

        elif len(time) == 20:
            # regular expression to validate UTC ISO time format
            # e.g. 2016-07-12T00:00:00Z
            reg_exp = re.compile('\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[1-2]\d|3'
                                 '[0-1])T(?:[0-1]\d|2[0-3]):[0-5]\d:[0-5]\dZ')

        else:
            return False

        if not reg_exp.match(time):
            return False

        return True

    def _normalize_reply(self, reply):

        try:
            soup = BeautifulSoup(reply, 'html.parser')
            return soup.text
        except Exception as e:
            self.debug_print('Handled exception', e)
            return 'Unparsable Reply. Please see the log files for the response text.'

    def handle_action(self, param):

        # Supported actions by app
        supported_actions = {
            'test_asset_connectivity': self._test_connectivity,
            'lookup_ip': self._lookup_ip,
            'lookup_domain': self._lookup_domain
        }

        action = self.get_action_identifier()

        try:
            run_action = supported_actions[action]
        except:
            raise ValueError('action %r is not supported' % action)

        return run_action(param)


if __name__ == '__main__':
    import sys
    import pudb

    pudb.set_trace()
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print json.dumps(in_json, indent=4)
        connector = DnsdbConnector()
        connector.print_progress_message = True
        connector._handle_action(json.dumps(in_json), None)
    exit(0)
