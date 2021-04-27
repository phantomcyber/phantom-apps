# File: dnsdb_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

from __future__ import print_function, unicode_literals

import dnsdb2
# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from datetime import datetime

# Local imports
from dnsdb_consts import *

import json
import re
import socket
import time


class DnsdbConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnector's init first
        super(DnsdbConnector, self).__init__()
        self._client = None
        self._api_key = None
        return

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
                    error_code = DNSDB_ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = DNSDB_ERR_CODE_MSG
                error_msg = DNSDB_ERR_MSG_UNAVAILABLE
        except:
            error_code = DNSDB_ERR_CODE_MSG
            error_msg = DNSDB_ERR_MSG_UNAVAILABLE

        try:
            if error_code in DNSDB_ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(DNSDB_PARSE_ERR_MSG)
            error_text = DNSDB_PARSE_ERR_MSG

        return error_text

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, DNSDB_VALID_INTEGER_MSG.format(key=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, DNSDB_VALID_INTEGER_MSG.format(key=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, DNSDB_NON_NEGATIVE_INTEGER_MSG.format(key=key)), None

        return phantom.APP_SUCCESS, parameter

    # Overriding domain validation for dnsdb
    # to allow wildcard domain search
    def _validate_domain(self, param):

        if len(param) > 255:
            return False
        if phantom.is_ip(param):
            return False
        if param[-1] == '.':
            param = param[:-1]
        allowed = re.compile(r"(?!-)[A-Z\\d\-_]{1,63}(?<!-')$", re.IGNORECASE)
        parts = param.split('.')

        # Wildcard search '*' is allowed in the first and
        # last subdomain only
        for idx, x in enumerate(parts):
            if idx == 0 or idx == (len(parts) - 1):
                if not (x == '*' or allowed.match(x)):
                    return False
            elif not allowed.match(x):
                return False
        return True

    def initialize(self):
        config = self.get_config()
        self._api_key = config[DNSDB_JSON_API_KEY]
        self._client = dnsdb2.Client(config[DNSDB_JSON_API_KEY])
        self.set_validator('domain', self._validate_domain)
        return phantom.APP_SUCCESS

    def _test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(DNSDB_TEST_CONNECTIVITY_MSG)

        try:
            rate = self._client.rate_limit()[DNSDB_JSON_RATE]
        except dnsdb2.exceptions.AccessDenied:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_ACCESS_DENIED_MSG)

        except dnsdb2.exceptions.QuotaExceeded:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_LIC_EXCEED_MSG)

        except Exception as e:
            self.debug_print(self._get_error_message_from_exception(e))
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_TEST_CONN_FAIL)
        self.save_progress(DNSDB_TEST_CONNECTIVITY_SUCCESS_MSG % (rate.get('limit'), rate.get('remaining'), rate.get('reset')))

        action_result.add_data(rate)
        return action_result.set_status(phantom.APP_SUCCESS, "Rate limit details fetched successfully")

    def _is_ipv6(self, address):

        try:
            socket.inet_pton(socket.AF_INET6, address)

        except socket.error:  # not a valid v6 address
            return False

        return True

    def _lookup_rrset(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Getting mandatory input parameters
        owner_name = param[DNSDB_JSON_OWNER_NAME]
        # Getting optional input parameters
        record_type = param.get(DNSDB_JSON_TYPE, DNSDB_JSON_TYPE_DEFAULT)
        if record_type and record_type not in DNSDB_LOOKUP_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, DNSDB_VALUE_LIST_VALIDATION_MSG.format(DNSDB_LOOKUP_TYPE_VALUE_LIST, DNSDB_JSON_TYPE))

        bailiwick = param.get(DNSDB_JSON_BAILIWICK)
        limit = param.get(DNSDB_JSON_LIMIT, 200)
        ret_val, limit = self._validate_integer(action_result, limit, DNSDB_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary_data = action_result.update_summary({})

        # Constructing request parameters based on input
        # Validating the input parameters provided
        # Would be used during REST call
        ret_val, timestamps = self._validate_params(param, action_result)

        # Something went wrong while validing input parameters
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            responses = list(self._client.lookup_rrset(owner_name,
                                                    bailiwick=bailiwick,
                                                    rrtype=record_type,
                                                    limit=limit,
                                                    time_first_before=timestamps[0],
                                                    time_first_after=timestamps[1],
                                                    time_last_before=timestamps[2],
                                                    time_last_after=timestamps[3],
                                                    ignore_limited=True))
        except dnsdb2.exceptions.AccessDenied:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_ACCESS_DENIED_MSG)
        except dnsdb2.exceptions.QuotaExceeded:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_LIC_EXCEED_MSG)
        except UnicodeError:
            return action_result.set_status(phantom.APP_ERROR,
                    DNSDB_ERR_INVALID_BAILIWICK % (bailiwick))
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        # No data is considered as app success
        if len(responses) == 0:
            return action_result.set_status(phantom.APP_SUCCESS, DNSDB_DATA_NOT_AVAILABLE_MSG)

        for resp in responses:
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

            if 'rrname' in resp:
                resp['rrname'] = resp['rrname'].rstrip('.')

            if 'bailiwick' in resp:
                resp['bailiwick'] = resp['bailiwick'].rstrip('.')

            # Response from the API is list of rrset.
            # Adding Each data of list to action_result
            action_result.add_data(resp)

        summary_data['total_items'] = len(responses)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_rdata_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Getting mandatory input parameter
        ip = param[DNSDB_JSON_IP]
        # Getting optional input parameter
        network_prefix = param.get(DNSDB_JSON_NETWORK_PREFIX)
        ret_val, network_prefix = self._validate_integer(action_result, network_prefix, DNSDB_NETWORK_PREFIX_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        limit = param.get(DNSDB_JSON_LIMIT, 200)
        ret_val, limit = self._validate_integer(action_result, limit, DNSDB_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary_data = action_result.update_summary({})

        if network_prefix is not None:
            # Validate network prefix
            # network prefix valid if between 0 and 32 for ipv4
            if phantom.is_ip(ip):
                net_prefix_valid = 0 <= network_prefix <= 32
            else:
                # network prefix valid if between 0 and 128 for ipv6
                net_prefix_valid = 0 <= network_prefix <= 128

            if not net_prefix_valid:
                self.debug_print(DNSDB_ERR_INVALID_NETWORK_PREFIX.format(prefix=network_prefix))
                return action_result.set_status(
                    phantom.APP_ERROR,
                    DNSDB_ERR_INVALID_NETWORK_PREFIX.format(prefix=network_prefix))

        # Endpoint as per parameter given
        if network_prefix is not None:
            ip = "%s,%s" % (ip, network_prefix)

        # Constructing request parameters based on input
        # Validating the input parameters provided
        # Would be used during REST call
        ret_val, timestamps = self._validate_params(param, action_result)

        # Something went wrong while validing input parameters
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            responses = list(self._client.lookup_rdata_ip(ip,
                                                        limit=limit,
                                                        time_first_before=timestamps[0],
                                                        time_first_after=timestamps[1],
                                                        time_last_before=timestamps[2],
                                                        time_last_after=timestamps[3],
                                                        ignore_limited=True))
        except dnsdb2.exceptions.AccessDenied:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_ACCESS_DENIED_MSG)
        except dnsdb2.exceptions.QuotaExceeded:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_LIC_EXCEED_MSG)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        # Something went wrong with the request
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # No data is considered as app success
        if len(responses) == 0:
            return action_result.set_status(phantom.APP_SUCCESS, DNSDB_DATA_NOT_AVAILABLE_MSG)

        # To display count of domains in summary data
        count_domain = set()

        for resp in responses:

            if 'rrname' in resp:
                resp['rrname'] = resp['rrname'].rstrip('.')
                count_domain.add(resp['rrname'])

            # Response from the API is list of rdata.
            # Adding Each data of list to action_result
            action_result.add_data(resp)

        summary_data['total_domains'] = len(count_domain)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_rdata_name(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Getting mandatory input parameter
        name = param[DNSDB_JSON_NAME]
        # Getting optional input parameter
        limit = param.get(DNSDB_JSON_LIMIT, 200)
        ret_val, limit = self._validate_integer(action_result, limit, DNSDB_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary_data = action_result.update_summary({})

        # Constructing request parameters based on input
        # Validating the input parameters provided
        # Would be used during REST call
        ret_val, timestamps = self._validate_params(param, action_result)

        # Something went wrong while validing input parameters
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            responses = list(self._client.lookup_rdata_name(name,
                                                        limit=limit,
                                                        time_first_before=timestamps[0],
                                                        time_first_after=timestamps[1],
                                                        time_last_before=timestamps[2],
                                                        time_last_after=timestamps[3],
                                                        ignore_limited=True))
        except dnsdb2.exceptions.AccessDenied:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_ACCESS_DENIED_MSG)
        except dnsdb2.exceptions.QuotaExceeded:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_LIC_EXCEED_MSG)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        # Something went wrong with the request
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # No data is considered as app success
        if len(responses) == 0:
            return action_result.set_status(phantom.APP_SUCCESS, DNSDB_DATA_NOT_AVAILABLE_MSG)

        # To display count of domains in summary data
        count_domain = set()

        for resp in responses:

            if 'rrname' in resp:
                resp['rrname'] = resp['rrname'].rstrip('.')
                count_domain.add(resp['rrname'])

            # Response from the API is list of rdata.
            # Adding Each data of list to action_result
            action_result.add_data(resp)

        summary_data['total_domains'] = len(count_domain)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_rdata_raw(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Getting mandatory input parameter
        raw_rdata = param[DNSDB_JSON_RAW_RDATA]
        # Getting optional input parameter
        limit = param.get(DNSDB_JSON_LIMIT, 200)
        ret_val, limit = self._validate_integer(action_result, limit, DNSDB_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        record_type = param.get(DNSDB_JSON_TYPE, DNSDB_JSON_TYPE_DEFAULT)
        if record_type and record_type not in DNSDB_LOOKUP_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, DNSDB_VALUE_LIST_VALIDATION_MSG.format(DNSDB_LOOKUP_TYPE_VALUE_LIST, DNSDB_JSON_TYPE))

        summary_data = action_result.update_summary({})

        # Constructing request parameters based on input
        # Validating the input parameters provided
        # Would be used during REST call
        ret_val, timestamps = self._validate_params(param, action_result)

        # Something went wrong while validing input parameters
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            responses = list(self._client.lookup_rdata_raw(raw_rdata,
                                                        rrtype=record_type,
                                                        limit=limit,
                                                        time_first_before=timestamps[0],
                                                        time_first_after=timestamps[1],
                                                        time_last_before=timestamps[2],
                                                        time_last_after=timestamps[3],
                                                        ignore_limited=True))
        except dnsdb2.exceptions.AccessDenied:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_ACCESS_DENIED_MSG)
        except dnsdb2.exceptions.QuotaExceeded:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_LIC_EXCEED_MSG)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            ret_val = action_result.set_status(phantom.APP_ERROR, err)

        # Something went wrong with the request
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # No data is considered as app success
        if len(responses) == 0:
            return action_result.set_status(phantom.APP_SUCCESS, DNSDB_DATA_NOT_AVAILABLE_MSG)

        # To display count of domains in summary data
        count_domain = set()

        for resp in responses:

            if DNSDB_JSON_RRNAME in resp:
                resp[DNSDB_JSON_RRNAME] = resp[DNSDB_JSON_RRNAME].rstrip('.')
                count_domain.add(resp[DNSDB_JSON_RRNAME])

            # Response from the API is list of rdata.
            # Adding Each data of list to action_result
            action_result.add_data(resp)

        summary_data['total_domains'] = len(count_domain)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _flex_search(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Getting mandatory input parameter
        query = param[DNSDB_JSON_QUERY]
        rrtype = param[DNSDB_JSON_TYPE]
        if rrtype not in DNSDB_JSON_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, DNSDB_VALUE_LIST_VALIDATION_MSG.format(DNSDB_JSON_TYPE_VALUE_LIST, DNSDB_JSON_TYPE))
        search_type = param[DNSDB_JSON_SEARCH_TYPE]
        if search_type not in DNSDB_JSON_SEARCH_TYPE_VALUE_LIST:
            return action_result.set_status(phantom.APP_ERROR, DNSDB_VALUE_LIST_VALIDATION_MSG.format(DNSDB_JSON_SEARCH_TYPE_VALUE_LIST, DNSDB_JSON_SEARCH_TYPE))

        # Getting optional input parameter
        limit = param.get(DNSDB_JSON_LIMIT, 10000)
        ret_val, limit = self._validate_integer(action_result, limit, DNSDB_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        exclude = param.get(DNSDB_JSON_EXCLUDE)

        summary_data = action_result.update_summary({})

        # Constructing request parameters based on input
        # Validating the input parameters provided
        # Would be used during REST call
        ret_val, timestamps = self._validate_params(param, action_result)

        # Something went wrong while validing input parameters
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        try:
            if rrtype == "RDATA" and search_type == "regex":
                responses = list(self._client.flex_rdata_regex(query,
                                                        time_first_before=timestamps[0],
                                                        time_first_after=timestamps[1],
                                                        time_last_before=timestamps[2],
                                                        time_last_after=timestamps[3],
                                                        exclude=exclude,
                                                        limit=limit,
                                                        ignore_limited=True))
            elif rrtype == "RDATA" and search_type == "glob":
                responses = list(self._client.flex_rdata_glob(query,
                                                        time_first_before=timestamps[0],
                                                        time_first_after=timestamps[1],
                                                        time_last_before=timestamps[2],
                                                        time_last_after=timestamps[3],
                                                        exclude=exclude,
                                                        limit=limit,
                                                        ignore_limited=True))
            elif rrtype == "RRNAMES" and search_type == "regex":
                responses = list(self._client.flex_rrnames_regex(query,
                                                        time_first_before=timestamps[0],
                                                        time_first_after=timestamps[1],
                                                        time_last_before=timestamps[2],
                                                        time_last_after=timestamps[3],
                                                        exclude=exclude,
                                                        limit=limit,
                                                        ignore_limited=True))
            elif rrtype == "RRNAMES" and search_type == "glob":
                responses = list(self._client.flex_rrnames_glob(query,
                                                        time_first_before=timestamps[0],
                                                        time_first_after=timestamps[1],
                                                        time_last_before=timestamps[2],
                                                        time_last_after=timestamps[3],
                                                        exclude=exclude,
                                                        limit=limit,
                                                        ignore_limited=True))
        except dnsdb2.exceptions.AccessDenied:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_ACCESS_DENIED_MSG)
        except dnsdb2.exceptions.QuotaExceeded:
            return action_result.set_status(
                phantom.APP_ERROR, DNSDB_REST_RESP_LIC_EXCEED_MSG)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        # No data is considered as app success
        if len(responses) == 0:
            return action_result.set_status(phantom.APP_SUCCESS, DNSDB_DATA_NOT_AVAILABLE_MSG)

        # To display count of domains in summary data
        count_domain = set()

        for resp in responses:
            if DNSDB_JSON_RRNAME in resp:
                resp[DNSDB_JSON_RRNAME] = resp[DNSDB_JSON_RRNAME].rstrip('.')
                count_domain.add(resp[DNSDB_JSON_RRNAME])

            # Response from the API is list of rdata.
            # Adding Each data of list to action_result
            action_result.add_data(resp)

        summary_data['total_items'] = len(responses)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_params(self, param, action_result):
        """ Function to validate input parameters and return error in case of
            validation fails
        """

        # Getting optional input parameter
        time_first_before = param.get(DNSDB_JSON_TIME_FIRST_BEFORE)
        time_first_after = param.get(DNSDB_JSON_TIME_FIRST_AFTER)
        time_last_before = param.get(DNSDB_JSON_TIME_LAST_BEFORE)
        time_last_after = param.get(DNSDB_JSON_TIME_LAST_AFTER)
        timestamps = [time_first_before, time_first_after, time_last_before, time_last_after]

        if time_first_before:
            # Validating the input for time format(epoch or relative seconds)
            if not self._is_valid_time(time_first_before):
                return action_result.set_status(phantom.APP_ERROR,
                                                    DNSDB_ERR_INVALID_TIME_FORMAT.format(time=time_first_before)), None

        if time_first_after:
            # Validating the input for time format(epoch or relative seconds)
            if not self._is_valid_time(time_first_after):
                return action_result.set_status(phantom.APP_ERROR,
                                                    DNSDB_ERR_INVALID_TIME_FORMAT.format(time=time_first_after)), None

        if time_last_before:
            # Validating the input for time format(epoch or relative seconds)
            if not self._is_valid_time(time_last_before):
                return action_result.set_status(phantom.APP_ERROR,
                                                    DNSDB_ERR_INVALID_TIME_FORMAT.format(time=time_last_before)), None

        if time_last_after:
            # Validating the input for time format(epoch or relative seconds)
            if not self._is_valid_time(time_last_after):
                return action_result.set_status(phantom.APP_ERROR,
                                                    DNSDB_ERR_INVALID_TIME_FORMAT.format(time=time_last_after)), None

        for i in timestamps:
            try:
                if i and time.strptime(i, DNSDB_TIME_FORMAT) > datetime.utcnow().timetuple():
                    return action_result.set_status(phantom.APP_ERROR, DNSDB_ERR_INVALID_TIME), None
            except ValueError:
                if i and int(i) > int(datetime.utcnow().timestamp()):
                    return action_result.set_status(phantom.APP_ERROR, DNSDB_ERR_INVALID_TIME), None
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, err), None

        return phantom.APP_SUCCESS, timestamps

    def _is_valid_time(self, time_value):
        """ Function that validates given time,
            time can be epoch time, relative seconds, or timestamp
            e.g.1380139330, -31536000, or 2021-01-05T12:06:02Z
        """
        date_format = DNSDB_TIME_FORMAT
        try:
            time.strptime(time_value, date_format)
        except ValueError:
            pass
        else:
            return True

        try:
            int(time_value)
        except ValueError:
            return False

        if not (len(time_value) == 10 or int(time_value) < 0):
            return False

        return True

    def handle_action(self, param):

        # Supported actions by app
        supported_actions = {
            'test_asset_connectivity': self._test_connectivity,
            'check_rate_limit': self._test_connectivity,
            'lookup_rdata_ip': self._lookup_rdata_ip,
            'lookup_rdata_name': self._lookup_rdata_name,
            'lookup_rdata_raw': self._lookup_rdata_raw,
            'lookup_rrset': self._lookup_rrset,
            'flex_search': self._flex_search
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
        print(json.dumps(in_json, indent=4))
        connector = DnsdbConnector()
        connector.print_progress_message = True
        connector._handle_action(json.dumps(in_json), None)
    exit(0)
