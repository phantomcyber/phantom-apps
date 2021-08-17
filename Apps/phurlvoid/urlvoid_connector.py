# File: urlvoid_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.utils as ph_utils

# Imports local to this App
from urlvoid_consts import *

import requests
import xmltodict
import json
import datetime
import tldextract


TLD_LIST_CACHE_FILE_NAME = "public_suffix_list.dat"
ISO_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


# Define the App Class
class URLVoidConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_DOMAIN_REPUTATION = "domain_reputation"
    ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'

    def __init__(self):

        # Call the BaseConnectors init first
        super(URLVoidConnector, self).__init__()

        self._base_url = BASE_URL

        self._state_file_path = None
        self._cache_file_path = None
        self._state = {}

    def initialize(self):

        self._state = self.load_state()
        self._req_sess = requests.Session()

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _should_update_cache(self):

        last_time = self._state.get(URLVOID_JSON_CACHE_UPDATE_TIME)

        if (not last_time):
            return True

        try:
            last_time = datetime.datetime.strptime(last_time, ISO_TIME_FORMAT)
        except Exception as e:
            self.debug_print("Exception while strptime", e)
            return True

        current_time = datetime.datetime.utcnow()

        time_diff = current_time - last_time

        app_config = self.get_app_config()
        cache_exp_days = int(app_config[URLVOID_JSON_CACHE_EXP_DAYS])

        if (time_diff.days >= cache_exp_days):
            self.debug_print("Diff days {0} >= cache exp days {1}".format(time_diff.days, cache_exp_days))
            return True

        return False

    def _get_domain(self, hostname):

        extract = None

        should_update = self._should_update_cache()
        try:
            if (should_update):
                extract = tldextract.TLDExtract(cache_file=self._cache_file_path)
            else:
                extract = tldextract.TLDExtract(cache_file=self._cache_file_path, suffix_list_urls=None)
        except Exception as e:
            self.debug_print("tldextract result failed", e)
            # The caller of this function has a try..except for this one
            raise

        result = extract(hostname)

        if (should_update):
            # Set the updated time
            self._state[URLVOID_JSON_CACHE_UPDATE_TIME] = datetime.datetime.utcnow().strftime(ISO_TIME_FORMAT)

        domain = "{0}.{1}".format(result.domain, result.suffix)  # pylint: disable=E1101

        return domain

    def _make_rest_call(self, endpoint, result):

        config = self.get_config()

        url = "{0}/{1}/{2}{3}".format(self._base_url, config[URLVOID_JSON_IDENTIFIER], config[URLVOID_JSON_APIKEY], endpoint)

        try:
            r = self._req_sess.get(url)
        except Exception as e:
            return (result.set_status(phantom.APP_ERROR, URLVOID_ERR_SERVER_CONNECTION, e), None)

        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101
            return (result.set_status(phantom.APP_ERROR, URLVOID_ERR_FROM_SERVER, status=r.status_code, detail=r.text), None)

        xml = r.text

        if (hasattr(result, 'add_debug_data')):
            result.add_debug_data(xml)

        try:
            response_dict = xmltodict.parse(xml)
            response_dict = json.loads(json.dumps(response_dict))
        except Exception as e:
            return (result.set_status(phantom.APP_ERROR, URLVOID_ERR_UNABLE_TO_PARSE_REPLY, e), None)

        error = response_dict.get('response', {}).get('error')

        if (error):
            return (result.set_status(phantom.APP_ERROR, URLVOID_ERR_FROM_SERVER, status=r.status_code, detail=error), response_dict)

        return (phantom.APP_SUCCESS, response_dict)

    def _get_data_paths(self, json_object_list, paths):

        ret_val = [None for x in paths]

        try:
            ret_val = ph_utils.extract_data_paths(json_object_list, paths)
        except Exception as e:
            self.debug_print("Handled exception", e)

        return ret_val

    def _domain_reputation(self, param):

        action_result = self.add_action_result(ActionResult(param))

        domain = param[URLVOID_JSON_DOMAIN]

        try:
            domain = self._get_domain(domain)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, URLVOID_ERR_PARSE_INPUT, e)

        self.debug_print("Querying Domain {0}".format(repr(domain)))

        summary = action_result.update_summary({})

        summary[URLVOID_JSON_DOMAIN] = domain

        endpoint = URLVOID_HOST_ENDPOINT.format(domain=domain)

        ret_val, resp_json = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(resp_json)

        # start updating the summary
        data_paths = ['response.detections.count',
                'response.details.ip.addr',
                'response.details.ip.hostname',
                'response.details.ip.city_name',
                'response.details.ip.country_code',
                'response.details.ip.asn']

        keys = ['positives', 'ip', 'hostname', 'city', 'country', 'asn']

        values = self._get_data_paths([resp_json], data_paths)

        try:
            summary.update(dict([(keys[x], values[0][x]) for x in xrange(len(keys))]))
        except Exception as e:
            self.debug_print("Handled Exception", e)

        if (not summary.get('positives')):
            summary['positives'] = 0

        return action_result.set_status(phantom.APP_SUCCESS)

    def _test_connectivity(self, param):

        endpoint = URLVOID_HOST_ENDPOINT.format(domain="phantomcyber.com")

        self.save_progress("Querying a known domain to check connectivity")

        ret_val, response = self._make_rest_call(endpoint, self)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return self.set_status(phantom.APP_ERROR)

        self.save_progress("Test Connectivity Passed")

        return self.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        action = self.get_action_identifier()

        if (action == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
          result = self._test_connectivity(param)
        elif (action == self.ACTION_ID_DOMAIN_REPUTATION):
            result = self._domain_reputation(param)

        return result


if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = URLVoidConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)

    exit(0)
