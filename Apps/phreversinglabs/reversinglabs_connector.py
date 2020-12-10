# File: reversinglabs_connector.py
# Copyright (c) 2014-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom imports
import phantom.app as phantom
from phantom.app import BaseConnector
from phantom.app import ActionResult

# THIS Connector imports
from reversinglabs_consts import *

# Other imports used by this connector
import simplejson as json
import hashlib
import requests
from requests.auth import HTTPBasicAuth
from collections import defaultdict

from builtins import str


class ReversinglabsConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_QUERY_FILE = "lookup_file"

    def __init__(self):

        # Call the BaseConnectors init first
        super(ReversinglabsConnector, self).__init__()

        self._malicious_status = ["MALICIOUS", "SUSPICIOUS"]
        self._headers = {'content-type': 'application/octet-stream'}
        self._auth = None

    def initialize(self):

        config = self.get_config()
        # setup the auth
        self._auth = HTTPBasicAuth(phantom.get_req_value(config, phantom.APP_JSON_USERNAME),
                phantom.get_req_value(config, phantom.APP_JSON_PASSWORD))

        self.debug_print('self.status', self.get_status())

        return phantom.APP_SUCCESS

    def _test_asset_connectivity(self, param):

        # Create a hash of a random string
        random_string = phantom.get_random_chars(size=10)

        try:
            md5_hash = hashlib.md5(random_string).hexdigest()
        except TypeError:  # py3
            md5_hash = hashlib.md5(random_string.encode('UTF-8')).hexdigest()

        self.save_progress(REVERSINGLABS_GENERATED_RANDOM_HASH)

        tree = lambda: defaultdict(tree)
        hash_type = 'md5'
        query = tree()
        query['rl']['query']['hash_type'] = hash_type
        query['rl']['query']['hashes'] = [md5_hash]

        self.save_progress(REVERSINGLABS_MSG_CONNECTING_WITH_URL, url=MAL_PRESENCE_API_URL, hash_type=hash_type)

        config = self.get_config()

        try:
            r = requests.post(MAL_PRESENCE_API_URL, verify=config[phantom.APP_JSON_VERIFY], auth=self._auth, data=json.dumps(query), headers=self._headers)
        except Exception as e:
            self.set_status(phantom.APP_ERROR, 'Request to server failed', e)
            self.save_progress(REVERSINGLABS_SUCC_CONNECTIVITY_TEST)
            return self.get_status()

        if (r.status_code != 200):
            self.set_status(phantom.APP_ERROR)
            status_message = '{0}. {1}. HTTP status_code: {2}, reason: {3}'.format(REVERSINGLABS_ERR_CONNECTIVITY_TEST,
                REVERSINGLABS_MSG_CHECK_CREDENTIALS, r.status_code, r.reason)
            self.append_to_message(status_message)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, REVERSINGLABS_SUCC_CONNECTIVITY_TEST)

    def _handle_samples(self, action_result, samples):

        if (not samples):
            return

        for sample in samples:

            if (not sample):
                continue

            try:
                # Get the data dictionary into the result to store information
                hash_data = action_result.get_data()[0]
            except:
                continue

            # Update the data with what we got
            hash_data.update(sample)

            try:
                positives = sample['xref'][0]['scanner_match']
                # Update the summary
                action_result.update_summary({REVERSINGLABS_JSON_TOTAL_SCANS: sample['xref'][0]['scanner_count'],
                    REVERSINGLABS_JSON_POSITIVES: positives})
            except:
                continue

        return

    def _get_hash_type(self, hash_to_query):

        if (phantom.is_md5(hash_to_query)):
            return 'md5'

        if (phantom.is_sha1(hash_to_query)):
            return 'sha1'

        if (phantom.is_sha256(hash_to_query)):
            return 'sha256'

        return None

    def _query_file(self, param):

        config = self.get_config()

        action_result = self.add_action_result(ActionResult(dict(param)))

        # get the hash
        hash_to_query = param[phantom.APP_JSON_HASH]

        # get the hash type
        hash_type = self._get_hash_type(hash_to_query)

        if (not hash_type):
            return action_result.set_status(phantom.APP_ERROR, "Unable to detect Hash Type")

        tree = lambda: defaultdict(tree)

        query = tree()
        query['rl']['query']['hash_type'] = hash_type
        query['rl']['query']['hashes'] = [hash_to_query]

        # First the malware presence
        self.save_progress(REVERSINGLABS_MSG_CONNECTING_WITH_URL, url=MAL_PRESENCE_API_URL, hash_type=hash_type)

        try:
            r = requests.post(MAL_PRESENCE_API_URL, verify=config[phantom.APP_JSON_VERIFY], auth=self._auth, data=json.dumps(query), headers=self._headers)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Request to server failed", e)

        if (r.status_code != 200):
            return action_result.set_status(phantom.APP_ERROR, REVERSINGLABS_ERR_MALWARE_PRESENCE_QUERY_FAILED, ret_code=r.status_code)

        try:
            rl_result = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Response does not seem to be a valid JSON", e)

        # set the status to success
        action_result.set_status(phantom.APP_SUCCESS)

        entries = rl_result.get('rl', {}).get('entries')

        if (not entries):
            return action_result.set_status(phantom.APP_ERROR, "Response does contains empty or None 'entries'")

        # Queried for a hash, so it should be present in the return value
        entry = entries[0]

        # Add a data dictionary into the result to store information
        hash_data = action_result.add_data({})

        # Add the status into it
        hash_data[REVERSINGLABS_JSON_STATUS] = entry.get('status', 'Unknown')

        # Set the summary
        action_result.update_summary({REVERSINGLABS_JSON_TOTAL_SCANS: 0, REVERSINGLABS_JSON_POSITIVES: 0})

        if (hash_data[REVERSINGLABS_JSON_STATUS] not in self._malicious_status):
            # No need to do anything more for this hash
            return action_result.set_status(phantom.APP_SUCCESS)

        self.save_progress(REVERSINGLABS_MSG_CONNECTING_WITH_URL, url=XREF_API_URL, hash_type=hash_type)

        try:
            r = requests.post(XREF_API_URL, verify=config[phantom.APP_JSON_VERIFY], auth=self._auth, data=json.dumps(query), headers=self._headers)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "XREF API Request to server failed", e)

        if (r.status_code != 200):
            self.debug_print("status code", r.status_code)
            return action_result.set_status(phantom.APP_ERROR, "XREF API Request to server error: {0}".format(r.status_code))

        try:
            rl_result = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "XREF Response does not seem to be a valid JSON", e)

        action_result.add_debug_data(rl_result)

        samples = rl_result.get('rl', {}).get('samples')

        if (not samples):
            return action_result.set_status(phantom.APP_ERROR, "Response contains empty or none 'samples'")

        self._handle_samples(action_result, samples)

        return phantom.APP_SUCCESS

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()

        if (action == self.ACTION_ID_QUERY_FILE):
            result = self._query_file(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            result = self._test_asset_connectivity(param)

        return result

    def finalize(self):

        # Init the positives
        total_positives = 0

        # Loop through the action results that we had added before
        for action_result in self.get_action_results():
            action = self.get_action_identifier()
            if (action == self.ACTION_ID_QUERY_FILE):
                # get the summary of the current one
                summary = action_result.get_summary()

                if (REVERSINGLABS_JSON_POSITIVES not in summary):
                    continue

                # If the detection is true
                if (summary[REVERSINGLABS_JSON_POSITIVES] > 0):
                    total_positives += 1

                self.update_summary({REVERSINGLABS_JSON_TOTAL_POSITIVES: total_positives})


if __name__ == '__main__':

    import sys
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
            print("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ReversinglabsConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
