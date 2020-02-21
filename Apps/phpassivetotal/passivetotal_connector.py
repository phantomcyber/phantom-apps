# File: passivetotal_connector.py
# Copyright (c) 2016-2020 Splunk Inc.
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
import requests
import json
import ipaddress


class PassivetotalConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_LOOKUP_IP = "lookup_ip"
    ACTION_ID_LOOKUP_DOMAIN = "lookup_domain"
    ACTION_ID_WHOIS_IP = "whois_ip"
    ACTION_ID_WHOIS_DOMAIN = "whois_domain"

    def __init__(self):

        # Call the BaseConnectors init first
        super(PassivetotalConnector, self).__init__()

    def initialize(self):

        # Base URL
        self._base_url = PASSIVETOTAL_REST_API_URL
        if (self._base_url.endswith('/')):
            self._base_url = self._base_url[:-1]

        self._host = ph_utils.get_host_from_url(self._base_url)

        self._params = {}

        self._headers = {'Content-Type': 'application/json'}

        return phantom.APP_SUCCESS

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
            r = requests.get(self._base_url + endpoint,
                    auth=(config[PASSIVETOTAL_JSON_KEY], config[PASSIVETOTAL_JSON_SECRET]),
                    params=params,
                    headers=self._headers)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, PASSIVETOTAL_ERR_SERVER_CONNECTION, e), resp_json, status_code)

        # It's ok if r.text is None, dump that
        action_result.add_debug_data({'r_text': r.text if r else 'r is None'})

        # get the status code, use from here on
        status_code = r.status_code

        # Try parsing the result as a json
        try:
            resp_json = r.json()
        except:
            # not a json, dump whatever was returned into the action result
            details = r.text.replace('{', '').replace('}', '')
            action_result.set_status(phantom.APP_ERROR, PASSIVETOTAL_ERR_FROM_SERVER, status=r.status_code, message=details)
            return (phantom.APP_ERROR, resp_json, status_code)

        # Check if it's a success
        if (200 <= status_code <= 299):
            # Success
            return (phantom.APP_SUCCESS, resp_json, status_code)

        # Error, dump the cleansed json into the details
        details = json.dumps(resp_json).replace('{', '').replace('}', '')
        action_result.set_status(phantom.APP_ERROR, PASSIVETOTAL_ERR_FROM_SERVER, status=r.status_code, message=details)
        return (phantom.APP_ERROR, resp_json, status_code)

    def _test_connectivity(self, param):

        # Progress
        self.save_progress(PASSIVETOTAL_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        endpoint = '/enrichment'

        action_result = ActionResult()

        self.save_progress(PASSIVETOTAL_MSG_GET_DOMAIN_TEST)

        ret_val, response, status_code = self._make_rest_call(endpoint, {'query': 'phantomcyber.com'}, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            self.set_status(phantom.APP_ERROR, action_result.get_message())
            self.append_to_message(PASSIVETOTAL_ERR_CONNECTIVITY_TEST)
            return phantom.APP_ERROR

        return self.set_status_save_progress(phantom.APP_SUCCESS, PASSIVETOTAL_SUCC_CONNECTIVITY_TEST)

    def _lookup_domain(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param[PASSIVETOTAL_JSON_DOMAIN]
        start_time = param.get(PASSIVETOTAL_JSON_FROM)
        end_time = param.get(PASSIVETOTAL_JSON_TO)

        if start_time:
            try:
                datetime.strptime(start_time, '%Y-%m-%d')
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, 'Incorrect date format for start time, it should be YYYY-MM-DD')

        if end_time:
            try:
                datetime.strptime(end_time, '%Y-%m-%d')
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, 'Incorrect date format for end time, it should be YYYY-MM-DD')

        # Progress
        self.save_progress(PASSIVETOTAL_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Add the extra data that will include info about this domain
        extra_data = action_result.add_data({})
        summary = action_result.update_summary({})

        ret_val = self._get_common_info(domain, extra_data, summary, action_result, param)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Dynamic
        self.save_progress('Querying Dynamic domain information')
        ret_val, response, status_code = self._make_rest_call('/dynamic', {'query': domain}, action_result)

        if (ret_val) and (response):
            results = response.get('results')
            if (results):
                extra_data[PASSIVETOTAL_JSON_DYNAMIC] = results

        # Subdomains
        self.save_progress('Getting Sub-domain list')
        ret_val, response, status_code = self._make_rest_call('/subdomains', {'query': domain}, action_result)

        if (ret_val) and (response):
            results = response.get('results')
            if (results):
                extra_data[PASSIVETOTAL_JSON_SUBDOMAINS] = results

        if (not extra_data) and (phantom.is_fail(ret_val)):
            # We don't seem to have any data _and_ the last call failed
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_common_info(self, query_param, data, summary, action_result, param={}):

        # Metadata
        self.save_progress('Querying Metadata')
        ret_val, response, status_code = self._make_rest_call('/enrichment', {'query': query_param}, action_result)

        if (not ret_val):
            message = response.get('error', {}).get('message', '')

            if ('quota has been exceeded' in message.lower()):
                return action_result.get_status()

        if (ret_val) and (response):

            data[PASSIVETOTAL_JSON_METADATA] = response

            if ('everCompromised' in response):
                summary.update({PASSIVETOTAL_JSON_EVER_COMPROMISED: response['everCompromised']})

            if ('autonomousSystemName' in response):
                summary.update({PASSIVETOTAL_JSON_AS_NAME: response['autonomousSystemName']})

            if ('country' in response):
                summary.update({PASSIVETOTAL_JSON_COUTRY: response['country']})

            if ('dynamicDns' in response):
                summary.update({PASSIVETOTAL_JSON_DYNAMIC_DOMAIN: response['dynamicDns']})

        # Take care of passive calls
        request_params = {'query': query_param}
        start_time = param.get(PASSIVETOTAL_JSON_FROM)
        end_time = param.get(PASSIVETOTAL_JSON_TO)

        if (start_time):
            request_params.update({'start': start_time})
        else:
            request_params.update({'start': (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")})

        if (end_time):
            request_params.update({'end': end_time})

        # Passive
        self.save_progress('Querying Passive information')
        ret_val, response, status_code = self._make_rest_call('/dns/passive', request_params, action_result)

        if (ret_val) and (response):
            data[PASSIVETOTAL_JSON_PASSIVE] = response
            summary.update({PASSIVETOTAL_JSON_FIRST_SEEN: response.get('firstSeen', ''),
                PASSIVETOTAL_JSON_LAST_SEEN: response.get('lastSeen', '')})

        # Unique
        self.save_progress('Querying for Unique domain info')
        ret_val, response, status_code = self._make_rest_call('/dns/passive/unique', request_params, action_result)

        if (ret_val) and (response):
            results = response.get('results')
            if (results):
                data[PASSIVETOTAL_JSON_UNIQUE] = results
                summary.update({PASSIVETOTAL_JSON_TOTAL_UNIQUE_DOMAINS: len(results)})

        # Classification
        self.save_progress('Querying Classification')
        ret_val, response, status_code = self._make_rest_call('/actions/classification', {'query': query_param}, action_result)

        if (ret_val) and (response):
            classification = response.get('classification', '')
            data[PASSIVETOTAL_JSON_CLASSIFICATION] = response
            summary.update({PASSIVETOTAL_JSON_CLASSIFICATION: classification})

        # Tags
        self.save_progress('Querying Tags')
        ret_val, response, status_code = self._make_rest_call('/actions/tags', {'query': query_param}, action_result)

        if (ret_val) and (response):
            tags = response.get('tags')
            if (tags):
                data[PASSIVETOTAL_JSON_TAGS] = tags

        # Sinkhole
        self.save_progress('Querying Sinkhole information')
        ret_val, response, status_code = self._make_rest_call('/actions/sinkhole', {'query': query_param}, action_result)

        if (ret_val) and (response):
            if ('sinkhole' in response):
                data[PASSIVETOTAL_JSON_SINKHOLE] = response['sinkhole']
                summary.update({PASSIVETOTAL_JSON_SINKHOLE: response['sinkhole']})

        # Ever Compromised
        self.save_progress('Querying Compromising information')
        ret_val, response, status_code = self._make_rest_call('/actions/ever-compromised', {'query': query_param}, action_result)

        if (ret_val) and (response):
            if ('everCompromised' in response):
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

        if (phantom.is_fail(ret_val)):
            # We don't seem to have any data _and_ the last call failed
            return action_result.get_status()

        if(not response):
            # return with a message
            return action_result.set_status(phantom.APP_SUCCESS, "No registrant info found")

        action_result.add_data(response)
        registrant = response.get('registrant')

        if(not registrant):
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

        if (phantom.is_fail(ret_val)):
            # We don't seem to have any data _and_ the last call failed
            return action_result.get_status()

        if(not response):
            # return with a message
            return action_result.set_status(phantom.APP_SUCCESS, "No registrant info found")

        action_result.add_data(response)
        registrant = response.get('registrant')

        if(not registrant):
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

        if start_time:
            try:
                datetime.strptime(start_time, '%Y-%m-%d')
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, 'Incorrect date format for start time, it should be YYYY-MM-DD')

        if end_time:
            try:
                datetime.strptime(end_time, '%Y-%m-%d')
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, 'Incorrect date format for end time, it should be YYYY-MM-DD')

        # Progress
        self.save_progress(PASSIVETOTAL_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        # Add the extra data that will include info about this ip
        extra_data = action_result.add_data({})
        summary = action_result.update_summary({})

        ret_val = self._get_common_info(ip, extra_data, summary, action_result, param)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # SSL Certificates
        ret_val, response, status_code = self._make_rest_call('/ssl-certificate/history', {'query': ip}, action_result)

        if (ret_val) and (response):
            if (response['results']):
                extra_data[PASSIVETOTAL_JSON_SSL_CERTIFICATES] = response['results']

        if (not extra_data) and (phantom.is_fail(ret_val)):
            # We don't seem to have any data _and_ the last call failed
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def validate_parameters(self, param):
        # Disable BaseConnector's validate functionality, since this App supports unicode domains and the validation routines don't
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

        if (action == self.ACTION_ID_LOOKUP_IP):
            ret_val = self._lookup_ip(param)
        elif (action == self.ACTION_ID_LOOKUP_DOMAIN):
            ret_val = self._lookup_domain(param)
        elif (action == self.ACTION_ID_WHOIS_IP):
            ret_val = self._whois_ip(param)
        elif (action == self.ACTION_ID_WHOIS_DOMAIN):
            ret_val = self._whois_domain(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
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

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
