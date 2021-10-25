# File: ciscoumbrella_connector.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from ciscoumbrella_consts import *

import requests
import simplejson as json
from datetime import datetime


class CiscoumbrellaConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_LIST_BLOCKED_DOMAINS = "list_blocked_domains"
    ACTION_ID_BLOCK_DOMAIN = "block_domain"
    ACTION_ID_UNBLOCK_DOMAIN = "unblock_domain"

    def __init__(self):

        # Call the BaseConnectors init first
        super(CiscoumbrellaConnector, self).__init__()

    def initialize(self):

        # Base URL
        self._base_url = CISCOUMB_REST_API_URL
        if (self._base_url.endswith('/')):
            self._base_url = self._base_url[:-1]

        self._host = self._base_url[self._base_url.find('//') + 2:]

        self._base_url = '{0}/1.0'.format(self._base_url)

        return phantom.APP_SUCCESS

    def _get_error_message(self, resp_json, response):

        ret_val = ''

        if (not resp_json):
            return ret_val

        ret_val = resp_json.get('message', '')

        if (response.status_code == 500):
            ret_val += ". The service may be down or your license may have expired."

        return ret_val

    def _make_delete_rest_call(self, endpoint, action_result, request_params={}):

        config = self.get_config()

        request_params.update({'customerKey': config[CISCOUMB_JSON_CUSTKEY]})

        headers = {'Content-Type': 'application/json'}

        resp_json = None
        status_code = None

        try:
            r = requests.delete(self._base_url + endpoint, headers=headers, params=request_params, verify=True)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, CISCOUMB_ERR_SERVER_CONNECTION, e), resp_json, status_code)

        # self.debug_print('REST url: {0}'.format(r.url))

        status_code = r.status_code

        if (r.status_code == 204):  # success, but no data
            return (phantom.APP_SUCCESS, resp_json, status_code)

        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101

            try:
                resp_json = r.json()
            except:
                return (action_result.set_status(phantom.APP_ERROR, "Response not a valid json"), resp_json, status_code)

            return (action_result.set_status(phantom.APP_ERROR, CISCOUMB_ERR_FROM_SERVER, status=r.status_code,
                message=self._get_error_message(resp_json, r)), resp_json, status_code)

        return (phantom.APP_SUCCESS, resp_json, status_code)

    def _make_rest_call(self, endpoint, action_result, request_params={}):

        config = self.get_config()

        request_params.update({'customerKey': config[CISCOUMB_JSON_CUSTKEY]})

        headers = {'Content-Type': 'application/json'}

        resp_json = None
        status_code = None

        try:
            r = requests.get(self._base_url + endpoint, headers=headers, params=request_params, verify=True)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, CISCOUMB_ERR_SERVER_CONNECTION, e), resp_json, status_code)

        # self.debug_print('REST url: {0}'.format(r.url))

        try:
            resp_json = r.json()
        except:
            return (action_result.set_status(phantom.APP_ERROR, "Response not a valid json"), resp_json, status_code)

        status_code = r.status_code

        # if (r.status_code == 204):  # success, but no data
        #     return (phantom.APP_SUCCESS, resp_json, status_code)

        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101
            return (action_result.set_status(phantom.APP_ERROR, CISCOUMB_ERR_FROM_SERVER, status=r.status_code,
                message=self._get_error_message(resp_json, r)), resp_json, status_code)

        return (phantom.APP_SUCCESS, resp_json, status_code)

    def _make_post_rest_call(self, endpoint, action_result, data=None, request_params={}):

        config = self.get_config()

        request_params.update({'customerKey': config[CISCOUMB_JSON_CUSTKEY]})

        headers = {'Content-Type': 'application/json'}

        resp_json = None
        status_code = None

        try:
            r = requests.post(self._base_url + endpoint, data=json.dumps(data), headers=headers, params=request_params, verify=True)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, CISCOUMB_ERR_SERVER_CONNECTION, e), resp_json, status_code)

        # self.debug_print('REST url: {0}'.format(r.url))

        try:
            resp_json = r.json()
        except:
            return (action_result.set_status(phantom.APP_ERROR, "Response not a valid json"), resp_json, status_code)

        status_code = r.status_code

        if (r.status_code == 202):  # success, return from here, requests treats 202 as !ok
            return (phantom.APP_SUCCESS, resp_json, status_code)

        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101
            return (action_result.set_status(phantom.APP_ERROR, CISCOUMB_ERR_FROM_SERVER, status=r.status_code,
                message=self._get_error_message(resp_json, r)), resp_json, status_code)

        return (phantom.APP_SUCCESS, resp_json, status_code)

    def _test_connectivity(self, param):

        # Progress
        self.save_progress(CISCOUMB_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        endpoint = '/domains'

        action_result = ActionResult()

        self.save_progress(CISCOUMB_MSG_GET_DOMAIN_LIST_TEST)

        ret_val, response, status_code = self._make_rest_call(endpoint, action_result, {'page': 1, 'limit': 1})

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            self.set_status(phantom.APP_ERROR, action_result.get_message())
            self.append_to_message(CISCOUMB_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, CISCOUMB_SUCC_CONNECTIVITY_TEST)

    def _list_blocked_domains(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Progress
        self.save_progress(CISCOUMB_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        endpoint = '/domains'

        page_index = param.get(CISCOUMB_JSON_PAGE_INDEX, CISCOUMB_DEFAULT_PAGE_INDEX)
        domain_limit = param.get(CISCOUMB_JSON_DOMAIN_LIMIT, CISCOUMB_DEFAULT_DOMAIN_LIMIT)

        ret_val, response, status_code = self._make_rest_call(endpoint, action_result, {'page': page_index, 'limit': domain_limit})

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            return self.set_status(phantom.APP_ERROR, action_result.get_message())

        domain_list = response.get('data', [])

        action_result.update_summary({CISCOUMB_JSON_TOTAL_DOMAINS: len(domain_list)})

        for domain in domain_list:
            action_result.add_data(domain)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _unblock_domain(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Progress
        self.save_progress(CISCOUMB_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        endpoint = '/domains'

        domain = param[CISCOUMB_JSON_DOMAIN]

        request_params = {'where[name]': domain}

        ret_val, response, status_code = self._make_delete_rest_call(endpoint, action_result, request_params)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            return self.set_status(phantom.APP_ERROR, action_result.get_message())

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Domain successfully unblocked")

    def _block_domain(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Progress
        self.save_progress(CISCOUMB_USING_BASE_URL, base_url=self._base_url)

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._host)

        ret_val, ret_data, status_code = self.get_container_info()

        if (ret_val is False):
            return action_result.set_status(phantom.APP_ERROR, ret_data)

        container_info = ret_data

        self.debug_print("Container info: ", container_info)

        endpoint = '/events'

        events = []

        domain = param[CISCOUMB_JSON_DOMAIN]

        event = {
                'deviceId': self.get_product_installation_id(),
                'deviceVersion': self.get_product_version(),
                'eventTime': datetime.strptime(container_info['create_time'], '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%dT%H:%M:%S.0Z'),
                'alertTime': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.0Z'),
                'dstDomain': domain,
                'dstUrl': 'http://{0}/'.format(domain),
                'protocolVersion': '1.0a',
                'providerName': 'Security Platform',
                'disableDstSafeguards': param.get(CISCOUMB_JSON_DISABLE_SAFEGUARDS, False),
                'eventType': container_info['label'],
                'eventSeverity': container_info['severity']}

        self.debug_print("Event:", event)

        events.append(event)

        ret_val, response, status_code = self._make_post_rest_call(endpoint, action_result, data=events)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, CISCOUMB_LIST_UPDATED_WITH_GUID, id=response['id'])

    def handle_action(self, param):
        """Function that handles all the actions

            Args:

            Return:
                A status code
        """

        # Get the action that we are supposed to carry out, set it in the connection result object
        action = self.get_action_identifier()

        ret_val = phantom.APP_SUCCESS

        if (action == self.ACTION_ID_LIST_BLOCKED_DOMAINS):
            ret_val = self._list_blocked_domains(param)
        elif (action == self.ACTION_ID_BLOCK_DOMAIN):
            ret_val = self._block_domain(param)
        elif (action == self.ACTION_ID_UNBLOCK_DOMAIN):
            ret_val = self._unblock_domain(param)
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
        try:
            print("Accessing the Login page")
            login_url = BaseConnector._get_phantom_base_url() + "login"
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

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

        connector = CiscoumbrellaConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
