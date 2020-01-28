# Copyright (c) 2017-2019 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from datetime import datetime
from datetime import timedelta
from bs4 import BeautifulSoup
import requests
import json
from proofpoint_consts import *

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ProofpointConnector(BaseConnector):
    def __init__(self):
        # Call the EmailConnector init first
        super(ProofpointConnector, self).__init__()

        self._pp_conn = None
        self._state_file_path = None
        self._state = {}

    def initialize(self):
        self._state = self.load_state()
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})
        return RetVal(action_result.set_status(phantom.APP_ERROR, 'Empty response and no information in the header'), None)

    def _process_html_response(self, response, action_result):
        status_code = response.status_code
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [ x.strip() for x in split_lines if x.strip() ]
            error_text = ('\n').join(split_lines)
        except:
            error_text = 'Cannot parse error details'

        message = ('Status Code: {0}. Data from server:\n{1}\n').format(status_code, error_text)
        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, ('Unable to parse JSON response. Error: {0}').format(str(e))), None)
        else:
            if 200 <= r.status_code < 399:
                return RetVal(phantom.APP_SUCCESS, resp_json)

        message = ('Error from server. Status Code: {0} Data from server: {1}').format(r.status_code, r.text.replace(u'{', '{{').replace(u'}', '}}'))
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)
        if not r.text:
            return self._process_empty_response(r, action_result)
        message = ("Can't process response from server. Status Code: {0} Data from server: {1}").format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, action_result, endpoint, method='get', **kwargs):
        config = self.get_config()
        user = config['username'].encode('utf-8')
        password = config['password']
        header = {'X-Requested-With': 'REST API',
                'Content-type': 'application/json',
                'Accept': 'application/json'}

        url = PP_API_BASE_URL + endpoint

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, ('Invalid method: {0}').format(method)), resp_json)

        try:
            res = request_func(url, auth=(user, password), headers=header, **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, ('Error Connecting to server. Details: {0}').format(str(e))), resp_json)

        return self._process_response(res, action_result)

    def _process_clicks(self, clicks, action):
        for click in clicks:
            guid = click.pop('GUID')
            self.save_progress('Processing click {}'.format(guid))
            container = {
                'start_time': click.get('threatTime'),
                'name': '{0} event {1}'.format(click.get('classification'),
                                               action),
                'source_data_identifier': guid,
                'artifacts': []
            }
            artifacts = container['artifacts']

            # pull these out for consistency with messages
            email_addresses = {
                'sender': click.pop('sender'),
                'recipient': click.pop('recipient')
            }

            cef = click
            cef['sourceAddress'] = cef.get('clickIP')
            cef['requestURL'] = cef.get('url')
            cef['action'] = action
            cef_types = {
                'campaignId': ['proofpoint campaign id'],
                'clickIP': ['ip'],
                'recipient': ['email'],
                'sender': ['email'],
                'threatID': ['proofpoint threat id'],
                'threatURL': ['url'],
                'url': ['url']
            }
            artifacts.append({
                'name': 'click {0} event'.format(action),
                'cef': cef,
                'cef_types': cef_types,
                'label': 'event',
                'source_data_identifier': 0,
                'run_automation': False
            })

            count = 1
            for key in email_addresses:
                if email_addresses[key] is not None:
                    artifacts.append({
                        'name': 'email artifact',
                        'cef': {key: email_addresses[key]},
                        'cef_types': {key: ['email']},
                        'label': 'event',
                        'source_data_identifier': count,
                        'run_automation': False
                    })
                    count += 1

            artifacts[-1]['run_automation'] = True

            self.save_container(container)

    def _process_messages(self, messages, action):
        for message in messages:
            guid = message.pop('GUID')
            self.save_progress('Processing message {}'.format(guid))
            container = {
                'start_time': message.get('messageTime'),
                'name': 'Message event {0}'.format(action),
                'source_data_identifier': guid,
                'artifacts': []
            }
            artifacts = container['artifacts']

            threats = message.pop('threatsInfoMap', [])
            email_addresses = {
                'ccAddress': message.pop('ccAddresses', []),
                'fromAddress': message.pop('fromAddress', []),
                'recipient': message.pop('recipient', []),
                'replyToAddress': message.pop('replyToAddress', []),
                'toAddress': message.pop('toAddresses', []),
                'sender': message.pop('sender', [])
            }
            for key in email_addresses:
                if not isinstance(email_addresses[key], list):
                    email_addresses[key] = [email_addresses[key]]

            # first add an artifact of all the base data
            cef = message
            cef['sourceAddress'] = cef.get('senderIP')
            cef['action'] = action
            cef['modulesRun'] = ', '.join(cef['modulesRun'])
            cef['policyRoutes'] = ', '.join(cef['policyRoutes'])

            cef_types = {
                'senderIP': ['ip'],
            }
            artifact = {
                'name': 'message event',
                'cef': cef,
                'cef_types': cef_types,
                'label': 'event',
                'source_data_identifier': 0,
                'run_automation': False
            }

            artifacts.append(artifact)

            count = 1
            for threat in threats:
                cef = threat
                cef_types = {
                    'campaignId': ['proofpoint campaign id'],
                    'threatId': ['proofpoint threat id'],
                    'threatUrl': ['url']
                }
                threat_type = cef.get('threatType').lower()
                if threat_type == 'url':
                    cef_types['threat'] = ['url']
                    cef['requestURL'] = cef.get('threat')
                elif threat_type == 'attachment':
                    cef_types['threat'] = ['hash', 'sha256']
                    cef['fileHash'] = cef.get('threat')
                elif threat_type == 'messagetext':
                    cef_types['threat'] = ['email']
                    cef['fromEmail'] = cef.get('threat')

                artifact = {
                    'name': 'threat detail',
                    'cef': cef,
                    'cef_types': cef_types,
                    'label': 'event',
                    'source_data_identifier': count,
                    'run_automation': False
                }
                count += 1
                artifacts.append(artifact)

            for key in email_addresses:
                for item in email_addresses[key]:
                    artifacts.append({
                        'name': 'email artifact',
                        'cef': {key: item},
                        'cef_types': {key: ['email']},
                        'label': 'event',
                        'source_data_identifier': count,
                        'run_automation': False
                    })
                    count += 1

            artifacts[-1]['run_automation'] = True

            self.save_container(container)

    def _on_poll(self, param):
        action_result = self.add_action_result(ActionResult(param))
        if self.is_poll_now():
            self.save_progress('Due to the nature of the API, the container '
                               'and artifact limits imposed by POLL NOW are '
                               'ignored. As a result POLL NOW will simply '
                               'resume where the previous ingestion activity '
                               'stopped and attempt to import all available '
                               'containers and artifacts.')

        # The API only allows for the last 12 hours to be accessible, and they
        # must be polled in no more than one hour intervals. Since this is very
        # much a real time service and playing catch-up is rather pointless,
        # limit polling to the last hour.

        mins = self.get_config()['initial_ingestion_window']

        try:
            mins = int(mins)
        except:
            return action_result.set_status(phantom.APP_ERROR, "Asset configuration parameter, initial_ingestion_window, must be an integer between 1 and 60")

        if not (1 <= mins <= 60):
            return action_result.set_status(phantom.APP_ERROR, "Asset configuration parameter, initial_ingestion_window, must be an integer between 1 and 60")

        start_at = ((datetime.utcnow() - timedelta(minutes=mins))
                    .replace(microsecond=0).isoformat() + 'Z')

        if (not self._state or 'last_poll' not in self._state or self._state['last_poll'] < start_at):
            self._state['last_poll'] = start_at

        params = {
            'sinceTime': self._state['last_poll']
        }

        # Connect to the server
        ret_val, data = self._make_rest_call(action_result, PP_API_PATH_ALL, params=params)

        if phantom.is_fail(ret_val):
            if "The sinceTime parameter gives a time too far into the past" in action_result.get_message():
                action_result.append_to_message("It is possible the Phantom clock has drifted. Please re-sync it or consider lowering initial_ingestion_window")
            return action_result.get_status()

        config = self.get_config()
        if config.get('ingest_permitted_clicks') and 'clicksPermitted' in data:
            self.save_progress('Processing {} permitted clicks'
                               .format(len(data['clicksPermitted'])))
            self._process_clicks(data['clicksPermitted'], 'permitted')
        if config.get('ingest_blocked_clicks') and 'clicksBlocked' in data:
            self.save_progress('Processing {} blocked clicks'
                               .format(len(data['clicksBlocked'])))
            self._process_clicks(data['clicksBlocked'], 'blocked')
        if (config.get('ingest_delivered_messages') and 'messagesDelivered' in data):
            self.save_progress('Processing {} delivered messages'
                               .format(len(data['messagesDelivered'])))
            self._process_messages(data['messagesDelivered'], 'delivered')
        if config.get('ingest_blocked_messages') and 'messagesBlocked' in data:
            self.save_progress('Processing {} blocked messages'
                               .format(len(data['messagesBlocked'])))
            self._process_messages(data['messagesBlocked'], 'blocked')

        self._state['last_poll'] = data['queryEndTime']

        return self.set_status(phantom.APP_SUCCESS)

    def _test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(param))
        start_at = ((datetime.utcnow() - timedelta(minutes=5))
                    .replace(microsecond=0).isoformat() + 'Z')

        params = {
            'sinceTime': start_at
        }

        # Connect to the server
        ret_val, _ = self._make_rest_call(action_result,
                                          PP_API_PATH_ALL, params=params)
        if phantom.is_fail(ret_val):
            return self.set_status_save_progress(phantom.APP_ERROR,
                                                 'Connection Failed.')

        return self.set_status_save_progress(phantom.APP_SUCCESS,
                                             'Connection successful.')

    def get_campaign_details(self, param):
        action_result = self.add_action_result(ActionResult(param))
        campaign_id = param.get('campaign_id')

        campaign_url = PP_API_PATH_CAMPAIGN.format(campaign_id)

        params = {'format': 'json'}

        ret_val, data = self._make_rest_call(action_result, campaign_url, params=params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(data)
        return action_result.set_status(phantom.APP_SUCCESS)

    def get_forensic_data(self, param):
        action_result = self.add_action_result(ActionResult(param))
        campaign_id = param.get('campaign_id')
        threat_id = param.get('threat_id')
        include_campaign_forensics = param.get('include_campaign_forensics')

        if not campaign_id and not threat_id:
            return action_result.set_status(phantom.APP_ERROR,
                                            ('Campaign ID or Threat ID must'
                                             ' be specified.'))

        if campaign_id and threat_id:
            return action_result.set_status(phantom.APP_ERROR,
                                            ('Only one of Campaign ID or '
                                             'Threat ID must be specified.'))

        params = {}
        if campaign_id:
            params['campaignId'] = campaign_id
        if threat_id:
            params['threatId'] = threat_id
            if include_campaign_forensics:
                params['includeCampaignForensics'] = include_campaign_forensics
        ret_val, data = self._make_rest_call(action_result,
                                             PP_API_PATH_FORENSICS, params=params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(data)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _decode_url(self, param):
        """ This function is used to handle the decoding of a Proofpoint rewritten URL.
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress(('In action handler for: {0}').format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {}
        url_list = []

        # The Decode API allows for multiple values. Split the parameter by ,
        url_split = param.get('url').split(',')

        for url in url_split:
            # Add the URL to the list to decode
            url_list.append(url)

        # Add the URL(s) to the json
        params['urls'] = url_list

        # Make rest call
        ret_val, response = self._make_rest_call(action_result, PP_API_PATH_DECODE, method="post", json=params)

        if (phantom.is_fail(ret_val)):
           return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        self.debug_print('action_id', self.get_action_identifier())

        action_mapping = {
            'test_connectivity': self._test_connectivity,
            'get_campaign_details': self.get_campaign_details,
            'get_campaign': self.get_campaign_details,
            'get_forensic_data': self.get_forensic_data,
            'get_forensic': self.get_forensic_data,
            'decode_url': self._decode_url,
            'on_poll': self._on_poll
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)
        return action_execution_status


if __name__ == '__main__':

    import sys
    import argparse
    import pudb

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
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ProofpointConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
