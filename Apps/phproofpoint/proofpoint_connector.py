# Copyright (c) 2017-2019 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from datetime import datetime
from datetime import timedelta
from HTMLParser import HTMLParseError
from bs4 import BeautifulSoup
import requests

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult


PP_API_BASE_URL = 'https://tap-api-v2.proofpoint.com'
PP_API_PATH_CLICKS_BLOCKED = '/v2/siem/clicks/blocked'
PP_API_PATH_CLICKS_PERMITTED = '/v2/siem/clicks/permitted'
PP_API_PATH_MESSAGES_BLOCKED = '/v2/siem/messages/blocked'
PP_API_PATH_MESSAGES_DELIVERED = '/v2/siem/messages/delivered'
PP_API_PATH_ISSUES = '/v2/siem/issues'
PP_API_PATH_ALL = '/v2/siem/all'
PP_API_PATH_CAMPAIGN = '/v2/campaign/{}'
PP_API_PATH_FORENSICS = '/v2/forensics'


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

    def _make_rest_call(self, action_result, endpoint, params=None):
        config = self.get_config()
        user = config['username'].encode('utf-8')
        password = config['password']
        url = PP_API_BASE_URL + endpoint
        if not params:
            params = {}
        params['format'] = 'json'

        try:
            res = requests.get(url, params=params, auth=(user, password))
            res.raise_for_status()
        except requests.exceptions.HTTPError:
            # a status code outside of the 200s occured
            res_text = res.text.replace('{', '{{').replace('}', '}}')
            message = ('Error response from server. Status code: {0}'
                       'Response: {1}').format(res.status_code, res_text)
            return action_result.set_status(phantom.APP_ERROR, message), None
        except requests.exceptions.RequestException as e:
            message = 'Error connecting to the url ({0})'.format(url)
            return (action_result.set_status(phantom.APP_ERROR, message, e),
                    None)

        content_type = res.headers.get('Content-Type', '')
        if 'html' in content_type:
            try:
                soup = BeautifulSoup(res.test, 'html.parser')
                error_text = soup.text
                split_lines = error_text.splitlines()
                split_lines = [x.strip() for x in split_lines if x.strip()]
                error_text = '\n'.join(split_lines)
            except HTMLParseError as e:
                error_text = 'Cannot parse error details: {}'.format(e.msg)

            message = ('Error response from server. Status code: {0}'
                       'Response: \n{1}\n').format(res.status_code, error_text)
            return action_result.set_status(phantom.APP_ERROR, message), None
        elif 'plain' not in content_type and 'json' not in content_type:
            res_text = res.text.replace('{', '{{').replace('}', '}}')
            message = 'Unexpected response from server: {0}'.format(res_text)
            return action_result.set_status(phantom.APP_ERROR, message), None

        try:
            return phantom.APP_SUCCESS, res.json()
        except ValueError as e:
            message = 'Unable to parse response JSON.'
            return (action_result.set_status(phantom.APP_ERROR, message, e),
                    None)

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

        start_at = ((datetime.utcnow() - timedelta(hours=1))
                    .replace(microsecond=0).isoformat() + 'Z')

        if (not self._state or 'last_poll' not in self._state or
                self._state['last_poll'] < start_at):
            self._state['last_poll'] = start_at

        params = {
            'sinceTime': self._state['last_poll']
        }

        # Connect to the server
        ret_val, data = self._make_rest_call(action_result,
                                             PP_API_PATH_ALL, params)
        if phantom.is_fail(ret_val):
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
        if (config.get('ingest_delivered_messages') and
                'messagesDelivered' in data):
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
        start_at = ((datetime.utcnow() - timedelta(hours=1))
                    .replace(microsecond=0).isoformat() + 'Z')

        params = {
            'sinceTime': start_at
        }

        # Connect to the server
        ret_val, _ = self._make_rest_call(action_result,
                                          PP_API_PATH_ALL, params)
        if phantom.is_fail(ret_val):
            return self.set_status_save_progress(phantom.APP_ERROR,
                                                 'Connection Failed.')

        return self.set_status_save_progress(phantom.APP_SUCCESS,
                                             'Connection successful.')

    def get_campaign_details(self, param):
        action_result = self.add_action_result(ActionResult(param))
        campaign_id = param.get('campaign_id')

        campaign_url = PP_API_PATH_CAMPAIGN.format(campaign_id)

        ret_val, data = self._make_rest_call(action_result, campaign_url)
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
                                             PP_API_PATH_FORENSICS, params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(data)
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()

        if action == phantom.ACTION_ID_INGEST_ON_POLL:
            result = self._on_poll(param)
        elif action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self._test_connectivity(param)
        elif ((action == 'get_campaign_details') or (action == 'get_campaign')):
            result = self.get_campaign_details(param)
        elif ((action == 'get_forensic_data') or (action == 'get_forensic')):
            result = self.get_forensic_data(param)
        return result
