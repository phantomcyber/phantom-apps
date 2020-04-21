# File: ciscothreatresponse_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from ciscothreatresponse_consts import *
from datetime import datetime, timedelta
import functools
import json
import re
from bs4 import UnicodeDammit

import humanize
import requests
from collections import Counter
from requests.exceptions import HTTPError, ConnectionError
from threatresponse import ThreatResponse
from threatresponse.exceptions import RegionError


class ScopeError(Exception):
    """ Raised when scope check fails. """

    def __init__(self, missing_scopes):
        scope_names = list({re.findall(r'\w+', scope)[0].capitalize()
                            for scope in missing_scopes})

        super(ScopeError, self).__init__(
            'Missing scopes: {}. Please, make sure that your API client has '
            'correct scope settings.'.format(', '.join(sorted(scope_names)))
        )


class CiscoThreatResponseConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CiscoThreatResponseConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

        # Tread response credentials
        self._client_id = None
        self._client_password = None
        self._region = None
        self._tr = None

        self._action_result = None

    def _handle_test_connectivity(self, param):
        self._action_result.set_param(dict(param))

        # Connectivity is tested while tr module initialization
        # at initialize method before action handling.
        # If the execution got here, connection is OK.

        self.save_progress("Test Connectivity Passed")
        return self._action_result.set_status(phantom.APP_SUCCESS)

    def format_time(self, time):
        initial_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        presentation_format = '%Y-%m-%d %H:%M:%S'
        datetime_format = datetime.strptime(time, initial_format) \
            if time != '---' else ''
        return datetime.strftime(datetime_format,
                                 presentation_format) \
            if datetime_format else '---'

    def _handle_context(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        self._action_result.set_param(dict(param))

        observable = param['observable']

        self.save_progress("Context START")
        # Make calls
        observables = self._tr.inspect.inspect({'content': observable})
        result = self._tr.enrich.observe.observables(observables)
        contexts = []

        # Add mock if no targets available, but there is a sighting
        mock_for_no_targets = [{}]

        for e in result['data']:
            # Add initial responses with targets
            if e['data'].get('sightings', None):
                for doc in e['data']['sightings']['docs']:
                    context = self.build_context_dict(
                        doc['observables'][0]['value'],
                        doc['observables'][0]['type'],
                        e['module'],
                        self.format_time(doc.get('targets',
                                                 mock_for_no_targets)[0]
                            .get('observed_time', {}).get(
                            'start_time', '---')),
                        doc.get('targets', mock_for_no_targets)[0].get(
                            'type', '---'),
                        self.targets(doc.get('targets',
                                             mock_for_no_targets)[0].get(
                            'observables', {})) or '---'
                    )

                    # Update responses with
                    # targets with disposition name if any
                    if e['data'].get('verdicts', None):
                        context['disposition'] = \
                            e['data']['verdicts']['docs'][0][
                                'disposition_name']

                    if context not in contexts:
                        contexts.append(context)

            else:
                # Add objects with no targets but with verdicts
                if e['data'].get('verdicts', None):
                    for doc in e['data']['verdicts']['docs']:
                        context = self.build_context_dict(
                            doc['observable']['value'],
                            doc['observable']['type'],
                            e['module'],
                            self.format_time(doc.get('valid_time', {}).get(
                                'start_time', '---')),
                            '---',
                            '---',
                            doc['disposition_name'])

                        if context not in contexts:
                            contexts.append(context)

        summary_bar = self.get_summary_bar(observables, contexts)

        self._action_result.add_data({'response': result,
                                      'context': contexts,
                                      'summary': summary_bar})

        summary = self._action_result.update_summary({})
        summary['num_data'] = len(contexts)

        self.save_progress("Context OK")
        return self._action_result.set_status(phantom.APP_SUCCESS)

    def get_summary_bar(self, observables, contexts):
        targets = []
        for e in contexts:
            if e['target'] not in targets and e['target'] != '---':
                targets.append(e['target'])

        count = Counter(x['type'] for x in observables)

        return {
            "targets": len(targets),
            "observables": len(observables),
            "domains": count['domain'],
            "file_hash": count['sha256'] + count['sha1'],
            "ip_address": count['ip'] + count['ipv6'],
            "urls": count['url']
        }

    def targets(self, targets):
        return ', '.join("'{}': '{}'".format(e['type'],
                                            e['value']) for e in targets)

    def build_context_dict(self, observable, type, module,
                           observed, sensor,
                           target, disposition='---'):
        return {
            'observable': observable,
            'type': type,
            'disposition': disposition,
            'module': module,
            'observed': observed,
            'sensor': sensor,
            'target': '---' if not target else target
        }

    def _expiration(self, end_time):
        date_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        now = datetime.now()

        end = datetime.strptime(end_time, date_format) if end_time else None
        twenty_years_from_now = now + timedelta(days=20 * 365)

        if not end or end > twenty_years_from_now:
            return 'Indefinite'

        return humanize.naturaltime(now - end)

    def _humanize_expiration(self, verdicts):
        return [
            v.update({'expiration':
                    self._expiration(
                            v.get('expiration'))}) or v for v in verdicts
        ]

    def _handle_verdict(self, param):
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        self._action_result.set_param(dict(param))

        observable = param['observable']

        self.save_progress("Verdicts START")
        result = self._tr.commands.verdict(observable)

        verdicts = self._humanize_expiration(result.get('verdicts', []))

        self._action_result.add_data({'response': result.get('response'),
                                      'verdicts': verdicts})

        summary = self._action_result.update_summary({})
        summary['num_data'] = len(verdicts)

        self.save_progress("Verdicts OK")
        return self._action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", action_id)

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'context':
            ret_val = self._handle_context(param)

        elif action_id == 'verdict':
            ret_val = self._handle_verdict(param)

        return ret_val

    def is_authentication_error(self, response):
        return response.status_code == 400 and response.json().get('error') \
               in ('invalid_client', 'wrong_client_creds')

    def is_scope_missing(self, response):
        return response.status_code == 403 and response.json().get("error") \
               == "missing_scope"

    def check_scopes(self, tr):
        scope_checks = (
            functools.partial(tr.inspect.inspect,
                              {'content': 'testscope.com'}),
            functools.partial(tr.enrich.deliberate.observables,
                              [{"value": "testscope.com", "type": "domain"}])
        )

        all_missing_scopes = set()

        for check in scope_checks:
            try:
                check()
            except HTTPError as error:
                self.debug_print(repr(error))

                if self.is_scope_missing(error.response):
                    all_missing_scopes.update(
                        error.response.json().get('missing-scopes', set())
                    )
                else:
                    raise error

        if all_missing_scopes:
            raise ScopeError(all_missing_scopes)

    def connect(self):
        message = None

        try:
            tr = ThreatResponse(
                client_id=self._client_id,
                client_password=self._client_password,
                region=self._region
            )

            self.check_scopes(tr)
            return tr

        except RegionError as error:
            self.debug_print(repr(error))
            message = (
                'Please make sure that your Region is valid.'
            )

        except ScopeError as error:
            self.debug_print(repr(error))
            message = error.args[0]

        except HTTPError as error:
            self.debug_print(repr(error))
            if self.is_authentication_error(error.response):
                message = (
                    'Please make sure that your API credentials '
                    '(Client ID and Client Password) are valid.'
                )
            else:
                message = 'Unexpected HTTPError occurred.'

        except ConnectionError as error:
            self.debug_print(repr(error))
            message = 'Failed to connect to Cisco Threat Response.'

        except Exception as error:
            self.debug_print(repr(error))
            message = 'Unexpected error occurred.'

        raise Exception(message)

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name
        # Required values can be accessed directly
        required_config_name = config['required_config_name']
        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')
        self._action_result = self.add_action_result(ActionResult())

        self._client_id = config['client_id']
        self._client_id = UnicodeDammit(self._client_id).unicode_markup.encode('utf-8')
        self._client_password = config['client_password']
        self._region = str(config['region']).lower()
        if self._region == 'us':
            self._region = ''

        try:
            self._tr = self.connect()
        except Exception as error:
            if self.get_action_identifier() == 'test_connectivity':
                self.save_progress(str(error))
                return self._action_result.set_status(
                    phantom.APP_ERROR, "Test Connectivity Failed"
                )
            else:
                return self._action_result.set_status(phantom.APP_ERROR,
                                                      str(error))

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


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
            login_url = CiscoThreatResponseConnector._get_phantom_base_url() \
                        + '/login'

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
            r2 = requests.post(login_url,
                               verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id "
                  "from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CiscoThreatResponseConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
