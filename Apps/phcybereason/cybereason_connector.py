# File: cybereason_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import csv
import json
import urlparse
import datetime
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class CybereasonConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CybereasonConnector, self).__init__()

        self._state = None

        self._base_url = ''
        self._login_url = ''
        self._password = ''
        self._username = ''
        self._session = None

    def _process_time(self, time_in_ms):
        """ Change number of milliseconds into a timestamp.

        Args:
            time_in_ms (int): Timestamp from Cybereason (number of milliseconds)

        Returns:
            str: Timestamp in a more readable format (%Y-%m-%d %H:%M:%S).
        """
        if not time_in_ms:
            return ''

        try:
            time_in_seconds = int(time_in_ms)
        except ValueError:
            return time_in_ms

        return str(datetime.datetime.utcfromtimestamp(time_in_seconds / 1000))

    def _create_session(self, action_result):
        """ Check if a cookie exists and is valid. If not, login and save the cookie.

        Args:
            action_result (ActionResult): Action_result object for the current action

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('Validating/creating session with Cybereason')

        # Check if the session has already been created.
        if self._session:
            self.save_progress('Cookie already exists, skipping login')
            return action_result.set_status(phantom.APP_SUCCESS)

        self._session = requests.session()
        # Check if there is a cookie already created and test it.
        if 'cookie' in self._state:
            self._session.cookies.update(self._state['cookie'])
            response = self._session.get(self._base_url)
            if response.status_code != 200:
                return action_result.set_status(phantom.APP_ERROR, 'Login failed: {0}'.format(response.status_code))
            if 'modal-content' in response.text:
                # Cookie is still good
                self.save_progress('Session created')
                return action_result.set_status(phantom.APP_SUCCESS)

        auth = {'username': self._username, 'password': self._password}
        url = urlparse.urljoin(self._base_url, 'login.html')

        response = self._session.post(url, data=auth)

        code = response.status_code

        if code == 500:
            return action_result.set_status(phantom.APP_ERROR, 'Server error')
        elif code != 200:
            return action_result.set_status(phantom.APP_ERROR, 'Login failed: {0}'.format(code))

        cookies = requests.utils.dict_from_cookiejar(self._session.cookies)
        cookie = {}
        for name, value in cookies.iteritems():
            if name == 'JSESSIONID' and value:
                cookie[name] = value
                self._state['cookie'] = cookie

                self.save_progress('Session created')
                return action_result.set_status(phantom.APP_SUCCESS)

        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)[0]

        return action_result.set_status(phantom.APP_ERROR, 'Unable to create session')

    def _process_empty_response(self, response, action_result):
        """ Process empty requests response from API call.

        Args:
            response: expected empty response from requests API call
            action_result (ActionResult): object of ActionResult class

        Returns:
            RetVal:
                * action_result: status success/failure
                * {} or None
        """
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, 'Empty response and no information in the header'), None)

    def _process_html_response(self, response, action_result):
        """ Process html requests response from API call.

        Do this no matter what the api talks. There is a high chance of a PROXY in between phantom
        and the rest of world, in case of errors, PROXY's return HTML, this function parses the
        error and adds it to the action_result.

        Args:
            response: html response from requests API call
            action_result (ActionResult): object of ActionResult class

        Returns:
            RetVal:
                * action_result: status success/failure
                * response.content or None
        """
        # Check if an attachment is returned otherwise, treat it like an error.
        if 'attachment' in response.headers.get('Content-Disposition', {}):
            return RetVal(phantom.APP_SUCCESS, response.content)

        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = 'Cannot parse error details'

        message = 'Status Code: {0}. Data from server:\n{1}\n'.format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        """ Process json from an API call.

        Args:
            r: json response from requests API call
            action_result (ActionResult): object of ActionResult class

        Returns:
            RetVal:
                * action_result: status success/failure
                * dict: resp_json
        """

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Unable to parse JSON response. Error: {0}'.format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = 'Error from server. Status Code: {0} Data from server: {1}'.format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_octet_stream(self, response, action_result):
        """ Process octet stream from an API call.

        Args:
            response: octet stream response from requests API call
            action_result (ActionResult): object of ActionResult class

        Returns:
            RetVal:
                * action_result: status success/failure
                * dict: response.content
        """
        return RetVal(action_result.set_status(phantom.APP_SUCCESS), response.content)

    def _process_response(self, r, action_result):
        """ Route response to correct processor.

        Args:
            r: content response from requests API call
            action_result (ActionResult): object of ActionResult class

        Returns:
            RetVal:
                * action_result: status success/failure
                * <processed response>
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately
        content_type = r.headers.get('Content-Type', 'No content type found.')

        # Process a json response
        if 'json' in content_type:
            return self._process_json_response(r, action_result)

        # Process file downloads (e.g., get indicators)
        if 'octet-stream' in content_type:
            return self._process_octet_stream(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in content_type:
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = 'Unable to process response from server. Status Code: {0}\nData from server: {1}\nContent-Type: {2}'.format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'), content_type)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, payload=None, headers=None, data=None, method='get'):
        """ Generic requests wrapper for making calls to a REST API.

        Args:
            endpoint (str): full URL of REST API endpoint
            action_result (ActionResult): object of ActionResult class
            payload (:obj:`dict`, optional): parameters to append to URI
            headers (:obj:`dict`, optional): dict of custom headers to send
            data (:obj:`str`, optional): json string to send to server
            method (:obj:`str`, optional): type of HTTP request to make (get, post, put, delete, etc...)

        Returns:
            RetVal:
                * action_result: status success/failure
                * <processed response>
        """
        config = self.get_config()

        resp_json = None

        if not self._session:
            ret_val = self._create_session(action_result)
            if phantom.is_fail(ret_val):
                return RetVal(action_result.get_status(), resp_json)

        try:
            request_func = getattr(self._session, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Invalid method: {0}'.format(method)), resp_json)

        # Create a URL to connect to
        url = urlparse.urljoin(self._base_url, endpoint)
        self.save_progress('*** make rest call ***')
        self.save_progress('url: {}'.format(url))
        self.save_progress('data: {}'.format(data))
        self.save_progress('headers: {}'.format(headers))
        self.save_progress('payload: {}'.format(payload))

        try:
            r = request_func(url,
                             json=data,
                             headers=headers,
                             verify=config.get('verify_server_cert', False),
                             params=payload)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error Connecting to server. Details: {0}'.format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        """ Validate the asset configuration for connectivity using supplied configuration.

        Args:
            param (dict): Parameters from action call.

        Returns:
            ActionResult: status success/failure
        """

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress('Connecting to endpoint and testing authentication.')
        # make rest call
        ret_val = self._create_session(action_result)

        if phantom.is_fail(ret_val):
            # the call to cybereason failed, action result should contain all the error details
            # so just return from here
            self.save_progress('Test Connectivity Failed. Error: {0}'.format(action_result.get_message()))
            return action_result.get_status()

        # Return success
        self.save_progress('Test Connectivity Passed')

        return action_result.get_status()

    def _handle_malop_remediation(self, param):
        """ !!! Cybereason asked that this action not be used at this time. !!!

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        malop_id = param['malop_id']
        data = {malop_id: 'CLOSED'}
        endpoint = '/rest/crimes/status'

        ret_val, response = self._make_rest_call(endpoint, action_result, data=data, method='post')
        if phantom.is_fail(ret_val):
            self.save_progress('Failed to move malop')
            return action_result.get_status()

        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['results'] = ret_val

        return action_result.set_status(phantom.APP_SUCCESS, 'Malop remediation successful')

    def _handle_get_malops(self, param):
        """

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        data = {'queryPath': [{'requestedType': 'MalopProcess', 'result': True}],
                'totalResultLimit': 10000,
                'perGroupLimit': 10000,
                'perFeatureLimit': 10000,
                'templateContext': 'OVERVIEW'}
        endpoint = '/rest/crimes/unified'

        ret_val, resp = self._make_rest_call(endpoint, action_result, data=data, method='post')
        if phantom.is_fail(ret_val):
            self.save_progress('Failed to get malops')
            return action_result.get_status()

        self.save_progress('Parsing response.')

        if not resp.get('data', {}):
            return action_result.set_status(phantom.APP_ERROR, 'Unable to find required key, "data", in response')
        if not resp['data'].get('resultIdToElementDataMap', {}):
            action_result.update_summary({'status': resp.get('status')})
            return action_result.set_status(phantom.APP_SUCCESS, 'No malops to return.')

        # Filter out everything that doesn't match the filter from the action param
        filter_dict = {
            'All': None,
            'Open': 'OPEN',
            'Unread': 'UNREAD',
            'Closed': 'CLOSED',
            'False Positive': 'FP'
        }
        mode = filter_dict[param['type']]
        output = {}
        if mode is not None:
            filter_me = resp['data'].pop('resultIdToElementDataMap')
            for malop_id, values in filter_me.iteritems():
                if values.get('simpleValues', {}).get('managementStatus', {}).get('values', [None])[0] == mode:
                    output[malop_id] = values
        else:
            output = resp['data'].pop('resultIdToElementDataMap')

        if len(output) == 0:
            action_result.update_summary({'status': resp.get('status')})
            return action_result.set_status(phantom.APP_SUCCESS, 'No malops match filter, {}.'.format(param['type']))

        # Parse malops and add to action_results
        required_keys = ['simpleValues', 'elementValues']
        required_keys_exist = False

        for malop_id, values in output.iteritems():
            # Check if required keys exist for at least one of the resultIdToElementDataMap results
            if not set(required_keys).issubset(values.keys()):
                continue
            required_keys_exist = True

            malop = {'malopID': malop_id}

            # Parse comments
            if 'comments' in values['simpleValues']:
                comments = []
                for ele in values['simpleValues']['comments'].get('values', []):
                    ele['timestamp'] = self._process_time(ele.get('timestamp'))
                    comments.append(ele)
                malop['comments'] = comments

            # Parse elementValue section
            for element in ['affectedMachines', 'affectedUsers']:
                if element in values['elementValues']:
                    value_list = []
                    for v in values['elementValues'][element].get('elementValues', []):
                        value_list.append(v['name'])
                    malop[element] = value_list

            # Parse simpleValue section
            for simple in ['malopActivityTypes', 'rootCauseElementNames', 'rootCauseElementTypes', 'detectionType',
                           'isBlocked', 'managementStatus', 'malopStartTime', 'malopLastUpdateTime']:
                if simple in values['simpleValues']:
                    if simple.endswith('Time'):
                        malop[simple] = self._process_time(values['simpleValues'][simple].get('values', [None])[0])
                    else:
                        malop[simple] = ', '.join(values['simpleValues'][simple].get('values', [None]))

            action_result.add_data(malop)

        # Add a dictionary that is made up of the most important values from data into the summary
        action_result.update_summary({'status': resp.get('status'), 'malop_count': len(output)})

        # return error if none of the outputs have the required keys return error
        if not required_keys_exist:
            message = 'Unable to find required keys, "data.resultIdToElementDataMap.<all {} objects>.({})", in response.'.format(param['type'], '|'.join(required_keys))
            return action_result.set_status(phantom.APP_ERROR, message)

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved malops')

    def _get_machine_details(self, action_result, identifiers):
        """ Query server to return the details of machines tracked in Cybereason.

        Args:
            action_result (ActionResult): Action_result object for the current action
            identifiers (list): machine names that can identify a machine in Cybereason

        Returns:
            RetVal:
                * str: status success/failure
                * dict or None: dictionary of machine details for each requested identifier, if successful
        """
        if not isinstance(identifiers, list):
            identifiers = [identifiers]

        required_fields = ['elementDisplayName',
                           'pylumId']
        optional_fields = ['osVersionType',
                           'platformArchitecture',
                           'uptime',
                           'isActiveProbeConnected',
                           'lastSeenTimeStamp',
                           'isIsolated']
        endpoint = '/rest/visualsearch/query/simple'
        query = {'queryPath': [{'requestedType': 'Machine',
                                'filters': [{'facetName': 'elementDisplayName', 'values': identifiers, 'filterType': 'ContainsIgnoreCase'}],
                                'isResult': True}],
                 'totalResultLimit': 1000,
                 'perGroupLimit': 100,
                 'perFeatureLimit': 100,
                 'templateContext': 'SPECIFIC',
                 'queryTimeout': 120000,
                 'customFields': required_fields + optional_fields
                 }
        ret_val, response = self._make_rest_call(endpoint, action_result, data=query, method='post')
        if phantom.is_fail(ret_val):
            msg = 'Failed to retrieve query response'
            self.save_progress(msg)
            return RetVal(action_result.set_status(phantom.APP_ERROR, msg), None)

        identifiers = [i.upper() for i in identifiers]  # change identifiers to be uppercase
        results = {k: {} for k in identifiers}

        # Add try/ except to catch key errors to end execution, if missing certain keys.
        try:
            data_maps = response['data']['resultIdToElementDataMap']
            for data_map in data_maps.itervalues():
                display_names = data_map['simpleValues']['elementDisplayName']['values']

                for name in display_names:
                    if name.upper() in identifiers:
                        pylum_ids = data_map['simpleValues']['pylumId']['values']

                        for pylum_id in pylum_ids:
                            # Check if the last seen is greater than another that we have already processed and replace
                            last_seen = data_map['simpleValues'].get('lastSeenTimeStamp', {}).get('values', [0])[0]
                            if last_seen > results[name].get('lastSeenTimeStamp', {}).get('values', 0):
                                details = {'pylum_id': pylum_id}

                                for field in optional_fields:
                                    # Change detail field name to fit standard
                                    detail_field = ''.join('_' + c.lower() if c.isupper() else c for c in field)

                                    # Get the first item from each optional field
                                    details[detail_field] = data_map['simpleValues'].get(field, {}).get('values', [None])[0]
                                results[name.upper()] = details

        except KeyError as message:
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        return RetVal(phantom.APP_SUCCESS, results)

    def _update_device(self, action_result, param, command='un-isolate'):
        """ Used to isolate or un-isolate devices in Cybereason.

        First, the IP or hostname needs to be matched up to a cybereason pylumid, then the command to isolate/un-isolate can be made.

        Args:
            action_result (ActionResult): Action_result object for the current action
            param (dict): Parameters sent in by a user or playbook
            command (str): Command to use upon update [Should be 'isolate' or 'un-isolate'

        Returns:
            ActionResult status: success/failure
        """
        if command not in ['isolate', 'un-isolate']:
            return action_result.set_status(phantom.APP_ERROR, '{} device command not implemented'.format(command))

        identifiers = param['identifier'].split(',')

        ret_val, machine_details = self._get_machine_details(action_result, identifiers)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Check if the machine is already isolated or not.
        isolated = []
        unisolated = []
        for identifier in identifiers:
            detail = machine_details[identifier.upper()]
            if detail.get('is_isolated') == 'true':
                isolated.append(detail['pylum_id'])
            else:
                unisolated.append(detail['pylum_id'])

        if command == 'isolate':
            pylum_ids = unisolated
            for isolated_host in isolated:
                action_result.add_data({'pylimid': isolated_host, 'status': 'Already isolated'})
        elif command == 'un-isolate':
            pylum_ids = isolated
            for unisolated_host in unisolated:
                action_result.add_data({'pylimid': unisolated_host, 'status': 'Already unisolated'})

        summary = action_result.update_summary({'number_of_devices_to_{}'.format(command): len(pylum_ids)})

        # If there are no hosts to run on the expected command, exit successfully.
        if len(pylum_ids) == 0:
            return action_result.set_status(phantom.APP_SUCCESS, 'Devices are already {}d'.format(command))

        data = {'pylumIds': pylum_ids}
        endpoint = 'rest/monitor/global/commands/{}'.format(command)  # should be 'isolate' or 'un-isolate'

        ret_val, response = self._make_rest_call(endpoint, action_result, data=data, method='post')
        if phantom.is_fail(ret_val):
            self.save_progress('Failed to update indicators')
            return action_result.get_status()

        for pylum_id, status in response.iteritems():
            action_result.add_data({'pylimid': pylum_id, 'status': status})

        failures = []
        for pylum_id in pylum_ids:
            if not response.get(pylum_id) or response.get(pylum_id) != 'Succeeded':
                failures.append(pylum_id)

        if not failures:
            return action_result.set_status(phantom.APP_SUCCESS, 'Command ({}) successfully complete'.format(command))
        else:
            summary['number_of_failed'] = len(failures)
            return action_result.set_status(phantom.APP_ERROR, 'Unsuccessful quarantine/ un-quarantine of {}'.format(', '.join(failures)))

    def _handle_quarantine_device(self, param):
        """ Wrapper for _update_device to quarantine a device.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        command = 'isolate'

        return self._update_device(action_result, param, command)

    def _handle_unquarantine_device(self, param):
        """ Wrapper for _update_device to quarantine a device.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        command = 'un-isolate'

        return self._update_device(action_result, param, command)

    def _handle_get_indicators(self, param):
        """ Retrieve all indicators currently loaded on Cybereason.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = '/rest/classification/download'

        ret_val, response = self._make_rest_call(endpoint, action_result)
        if phantom.is_fail(ret_val):
            self.save_progress('Failed to get indicators')
            return action_result.get_status()

        try:
            results = list(csv.DictReader(response.splitlines()))
        except:
            results = []

        if not results:
            return action_result.set_status(phantom.APP_SUCCESS, 'Indicator list is empty')

        # Replace string values with Python literals in each row
        replace = {'false': False, 'true': True, 'null': None}
        for row in results:
            for key, value in row.iteritems():
                if value in replace:
                    row[key] = replace[value]
            action_result.add_data(row)

        action_result.update_summary({'indicator_count': len(results)})

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved indicators')

    def _update_indicator(self, action_result, param, remove=False):
        """ Used to either add or remove indicators from Cybereason.

        Args:
            action_result (ActionResult): Action_result object for the current action
            param (dict): Parameters sent in by a user or playbook
            remove (bool): If True, delete the indicator from the list

        Returns:
            ActionResult status: success/failure
        """
        keys = [value.strip().lower() for value in param['keys'].split(',')]
        data = [{'keys': keys,
                 'maliciousType': param['reputation'],
                 'prevent': param['prevention'],
                 'remove': remove}]
        endpoint = 'rest/classification/update'

        ret_val, response = self._make_rest_call(endpoint, action_result, data=data, method='post')
        if phantom.is_fail(ret_val):
            self.save_progress('Failed to update indicators')
            return action_result.get_status()

        for key in keys:
            action_result.add_data({'key': key,
                                    'reputation': param['reputation'],
                                    'prevent': param['prevention'],
                                    'remove': remove})

        action_result.update_summary(response)

        if 'outcome' in response:
            if response['outcome'] == 'success':
                return action_result.set_status(phantom.APP_SUCCESS, 'Successfully updated indicators')
            else:
                return action_result.set_status(phantom.APP_ERROR, 'Failed updating the indicator list')
        else:
            return action_result.set_status(phantom.APP_ERROR, 'Unexpected response from server')

    def _handle_add_indicators(self, param):
        """ Wrapper for _update_indicator to add an indicator.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        return self._update_indicator(action_result, param, remove=False)

    def _handle_delete_indicators(self, param):
        """ Wrapper for _update_indicator to delete an indicator.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        return self._update_indicator(action_result, param, remove=True)

    def handle_action(self, param):
        """ Phantom action handler for Cybereason.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            status success/failure
        """

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print('action_id:', action_id)

        supported_actions = {
            'test_connectivity': self._handle_test_connectivity,
            # 'malop_remediation': self._handle_malop_remediation,  # Disabled at request of Cybereason.
            'get_malops': self._handle_get_malops,
            'quarantine_device': self._handle_quarantine_device,
            'unquarantine_device': self._handle_unquarantine_device,
            'get_indicators': self._handle_get_indicators,
            'add_indicators': self._handle_add_indicators,
            'delete_indicators': self._handle_delete_indicators
        }

        if action_id in supported_actions:
            ret_val = supported_actions[action_id](param)
        else:
            raise ValueError('Action {0} is not supported'.format(action_id))

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config['base_url']
        self._username = config['username']
        self._password = config['password']

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


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
        password = getpass.getpass('Password: ')

    if (username and password):
        try:
            print ('Accessing the Login page')
            r = requests.get('https://127.0.0.1/login', verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ('Logging into Platform to get the session id')
            r2 = requests.post('https://127.0.0.1/login', verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ('Unable to get session id from the platfrom. Error: ' + str(e))
            exit(1)

    if (len(sys.argv) < 2):
        print 'No test json specified as input'
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CybereasonConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
