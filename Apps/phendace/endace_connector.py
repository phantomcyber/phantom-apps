# --
# File: endace_connector.py
#
# Copyright (C) Endace Technology Limited, 2018-2021
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Phantom App imports
import phantom.app as phantom
# import phantom.utils as utils
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom import vault as Vault

from endace_consts import *
import requests
import tempfile
import shutil
import json
import os
import re

from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class EndaceConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(EndaceConnector, self).__init__()

        self.server = None
        self.verify_cert = None
        self.username = None
        self.password = None
        self.max_pcap_size = None
        self._base_url = None

        self._state = None

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = ERR_CODE_MSG
        error_msg = ERR_MSG_UNAVAILABLE

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
        except:
            pass

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """
        Validate an integer.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, VALID_INT_MSG.format(param=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, VALID_INT_MSG.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, NON_NEG_INT_MSG.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, NON_NEG_NON_ZERO_INT_MSG.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _process_empty_response(self, response, action_result):
        """ Process empty requests response from API call.

        Args:
            response: empty response from requests API call
            action_result (ActionResult): object of ActionResult class

        Returns:
            RetVal:
                * action_result: status success/failure
                * {} or None
        """

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                'Status Code: {}. Empty response and no information in the header'.format(response.status_code)), None)

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
                * action_result: status failure
                * None
        """
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
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
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Unable to parse JSON response. Error: {0}'.format(err_msg)), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = 'Error from server. Status Code: {0} Data from server: {1}'.format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_content_response(self, response, action_result):
        """ Process plain content from an API call. Can be used for downloading files.

        Args:
            response: content response from requests API call
            action_result (ActionResult): object of ActionResult class

        Returns:
            RetVal:
                * action_result: status success/failure
                * content or None
        """

        status = response.status_code

        if status == 200:
            return RetVal(phantom.APP_SUCCESS, response.content)

        message = 'Error from server. Status code: {0}'.format(status)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

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
        content_type = r.headers.get('Content-Type', '')

        # Process a json response
        if 'json' in content_type:
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in content_type:
            return self._process_html_response(r, action_result)

        if 'vnd.tcpdump.pcap' in content_type:
            return self._process_content_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method='get'):
        """ Generic requests wrapper for making calls to a REST API.

        Args:
            endpoint (str): full URL of REST API endpoint
            action_result (ActionResult): object of ActionResult class
            headers (:obj:`dict`, optional): dict of custom headers to send
            params (:obj:`dict`, optional): parameters to append to URI
            data (:obj:`str`, optional): json string to send to server
            method (:obj:`str`, optional): type of HTTP request to make (get, post, put, delete, etc...)

        Returns:
            RetVal:
                * action_result: status success/failure
                * <processed response>
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Invalid method: {0}'.format(method)), resp_json)

        # Create a URL to connect to
        url = "{}{}".format(self._base_url, endpoint)

        try:
            r = request_func(url,
                             auth=(self.username, self.password),
                             json=data,
                             headers=headers,
                             verify=self.verify_cert,
                             params=params)
        except requests.exceptions.InvalidSchema:
            error_message = 'Error connecting to server. No connection adapters were found for {}'.format(url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.InvalidURL:
            error_message = 'Error connecting to server. Invalid URL {}'.format(url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except requests.exceptions.ConnectionError:
            error_message = 'Error connecting to server. Connection refused from server for {}'.format(url)
            return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), resp_json)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Error Connecting to server. Details: {0}'.format(err_msg)), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        """ Validate the asset configuration for connectivity using supplied configuration.

        Args:
            param (dict): Parameters from action call.

        Returns:
            ActionResult: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress('Connecting to Endace')
        # make rest call
        ret_val, response = self._make_rest_call('', action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            self.save_progress('Test Connectivity Failed')
            return action_result.get_status()

        if 'links' not in response:
            # The response should be a json object with a list of links.
            self.save_progress('Test Connectivity Failed')
            return action_result.set_status(phantom.APP_ERROR, 'Unexpected response: {0}'.format(response))

        self.save_progress('Test Connectivity Passed')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _move_file_to_vault(self, container_id, file_size, type_str, local_file_path, action_result):
        """ Moves a downloaded file to vault.

        Args:
            container_id (str): ID of the container in which we need to add vault file
            file_size (int): size of file
            type_str (str): file type
            local_file_path (str): path where file is stored
            action_result (ActionResult): object of ActionResult class
        Return:
            RetVal:
                * str: status success/failure
                * dict or None: vault details, if successful
        """

        self.send_progress(phantom.APP_PROG_ADDING_TO_VAULT)

        vault_details = {phantom.APP_JSON_SIZE: file_size,
                         phantom.APP_JSON_TYPE: type_str,
                         phantom.APP_JSON_CONTAINS: [type_str],
                         phantom.APP_JSON_ACTION_NAME: self.get_action_name(),
                         phantom.APP_JSON_APP_RUN_ID: self.get_app_run_id()}

        file_name = os.path.basename(local_file_path)

        # Adding file to vault
        try:
            success, message, vault_id = Vault.vault_add(container_id, local_file_path, file_name)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Unable to get Vault item details from Phantom. Details: {0}'.format(err_msg)), None)

        # Updating report data with vault details
        if success:
            success, message, info = Vault.vault_info(vault_id, file_name, container_id, trace=True)
            vault_details[phantom.APP_JSON_VAULT_ID] = vault_id
            vault_details['filename'] = file_name
            if success:
                self.send_progress('Success adding file to Vault. Vault ID: {}'.format(vault_id))
            return RetVal(phantom.APP_SUCCESS, vault_details)

        # Error while adding file to vault
        self.debug_print('ERROR: Adding file to vault:', message)
        action_result.append_to_message('. {}'.format(message))

        # set the action_result status to error, the handler function
        # will most probably return as is
        return RetVal(phantom.APP_ERROR, None)

    def _handle_get_pcap(self, param):
        """ Request PCAP download, get status, and save to disk.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult:
                * str: status success/failure
                * str: message
        """

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))
        summary_data = action_result.update_summary({'pcap_id': param['pcap_id']})

        endpoint = "datamines/{}/download/download.pcap".format(param['pcap_id'])

        self.send_progress('Download starting')
        # Start download of PCAP file
        dl_ret_val, dl_response = self._make_rest_call(endpoint, action_result, method='get')

        # Check if something went wrong with the request
        if phantom.is_fail(dl_ret_val):
            return action_result.get_status()

        self.send_progress('Checking status of download')
        # Run get_status to check if the download fully completed or if it had been canceled
        endpoint = "datamines/{}".format(param['pcap_id'])
        status_ret_val, status_response = self._make_rest_call(endpoint, action_result, method='get')

        all_response = {'status': status_response}

        if phantom.is_fail(status_ret_val):
            return action_result.get_status()

        state = status_response.get('datamine', {}).get('status', {}).get('state', None)
        summary_data['state'] = state
        if state != 'COMPLETED':
            action_result.add_data(all_response)
            return action_result.set_status(phantom.APP_ERROR, 'Error downloading file. {}'.format(state))

        filename = "{}.pcap".format(param['pcap_id'])

        self.send_progress('Saving file to disk')
        # Creating file
        temp_dir = tempfile.mkdtemp()
        try:
            file_path = os.path.join(temp_dir, filename)
            with open(file_path, 'wb') as file_obj:
                file_obj.write(dl_response)
        except Exception as e:
            self.debug_print('Error creating file')
            shutil.rmtree(temp_dir)
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, 'Error creating file. Error Details: {}'.format(err_msg))

        container_id = self.get_container_id()

        # Check if file with same file name and size is available in vault and save only if it is not available
        try:
            vault_list = Vault.vault_info(container_id=container_id)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR,
                                            'Unable to get Vault item details from Phantom. Details: {0}'.format(err_msg))

        vault_details = {}
        try:
            # Iterate through each vault item in the container and compare name and size of file
            for vault in vault_list[2]:
                if vault.get('name') == filename and vault.get('size') == os.path.getsize(file_path):
                    self.send_progress('PCAP already available in Vault')
                    vault_details = {phantom.APP_JSON_SIZE: vault.get('size'),
                                    phantom.APP_JSON_VAULT_ID: vault.get(phantom.APP_JSON_VAULT_ID),
                                    'filename': filename}
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, 'Error details: {}'.format(err_msg))

        if not vault_details:
            vault_ret_val, vault_details = self._move_file_to_vault(container_id, os.path.getsize(file_path), 'pcap',
                                                                    file_path, action_result)
            # Check if something went wrong while moving file to vault
            if phantom.is_fail(vault_ret_val):
                return action_result.set_status(phantom.APP_ERROR, 'Could not move file to vault')

        shutil.rmtree(temp_dir)

        summary_data['file_availability'] = True
        summary_data[phantom.APP_JSON_VAULT_ID] = vault_details[phantom.APP_JSON_VAULT_ID]

        all_response['vault'] = vault_details
        action_result.add_data(all_response)

        message = 'PCAP downloaded to Vault: {0}'.format(vault_details[phantom.APP_JSON_VAULT_ID])

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_delete_pcap(self, param):
        """ Delete datamine from Endace, if the PCAP download is in progress, it is canceled then deleted.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult:
                * str: status success/failure
                * str: message
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = "datamines/{}".format(param['pcap_id'])

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, method='delete')

        if phantom.is_fail(ret_val):
            # the call to Endace failed, action result should contain all the error details.
            return action_result.get_status()

        action_result.add_data(response)

        resp = response.get('messages', [{}])[0]
        action_result.update_summary({'name': resp.get('name', None), 'type': resp.get('type', None)})

        message = resp.get('description', None)

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_status(self, param):
        """ Get status for a specific datamine from Endace.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult:
                * str: status success/failure
                * str: message
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = "datamines/{}".format(param['pcap_id'])

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, method='get')

        if phantom.is_fail(ret_val):
            # the call to Endace failed, action result should contain all the error details.
            return action_result.get_status()

        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        state = response.get('datamine', {}).get('status', {}).get('state', None)
        message = state
        summary['state'] = state
        if state == 'RUNNING':
            summary['progress_percentage'] = response.get('datamine', {}).get('status', {}).get('progressPercentage', None)
            message += '; {:.0f}% complete'.format(summary['progress'] * 100)

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_run_query(self, param):
        """ First creates flow search, and if there are results and they do not exceed the max pcap byte limit, create the datamine too.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult:
                * str: status success/failure
                * str: message
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Add required fields.
        parameters = {'host1': param['host1'],
                      'host2': param['host2'],
                      'protocol': param['protocol']}

        # Validate time fields
        if 'time' in param:
            parameters['time3339'] = param.get('time')
            # Integer validation for 'span_before' action parameter
            span_before = param.get('span_before', 30)
            ret_val, span_before = self._validate_integer(action_result, span_before, SPAN_BEFORE_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            parameters['spanBefore'] = span_before
            # Integer validation for 'span_after' action parameter
            span_after = param.get('span_after', 30)
            ret_val, span_after = self._validate_integer(action_result, span_after, SPAN_AFTER_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            parameters['spanAfter'] = span_after
        elif 'start_time' in param and 'end_time' in param:
            parameters['startTime3339'] = param.get('start_time')
            parameters['endTime3339'] = param.get('end_time')
        else:
            message = 'Missing parameters. Either ("time") or ("start_time" and "end_time") are required to run this action'
            return action_result.set_status(phantom.APP_ERROR, message)

        if 'port1' in param:
            # Integer validation for 'port1' action parameter
            port1 = param.get('port1')
            ret_val, port1 = self._validate_integer(action_result, port1, PORT1_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            parameters['port1'] = port1

        if 'port2' in param:
            # Integer validation for 'port2' action parameter
            port2 = param.get('port2')
            ret_val, port2 = self._validate_integer(action_result, port2, PORT2_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            parameters['port2'] = port2

        # make rest call
        flow_ret_val, flow_resp = self._make_rest_call('flowsearch', action_result, params=parameters, method='get')

        if phantom.is_fail(flow_ret_val):
            # the call to Endace failed, action result should contain all the error details.
            return action_result.get_status()

        self.save_progress('Flow search complete')

        all_response = {'flow': flow_resp}

        byte_count = flow_resp.get('results', {}).get('total', {}).get('flowByteCount', -1)
        summary = action_result.update_summary({'flow_byte_count': byte_count})

        # Check max pcap size before continuing.
        if not int(self.max_pcap_size) == 0:  # if set to 0, ignore max_byte_count
            if int(byte_count) > int(self.max_pcap_size):
                message = 'Exceeded maximum pcap size. {0} > {1}'.format(byte_count, self.max_pcap_size)
                return action_result.set_status(phantom.APP_ERROR, message)
            if byte_count == -1:
                message = 'Unable to parse byte count from response'
                return action_result.set_status(phantom.APP_ERROR, message)

        self.save_progress('Creating datamine')

        # Create datamine ######
        dm_parameters = {}

        for link in flow_resp.get('results', {}).get('total', {}).get('links', []):
            for field in link.get('fields', []):
                try:
                    dm_parameters[field['name']] = field['value']
                except:
                    message = 'Error parsing flow search links'
                    return action_result.set_status(phantom.APP_ERROR, message)

        # make rest call
        dm_ret_val, dm_resp = self._make_rest_call('datamines', action_result, params=dm_parameters, method='post')

        if phantom.is_fail(dm_ret_val):
            # the call to Endace failed, action result should contain all the error details.
            return action_result.get_status()

        all_response['create_datamine'] = dm_resp
        action_result.add_data(all_response)

        # Add datamine information into the summary, if it exists
        if 'results' in dm_resp and dm_resp['results']:
            summary['pcap_id'] = dm_resp['results'][0].get('datamineID', '')

        if 'messages' in dm_resp and dm_resp['messages']:
            summary['message_type'] = dm_resp['messages'][0].get('type', '')

        message = dm_resp.get('messages', [{}])[0].get('description', 'Missing message description.')

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def handle_action(self, param):
        """ Phantom action handler for Endace.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult:
                * str: status success/failure
                * str: message
        """

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print('action_id', self.get_action_identifier())

        supported_actions = {
            'test_connectivity': self._handle_test_connectivity,
            'get_pcap': self._handle_get_pcap,
            'delete_pcap': self._handle_delete_pcap,
            'get_status': self._handle_get_status,
            'run_query': self._handle_run_query
        }
        try:
            ret_val = supported_actions[action_id](param)
        except:
            raise ValueError('Action {0} is not supported'.format(action_id))

        return ret_val

    def _validate_rfc3339(self, date_time):
        """ Validate timestamps are in a valid RFC 3339 format.

        See RFC for more information: https://www.ietf.org/rfc/rfc3339.txt

        Args:
            date_time (str): String to validate if it meets RFC 3339 formatting requirements

        Returns:
            bool: True if correct, False otherwise
        """

        date = r'(\d{4})-(0[1-9]|1[012])-(0[1-9]|[12]\d|3[01])'
        time = r'([01]\d|2[0-3]):([0-5]\d):([0-5]\d|60)(\.\d+)?'
        offset = r'([Zz]|[+-]([01]\d|2[0-3]):[0-5]\d)'
        rfc3339 = r'^{0}[Tt]{1}{2}$'.format(date, time, offset)

        return bool(re.match(rfc3339, date_time))

    def _validate_uuid(self, uuid):
        """ Validate UUID.

        Args:
            uuid (str): String to validate if it is a UUID

        Returns:
            bool: True if correct, False otherwise
        """

        regex_uuid = r'^[a-z\d]{8}(-[a-z\d]{4}){3}-[a-z\d]{12}$'

        return bool(re.match(regex_uuid, uuid.lower()))

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        config = self.get_config()

        self.server = config['server']
        self.verify_cert = config.get('verify_cert', False)
        self.username = config['username']
        self.password = config['password']
        max_pcap_size = config['max_pcap_size']
        ret_val, self.max_pcap_size = self._validate_integer(self, max_pcap_size, MAX_PCAP_SIZE_KEY, allow_zero=True)
        if phantom.is_fail(ret_val):
            return self.get_status()

        self._base_url = 'https://{}/api/v5/'.format(self.server)

        self.set_validator('rfc3339', self._validate_rfc3339)
        self.set_validator('pcap id', self._validate_uuid)

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

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass('Password: ')

    if username and password:
        try:
            login_url = EndaceConnector._get_phantom_base_url() + '/login'

            print('Accessing the Login page')
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print('Logging into Platform to get the session id')
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print(('Unable to get session id from the platfrom. Error: ' + str(e)))
            exit(1)

    if len(sys.argv) < 2:
        print('No test json specified as input')
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print((json.dumps(in_json, indent=4)))

        connector = EndaceConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print((json.dumps(json.loads(ret_val), indent=4)))

    exit(0)
