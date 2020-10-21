# File: taniumthreatresponse_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

import requests
import tempfile
import datetime
import json
import uuid
import os
from bs4 import BeautifulSoup
from bs4 import UnicodeDammit


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TaniumThreatResponseConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TaniumThreatResponseConnector, self).__init__()

        self._state = dict()

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._session_key = None

    def _process_empty_response(self, response, action_result):

        if int(response.status_code) >= 200 and int(response.status_code) <= 299:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, 'Status code {}: Empty response and no information in the header'.format(response.status_code)), None)

    def _process_content_response(self, response, action_result):
        """ Process plain content from an API call. Can be used for downloading files.

        Args:
            response (Response): response from API request
            action_result (ActionResult): object of ActionResult class

        Returns:
            RetVal:
                * ActionResult: status success/failure
                * Response or None:
        """

        if 200 <= response.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, response)

        message = 'Error from server. Status code: {0}'.format(response.status_code)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Remove the script and style from the HTML message
            for element in soup(["script", "style"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = 'Cannot parse error details'

        message = 'Status Code: {0}. Data from server:\n{1}\n'.format(status_code, UnicodeDammit(error_text).unicode_markup.encode('utf-8'))

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

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
                r.status_code, UnicodeDammit(r.text.replace('{', '{{').replace('}', '}}')).unicode_markup.encode('UTF-8'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # If it is a file download, process before getting getting debug data due tyo
        if 'octet' in r.headers.get('Content-Type', ''):
            return self._process_content_response(r, action_result)

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not a content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        if r.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, r.text)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, UnicodeDammit(r.text.replace('{', '{{').replace('}', '}}')).unicode_markup.encode('UTF-8'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_token(self, action_result, from_action=False):
        """ This function is used to get a token via REST Call.

        :param action_result: Object of action result
        :param from_action: Boolean object of from_action
        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        config = self.get_config()
        username = UnicodeDammit(config.get('username')).unicode_markup.encode('utf-8')
        auth = (username, config.get('password'))
        headers = {
            'Content-Type': 'application/json'
        }

        ret_val, resp_json = self._make_rest_call("{}{}".format(self._base_url, "/auth"), action_result, verify=self._verify, headers=headers, auth=auth, method='post')

        if (phantom.is_fail(ret_val)):
            self._state['session_key'] = None
            self._session_key = None
            self.save_state(self._state)
            return action_result.get_status()

        self._state['session_key'] = resp_json
        self._session_key = resp_json
        self.save_state(self._state)

        return phantom.APP_SUCCESS

    def _make_rest_call_helper(self, endpoint, action_result, headers=None, params=None, data=None, json=None, method="get"):
        """ Function that helps setting REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        try:
            url = "{0}{1}".format(self._base_url, endpoint)
        except Exception as e:
            if e.message:
                try:
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                except:
                    error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."
            else:
                error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."
            return action_result.set_status(phantom.APP_ERROR, "Please check the asset configuration and action parameters. Error: {0}".format(error_msg))

        if headers is None:
            headers = {}

        if not self._session_key:
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        headers.update({'session': str(self._session_key)})
        if 'Content-Type' not in headers.keys():
            headers.update({'Content-Type': 'application/json'})

        ret_val, resp_json = self._make_rest_call(url, action_result, verify=self._verify, headers=headers, params=params, data=data, json=json, method=method)

        # If token is expired, generate a new token
        msg = action_result.get_message()

        if msg and ("HTTP 401: Unauthorized" in msg or "403" in msg):
            ret_val = self._get_token(action_result)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None
            headers.update({'session': str(self._session_key)})
            if 'Content-Type' not in headers.keys():
                headers.update({'Content-Type': 'application/json'})

            ret_val, resp_json = self._make_rest_call(url, action_result, verify=self._verify, headers=headers, params=params, data=data, json=json, method=method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _make_rest_call(self, endpoint, action_result, verify=True, headers=None, params=None, data=None, json=None, auth=None, method="get"):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param json: JSON object
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            r = request_func(endpoint, json=json, data=data, headers=headers, verify=verify, auth=auth, params=params)
        except Exception as e:
            if e.message:
                try:
                    error_msg = UnicodeDammit(e.message).unicode_markup.encode('utf-8')
                except:
                    error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."
            else:
                error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(error_msg)), resp_json)

        return self._process_response(r, action_result)

    def _get_filename_from_tanium(self, action_result, file_id):

        filename = None

        endpoint = '/plugin/products/trace/filedownloads'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('List Files Failed')
            return RetVal(action_result.get_status(), None)

        for f in response:
            if f.get('id') == int(file_id):
                filename = f.get('path', '').split('\\')[-1]
                break

        return RetVal(phantom.APP_SUCCESS, filename)

    def _save_temp_file(self, content):
        """

        Args:
            content:

        Returns:

        """

        if hasattr(Vault, 'get_vault_tmp_dir'):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = '/opt/phantom/vault/tmp'

        temp_dir = temp_dir + '/{}'.format(uuid.uuid4())
        os.makedirs(temp_dir)

        file_obj = tempfile.NamedTemporaryFile(prefix='taniumthreatresponse_',
                                               dir=temp_dir,
                                               delete=False)
        file_obj.close()

        with open(file_obj.name, 'wb') as f:
            f.write(content)

        return file_obj.name

    def _list_connections(self, action_result):
        """ Return a list of current connections.

        Args:
            action_result (ActionResult): object of ActionResult class

        Returns:
            RetVal:
                bool: Success/ Failure
                list: Current connections in Tanium Threat Response

        """

        endpoint = '/plugin/products/trace/conns'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if message:
                message = UnicodeDammit(message).unicode_markup.encode('utf-8')
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Unable to list connections{}'.format('. Error message: {}'.format(message) if message else "")), None)

        return RetVal(phantom.APP_SUCCESS, response)

    def _is_connection_active(self, action_result, conn_id):
        """ Check to see if connection exists and is active.

        Args:
            action_result (ActionResult): object of ActionResult class
            conn_id (str): Connection ID to check if it is active

        Returns:
            bool: Success/ Failure
        """

        ret_val, response = self._list_connections(action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for connection in response:
            if conn_id == connection.get('name', ''):
                state = connection.get('info', {}).get('state', '')
                if state == 'active':
                    return phantom.APP_SUCCESS
                elif not state:
                    message = 'Connection not active. Error occurred while fetching the state of the connection'
                    return action_result.set_status(phantom.APP_ERROR, message)
                else:
                    message = 'Connection not active. Current state: {}'.format(state)
                    return action_result.set_status(phantom.APP_ERROR, message)

        message = 'Could not find connection'
        return action_result.set_status(phantom.APP_ERROR, message)

    def _handle_test_connectivity(self, param):
        """ Test connectivity by listing the current connections

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._get_token(action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Test Connectivity Failed')
            return action_result.get_status()

        ret_val, response = self._make_rest_call_helper('/plugin/products/trace/status', action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Test Connectivity Failed')
            return action_result.get_status()

        self.save_progress(response)
        self.save_progress('Test Connectivity Passed')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_computers(self, param):
        """ Get a list of computers that match name passed in param.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # name is a required parameter, but it can be blank.
        params = {'name': param.get('name', '')}
        endpoint = '/plugin/products/trace/computers/'

        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=params)
        if phantom.is_fail(ret_val):
            self.save_progress('List Computers Failed')
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, 'No results found')

        summary = action_result.update_summary({})
        summary['total_results'] = len(response)

        for r in response:
            action_result.add_data({'name': r})

        self.save_progress('List computers successful')
        message = 'Retrieved list of computers'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_initialize_computers_list(self, param):
        """ Initialize the endpoints

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = '/plugin/products/trace/computers/initialize'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Initialize computers failed')
            return action_result.get_status()

        self.save_progress('Initialize computers successful')
        message = 'Requested an initialize computer action'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_list_connections(self, param):
        """ List the current connections

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._list_connections(action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('List connections failed')
            return action_result.get_status()

        summary = action_result.update_summary({})
        summary['total_connections'] = len(response)
        for state in [x['info']['state'] for x in response if 'state' in x['info']]:
            summary[state + '_connections'] = len([x for x in response if 'state' in x['info'] and x['info']['state'] == state])

        for r in response:
            action_result.add_data(r)

        self.save_progress('List connections successful')
        message = 'Number of active connections found: {}'.format(summary.get('active_connections'))
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_create_connection(self, param):
        """ Create connection with an endpoint.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        conntimeout = param.get('conntimeout')

        if conntimeout:
            try:
                conntimeout = int(conntimeout)
                if conntimeout <= 0:
                    raise ValueError
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a non-zero positive integer in conntimeout parameter')
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a non-zero positive integer in conntimeout parameter. Error: {0}'.format(e.message))

        data = {'dst': param.get('dst'),
                'dstType': param.get('dsttype'),
                'remote': param.get('remote')}

        if conntimeout:
            data.update({'connTimeout': conntimeout})

        endpoint = '/plugin/products/trace/conns'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, json=data, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Create connection failed')
            return action_result.get_status()

        self.save_progress('Create connection successful')
        message = 'Create connection requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_connection(self, param):
        """ Get connection information.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = UnicodeDammit(param.get('connection_id')).unicode_markup.encode('utf-8')

        endpoint = '/plugin/products/trace/conns/{}'.format(cid)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Get connection failed')
            return action_result.get_status()

        action_result.add_data(response)

        self.save_progress('Get connection successful')
        message = 'Connection information found'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_delete_connection(self, param):
        """ Deletes specified connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = UnicodeDammit(param.get('connection_id')).unicode_markup.encode('utf-8')

        endpoint = '/plugin/products/trace/conns/{}'.format(cid)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, method='delete')

        if phantom.is_fail(ret_val):
            self.save_progress('Delete connection failed')
            return action_result.get_status()

        self.save_progress('Delete connection successful')
        message = 'Delete connection requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_list_snapshots(self, param):
        """ List existing snapshots.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = '/plugin/products/trace/locals'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('List snapshots failed')
            return action_result.get_status()

        for host, names in response.iteritems():
            for name in names:
                each_snapshot = dict()
                each_snapshot['host'] = host
                each_snapshot['name'] = name
                action_result.add_data(each_snapshot)

        summary = action_result.update_summary({})
        summary['total_snapshots'] = action_result.get_data_size()

        self.save_progress('List snapshots successful')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_snapshot(self, param):
        """ Create new snapshot. Requires a connection to already be setup.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = UnicodeDammit(param['connection_id']).unicode_markup.encode('utf-8')

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        endpoint = '/plugin/products/trace/conns/{}/snapshots'.format(cid)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Create snapshot failed')
            return action_result.get_status()

        self.save_progress('Create snapshot successful')
        message = 'Create snapshot requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_delete_snapshot(self, param):
        """ Delete existing snapshot.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        host = UnicodeDammit(param['host']).unicode_markup.encode('utf-8')
        filename = UnicodeDammit(param['filename']).unicode_markup.encode('utf-8')

        endpoint = '/plugin/products/trace/locals/{}/{}'.format(host, filename)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, method='delete')

        if phantom.is_fail(ret_val):
            self.save_progress('Delete snapshot failed')
            return action_result.get_status()

        self.save_progress('Delete snapshot successful')
        message = 'Delete snapshot requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_list_local_snapshots(self, param):
        """ List all of the local snapshots and their file sizes.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = '/plugin/products/trace/snapshots'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('List local snapshots failed')
            return action_result.get_status()

        for name, entry in response.iteritems():
            for key, value in entry.iteritems():
                each_snapshot = dict()
                each_snapshot.update(value)
                each_snapshot['snapshot'] = key
                each_snapshot['connection_id'] = name
                action_result.add_data(each_snapshot)

        summary = action_result.update_summary({})
        summary['total_snapshots'] = action_result.get_data_size()

        self.save_progress('List local snapshots successful')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_local_snapshot(self, param):
        """ Download a local snapshot to the Vault.

        TODO: Action is DISABLED until "upload local snapshot" can work.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        directory = UnicodeDammit(param['directory'].strip()).unicode_markup.encode('utf-8')
        filename = UnicodeDammit(param['filename'].strip()).unicode_markup.encode('utf-8')
        endpoint = '/plugin/products/trace/locals/{}/{}'.format(directory, filename)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Get local snapshot failed')
            return action_result.get_status()

        metadata = {
            'size': len(response.content),
            'contains': ['threatresponse snapshot'],
            'action': self.get_action_name(),
            'app_run_id': self.get_app_run_id()
        }

        file_name = '{}_{}'.format(directory, filename)

        # Save file
        self.send_progress('Saving file to disk.')
        try:
            temp_name = self._save_temp_file(response.content)
        except Exception as e:
            self.debug_print('Error creating file.')
            return action_result.set_status(phantom.APP_ERROR, 'Error creating file. {}'.format(e))

        vault = Vault.add_attachment(temp_name, self.get_container_id(), file_name=file_name, metadata=metadata)
        if filename:
            vault['file_name'] = file_name

        action_result.add_data(vault)

        self.save_progress('Get local snapshot successful')
        message = 'Downloaded snapshot to vault'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_upload_local_snapshot(self, param):
        """ Upload local snapshot.

        TODO: DISABLED until we can get the API to work

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_id = param['vault_id']
        file_path = Vault.get_file_path(vault_id)
        data = open(file_path, 'rb').read()

        endpoint = '/plugin/products/trace/locals'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, data=data, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Upload local snapshot failed')
            return action_result.get_status()

        self.save_progress('Upload local snapshot successful')
        message = 'Uploaded snapshot from vault'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_delete_local_snapshot(self, param):
        """ Delete a local snapshot.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = UnicodeDammit(param.get('connection_id')).unicode_markup.encode('utf-8')
        db = UnicodeDammit(param.get('snapshot')).unicode_markup.encode('utf-8')

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        endpoint = '/plugin/products/trace/conns/{}/snapshots/{}'.format(cid, db)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, method='delete')

        if phantom.is_fail(ret_val):
            self.save_progress('Delete local snapshot failed')
            return action_result.get_status()

        self.save_progress('Delete local snapshot successful')
        message = 'Delete local snapshot requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_process(self, param):
        """ Get process information from an existing connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = UnicodeDammit(param['connection_id']).unicode_markup.encode('utf-8')

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        endpoint = '/plugin/products/trace/conns/{connection_id}/processes/{process_table_id}'.format(**param)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Get process failed')
            return action_result.get_status()

        action_result.add_data(response)

        self.save_progress('Get process successful')
        message = 'Process information retrieved'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_process_timeline(self, param):
        """ Get process timeline from an existing connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = UnicodeDammit(param['connection_id']).unicode_markup.encode('utf-8')

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        endpoint = '/plugin/products/trace/conns/{connection_id}/eprocesstimelines/{process_table_id}'.format(**param)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Get Process Timeline Failed')
            return action_result.get_status()

        # Process response
        out = []
        for event_type in response:
            for date, l in event_type.get('details', {}).iteritems():
                for event in l:
                    out.append({
                        'type': event_type.get('name'),
                        'date': date,
                        'isodate': datetime.datetime.utcfromtimestamp(int(date) / 1000).isoformat() + 'Z',
                        'event': event
                    })

        # Sort and add to action result
        sorted_out = sorted(out, key=lambda x: x['date'])
        for each_out in sorted_out:
            action_result.add_data(each_out)

        self.save_progress('Get Process Timeline Successful')
        message = 'Process timeline retrieved'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_process_tree(self, param):
        """ Get process tree for a process from an existing connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = UnicodeDammit(param['connection_id']).unicode_markup.encode('utf-8')

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        endpoint = '/plugin/products/trace/conns/{connection_id}/processtrees/{process_table_id}'.format(**param)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Get process tree Failed')
            return action_result.get_status()

        if response:
            action_result.add_data(response[0])
        else:
            return action_result.set_status(phantom.APP_SUCCESS, 'No process tree found')

        self.save_progress('Get process tree Successful')
        message = 'Process tree retrieved'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_parent_process_tree(self, param):
        """ Get parent process tree for a process from an existing connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = UnicodeDammit(param['connection_id']).unicode_markup.encode('utf-8')

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        endpoint = '/plugin/products/trace/conns/{connection_id}/parentprocesstrees/{process_table_id}'.format(**param)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Get parent process tree Failed')
            return action_result.get_status()

        if response:
            action_result.add_data(response[0])
        else:
            return action_result.set_status(phantom.APP_SUCCESS, 'No parent process tree found')

        self.save_progress('Get Parent process tree Successful')
        message = 'Parent process tree retrieved'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_children_process_tree(self, param):
        """ Get children process tree for a process from an existing connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = UnicodeDammit(param['connection_id']).unicode_markup.encode('utf-8')

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        endpoint = '/plugin/products/trace/conns/{connection_id}/processtrees/{process_table_id}/children'.format(**param)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Get children process tree Failed')
            return action_result.get_status()

        if response:
            action_result.add_data(response[0])
        else:
            return action_result.set_status(phantom.APP_SUCCESS, 'No children process tree found')

        self.save_progress('Get children process tree Successful')
        return action_result.set_status(phantom.APP_SUCCESS, 'Children process tree retrieved')

    def _handle_get_events(self, param):
        """ Return events and number of events of a certain type where the value exists in one or more
        of the queried fields from an existing connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get('limit')
        offset = param.get('offset')
        sort = param.get('sort')
        fields = param.get('fields')
        operators = param.get('operators')
        value = param.get('value')
        cid = UnicodeDammit(param['connection_id']).unicode_markup.encode('utf-8')

        if limit or limit == 0:
            try:
                limit = int(limit)
                if limit <= 0:
                    raise ValueError
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a positive non-zero integer in limit parameter')
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a positive non-zero integer in limit parameter. Error: {0}'.format(e.message))

        if offset:
            try:
                offset = int(offset)
                if offset < 0:
                    raise ValueError
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a positive integer in offset parameter')
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide a positive integer in offset parameter. Error: {0}'.format(e.message))

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        params = {}

        if fields or value or operators:
            if not (fields and value and operators):
                return action_result.set_status(phantom.APP_ERROR, 'fields, operators, and value need to be filled in to query events. Returning all results')
            else:

                filter_type = param.get("filter_type", "all")

                fields = [field.strip() for field in fields.split(',')]
                fields = list(filter(None, fields))

                value = [val.strip() for val in value.split(',')]
                value = list(filter(None, value))

                operators = [operator.strip() for operator in operators.split(',')]
                operators = list(filter(None, operators))

                if not (len(fields) == len(value) and len(value) == len(operators)):
                    return action_result.set_status(phantom.APP_ERROR, "Length of value, fields , and operators must be equal")

                group_list = []

                for i, _filter in enumerate(fields):
                    params["f{}".format(str(i))] = fields[i]
                    params["o{}".format(str(i))] = operators[i]
                    params["v{}".format(str(i))] = value[i]
                    group_list.append(str(i))

                params["gm1"] = filter_type
                params["g1"] = ",".join(group_list)

        endpoint = '/plugin/products/trace/conns/{connection_id}/{event_type}/eventsCount'.format(**param)

        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=params)

        if phantom.is_fail(ret_val):
            self.save_progress('Get Events Count Failed')
            return action_result.get_status()

        action_result.update_summary({'event_count': response})

        if limit:
            params['limit'] = limit
        if offset:
            params['offset'] = offset
        if sort:
            params['sort'] = sort

        endpoint = '/plugin/products/trace/conns/{connection_id}/{event_type}/events'.format(**param)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=params)

        if phantom.is_fail(ret_val):
            self.save_progress('Get Events Failed')
            return action_result.get_status()

        for event in response:
            action_result.add_data(event)
        action_result.update_summary({'type': param.get('event_type')})

        self.save_progress('Get Events Successful')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_events_summary(self, param):
        """ Return counts of event types and operations from an existing connection.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = UnicodeDammit(param['connection_id']).unicode_markup.encode('utf-8')

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        endpoint = '/plugin/products/trace/conns/{connection_id}/eventcounts'.format(**param)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Events Summary Failed')
            return action_result.get_status()

        if not response:
            response = []

        for r in response:
            action_result.add_data(r)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total_categories'] = len(set([r['category'] for r in response]))
        summary['total_events_operations'] = len(response)
        summary['total_events_count'] = sum([int(r['count']) for r in response])

        self.save_progress('Events Summary Successful')
        message = 'Number of categories found: {}'.format(summary.get('total_categories'))
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_list_files(self, param):
        """ Return list of saved files and number of files.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = '/plugin/products/trace/filedownloads'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('List Files Failed')
            return action_result.get_status()

        if not response:
            return action_result.set_status(phantom.APP_SUCCESS, 'No results found')

        for r in response:
            action_result.add_data(r)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['file_count'] = len(response)

        self.save_progress('List Files Successful')
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_save_file(self, param):
        """ Save file from remote computer to Tanium Threat Response.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        cid = UnicodeDammit(param['connection_id']).unicode_markup.encode('utf-8')

        if not self._is_connection_active(action_result, cid):
            self.save_progress('Inactive or non-existent connection')
            return action_result.get_status()

        data = {
            'connId': cid,
            'path': UnicodeDammit(param.get('file_path')).unicode_markup.encode('utf-8')
        }

        endpoint = '/plugin/products/trace/filedownloads'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, json=data, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Save File Failed')
            return action_result.get_status()

        self.save_progress('Save File Successful')
        message = 'Save file requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_delete_file(self, param):
        """ Delete a downloaded file from Tanium Threat Response.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        file_id = param["file_id"]
        if file_id is not None:
            try:
                file_id = int(file_id)
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide an integer in file_id parameter')
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide an integer in file_id parameter. Error: {0}'.format(e.message))
        endpoint = '/plugin/products/trace/filedownloads/{file_id}'.format(file_id=file_id)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, method='delete')

        if phantom.is_fail(ret_val):
            self.save_progress('Delete File Failed')
            return action_result.get_status()

        self.save_progress('Delete File Successful')
        message = 'Delete file requested'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_get_file(self, param):
        """ Download a file from Tanium Threat Response to the Phantom Vault.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """

        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        file_id = param["file_id"]
        if file_id is not None:
            try:
                file_id = int(file_id)
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide an integer in file_id parameter')
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, 'Please provide an integer in file_id parameter. Error: {0}'.format(e.message))
        endpoint = '/plugin/products/trace/filedownloads/{file_id}'.format(file_id=file_id)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress('Get File Failed')
            return action_result.get_status()

        metadata = {
            'size': len(response.content),
            'contains': [],
            'action': self.get_action_name(),
            'app_run_id': self.get_app_run_id()
        }

        # Get file name from Tanium, if it exists
        ret_val, filename = self._get_filename_from_tanium(action_result, param['file_id'])

        # Save file
        self.send_progress('Saving file to disk.')
        try:
            temp_name = self._save_temp_file(response.content)
        except Exception as e:
            self.debug_print('Error creating file.')
            return action_result.set_status(phantom.APP_ERROR, 'Error creating file. {}'.format(e))

        if phantom.is_fail(ret_val) or not filename:
            filename = temp_name.split('/')[-1]

        vault = Vault.add_attachment(temp_name, self.get_container_id(), file_name=filename, metadata=metadata)
        if filename:
            vault['file_name'] = filename

        action_result.add_data(vault)

        self.save_progress('Get File Successful')
        message = 'File downloaded to vault'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_upload_intel_doc(self, param):
        """ Upload intel document to Tanium Threat Response.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ''' future TODO: file ingestion
        vault_id = param['vault_id']
        file_path = Vault.get_file_path(vault_id)
        data = open(file_path, 'rb').read()
        '''

        headers = {
            'Content-Type': 'application/xml'
        }

        data = param['intel_doc']

        endpoint = '/plugin/products/detect3/api/v1/intels'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, headers=headers, data=data, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Upload intel document failed')
            return action_result.get_status()

        action_result.add_data(response)

        self.save_progress('Upload intel document successful')
        message = 'Uploaded intel document to Tanium Threat Response'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_start_quick_scan(self, param):
        """ Scan a computer group for hashes in intel document.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        computer_group_name = param['computer_group_name']
        endpoint = "{}/{}".format("/api/v2/groups/by-name", computer_group_name)
        ret_val, response = self._make_rest_call_helper(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        response_data = response.get("data")

        if not response_data:
            error_message = "No group exists with name {}. Also, please verify that your account has sufficient permissions to access the groups".format(computer_group_name)
            return action_result.set_status(phantom.APP_ERROR, error_message)

        computer_group_id = response_data.get("id")

        data = {
            'intelDocId': param['intel_doc_id'],
            'computerGroupId': computer_group_id
        }

        endpoint = '/plugin/products/detect3/api/v1/quick-scans'
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, json=data, method='post')

        if phantom.is_fail(ret_val):
            self.save_progress('Start quick scan failed')
            return action_result.get_status()

        action_result.add_data(response)

        self.save_progress('Start quick scan successful')
        message = 'Started quick scan successfully'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_list_alerts(self, param):
        """ List alerts with optional filtering.

        Args:
            param (dict): Parameters sent in by a user or playbook

        Returns:
            ActionResult status: success/failure
        """
        self.save_progress('In action handler for: {0}'.format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = '/plugin/products/detect3/api/v1/alerts'
        params = {
            'limit': param['limit']
        }
        for p in param['query'].split('&'):
            k = p.split('=')[0]
            k = UnicodeDammit(k).unicode_markup.encode('utf-8')
            v = p.split('=')[1]
            try:
                params[k] = int(v)
            except ValueError:
                params[k] = v
        ret_val, response = self._make_rest_call_helper(endpoint, action_result, params=params)

        if phantom.is_fail(ret_val):
            self.save_progress('List alerts failed')
            return action_result.get_status()

        for alert in response:
            details = json.loads(alert['details'])
            alert['path'] = details['match']['properties']['fullpath']
            alert['event_type'] = details['match']['type']
            alert['md5'] = details['match']['properties']['md5']
            action_result.add_data(alert)

        action_result.update_summary({'total_alerts': len(response)})

        self.save_progress('List alerts successful')
        message = 'Listed alerts successfully'
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def handle_action(self, param):

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print('action_id', action_id)

        # Dictionary mapping each action with its corresponding actions
        supported_actions = {
            'test_connectivity': self._handle_test_connectivity,
            'list_computers': self._handle_list_computers,
            'initialize_computers_list': self._handle_initialize_computers_list,
            'list_connections': self._handle_list_connections,
            'create_connection': self._handle_create_connection,
            'get_connection': self._handle_get_connection,
            'delete_connection': self._handle_delete_connection,
            'list_snapshots': self._handle_list_snapshots,
            'create_snapshot': self._handle_create_snapshot,
            'delete_snapshot': self._handle_delete_snapshot,
            'list_local_snapshots': self._handle_list_local_snapshots,
            # Unable to get 'upload_local_snapshot' work with the API, disabling for now
            # 'get_local_snapshot': self._handle_get_local_snapshot,
            # 'upload_local_snapshot': self._handle_upload_local_snapshot,
            'delete_local_snapshot': self._handle_delete_local_snapshot,
            'get_process': self._handle_get_process,
            'get_process_timeline': self._handle_get_process_timeline,
            'get_process_tree': self._handle_get_process_tree,
            'get_parent_process_tree': self._handle_get_parent_process_tree,
            'get_children_process_tree': self._handle_get_children_process_tree,
            'get_events': self._handle_get_events,
            'get_events_summary': self._handle_get_events_summary,
            'list_files': self._handle_list_files,
            'save_file': self._handle_save_file,
            'delete_file': self._handle_delete_file,
            'get_file': self._handle_get_file,
            'upload_intel_doc': self._handle_upload_intel_doc,
            'start_quick_scan': self._handle_start_quick_scan,
            'list_alerts': self._handle_list_alerts
        }

        if action_id in supported_actions:
            return supported_actions[action_id](param)
        else:
            return phantom.APP_ERROR
            # raise ValueError('Action {0} is not supported'.format(action_id))

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = UnicodeDammit(config.get('base_url')).unicode_markup.encode('utf-8')

        # removing single occurence of trailing back-slash or forward-slash
        if self._base_url.endswith('/'):
            self._base_url = self._base_url.strip('/').strip('\\')
        elif self._base_url.endswith('\\'):
            self._base_url = self._base_url.strip('\\').strip('/')

        # removing single occurence of leading back-slash or forward-slash
        if self._base_url.startswith('/'):
            self._base_url = self._base_url.strip('/').strip('\\')
        elif self._base_url.startswith('\\'):
            self._base_url = self._base_url.strip('\\').strip('/')

        self._session_key = self._state.get('session_key', '')
        self._verify = config['verify_server_cert']

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
        password = getpass.getpass('Password: ')

    if (username and password):
        try:
            login_url = '{}/login'.format(BaseConnector.get_phantom_base_url())
            print ('Accessing the Login page')
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print ('Logging into Platform to get the session id')
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ('Unable to get session id from the platform. Error: ' + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TaniumThreatResponseConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
