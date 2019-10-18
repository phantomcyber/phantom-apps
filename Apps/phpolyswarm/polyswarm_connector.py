# File: polyswarm_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

from polyswarm_consts import *

import os
import time
import requests
import json
import logging
import uuid

# Set Debug level
# logging.basicConfig(level=logging.DEBUG)


class Polyswarm_API:

    def __init__(self, config):
        """
        __init__
        :param config: config with api key for connection

        :return:
        """
        self.config = config
        self.headers = {'Authorization': self.config['polyswarm_api_key']}

    def _http_request(self, method, path_url, data=None, files=None):
        """
        Send HTTP Request

        :param method: [get|post]
        :param path_url: URL for request
        :param data: data for 'post' or 'get' request
        :param files: for uploading files with 'post'

        :return: tuple (status_code, content)
        """
        r = None

        # set full URL for request
        try:
            full_url = '{base_url}{path_url}'.format(base_url=self.config['base_url'],
                                                    path_url=path_url)
        except:
            self.debug_print('Error occurred while making HTTP Request. {0}'.format(POLYSWARM_CONFIG_PARAMS_ERR_MSG))
            return phantom.APP_ERROR, None

        logging.info('[{method}] URL: {full_url} - params/data: {data} - files: {files} - headers: {headers}'.
                       format(method=method.upper(),
                              full_url=full_url,
                              data=data,
                              files=files,
                              headers=self.headers))

        if method.lower() == "get":
            r = requests.get(full_url,
                             params=data,
                             headers=self.headers)
        elif method.lower() == "post":
            r = requests.post(full_url,
                              data=data,
                              files=files,
                              headers=self.headers)
        r.raise_for_status()

        logging.info('[Response] Status code: {status_code} - Content: {response}'.
                       format(status_code=r.status_code,
                              response=r.content))

        return (r.status_code, r.content)

    def _get_hash_type(self, hash):
        """
        Return Hash Type

        :param hash: hash string

        :return: hash type string; empty if failed
        """
        if len(hash) == 40:
            return 'sha1'
        elif len(hash) == 64:
            return 'sha256'
        elif len(hash) == 32:
            return 'md5'

        return ''

    def search_hash(self, hash):
        """
        Search Hash

        :param hash: hash

        :return: tuple (status_code, response)
        """
        hash_type = self._get_hash_type(hash)

        params = {'type': hash_type,
                  'with_instances': 'true',
                  'hash': hash}

        return self._http_request('get', '/search', params)

    def scan_url(self, url):
        """
        Upload URL for scan

        :param url: string

        :return: tuple (status_code, response)
        """
        path_url = '/consumer/{polyswarm_community}'.format(polyswarm_community=self.config['polyswarm_community'])

        params = {'url': url,
                  'artifact-type': 'url'}

        return self._http_request('post', path_url, params)

    def lookup(self, uuid):
        """
        UUID Lookup

        :param uuid: string

        :return: tuple (status_code, response)
        """
        path_url = '/consumer/{polyswarm_community}/uuid/{uuid}'.format(polyswarm_community=self.config['polyswarm_community'],
                                                                   uuid=uuid)

        status_code, response = self._http_request('get', path_url)
        window_closed = json.loads(response)['result']['files'][0]['window_closed']

        # we got the results at first shot
        if window_closed:
            return (status_code, response)

        # we dont have any results already - wait for the bounty to complete
        # and try again
        time.sleep(30)

        while not window_closed:
            status_code, response = self._http_request('get', path_url)
            window_closed = json.loads(response)['result']['files'][0]['window_closed']
            time.sleep(1)

        return (status_code, response)

    def search_url(self, url):
        """
        Scan URL and return scan results

        :param url: string

        :return: (status_code, response, uuid)
        """
        status_code, response = self.scan_url(url)
        uuid = json.loads(response)['result']
        status_code, response = self.lookup(uuid)

        return (status_code, response, uuid)

    def get_file(self, hash):
        """
        Download file by hash

        :param hash: File Hash for Download

        :return: tuple (status_code, response)
        """
        hash_type = self._get_hash_type(hash)

        logging.info('[get_file] Hash type: {hash_type}'.
                       format(hash_type=hash_type))

        return self._http_request('get', '/download/{hash_type}/{hash}'.
                                  format(hash_type=hash_type, hash=hash))

    def detonate_file(self, file_name, file_path):
        """
        Upload File to Polyswarm and get the scan results

        :param file_name: file name
        :param file_path: complete path from the file to upload

        :return: (status_code, response, uuid)
        """
        path_url = '/consumer/{polyswarm_community}'.format(polyswarm_community=self.config['polyswarm_community'])

        files = { 'file': (file_name, open(file_path, 'rb')) }
        # Force re-scans if file was already submitted
        # params = { 'force': 'true' }
        params = {}

        status_code, response = self._http_request('post', path_url, params, files)
        uuid = json.loads(response)['result']
        status_code, response = self.lookup(uuid)

        return (status_code, response, uuid)


class PolyswarmConnector(BaseConnector):

    def __init__(self, cli=False):
        # Call the BaseConnectors init first
        super(PolyswarmConnector, self).__init__()

        self.polyswarm_api = None
        self._state = None
        self._base_url = None
        # variable to get aware we are called from cmd
        self.cli = cli

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # setup polyswarm_api object
        self.polyswarm_api = Polyswarm_API(config)

        # Access action parameters passed in the 'param' dictionary
        try:
            self.save_progress('Base URL is: {base_url} - Community: {polyswarm_community}'.
                            format(base_url=config['base_url'],
                                   polyswarm_community=config['polyswarm_community']))
        except:
            self.save_progress(POLYSWARM_DEBUG_ERROR_MSG)
            return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _update_results(self, action_result, total_scans, positives, uuid):
        # update result_data -> summary
        action_result.update_summary({'total_scans': str(total_scans)})
        action_result.update_summary({'scan_uuid': uuid})
        action_result.update_summary({'positives': str(positives)})

        # update result_data -> data
        data = { 'total': str(total_scans),
                 'permalink': '{url_results}/{uuid}'.
                                format(url_results=POLYSWARM_URL_RESULTS,
                                       uuid=uuid),
                 'positives': str(positives),
                 'scan_uuid': uuid }

        action_result.add_data(data)

    def _handle_test_connectivity(self, param):
        EICAR_HASH = '131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267'

        # Polywarm API Response
        #  HTTP Response
        #   status code
        #   response
        status_code = 0
        response = ''

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            status_code, response = self.polyswarm_api.search_hash(EICAR_HASH)

            if (phantom.is_fail(status_code)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # for now the return is commented out, but after implementation, return from here
                return action_result.get_status()

        except requests.exceptions.HTTPError as err:
                return action_result.\
                       set_status(phantom.APP_ERROR,
                                  'Error with endpoint: {err}'.
                                  format(err=err))

        self.save_progress("Connection successful")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_file_reputation(self, param):
        self.save_progress('In action handler for: {0}'.
                            format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector)
        # to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # default values
        total_scans = 0
        positives = 0

        # Polywarm API Response
        #  HTTP Response
        #   status code
        #   response
        #   uuid = uuid from Polyswarm
        status_code = 0
        response = ''
        uuid = 'null'

        try:
            status_code, response = self.polyswarm_api.search_hash(param['hash'])

            if (phantom.is_fail(status_code)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # for now the return is commented out, but after implementation, return from here
                return action_result.get_status()

            # load json response for iteration
            try:
                artifact_instances = json.loads(response)['result'][0]['artifact_instances']
            except:
                return action_result.set_status(phantom.APP_ERROR,
                              'Error in response. Details: ' + (str(response)))

            uuid = artifact_instances[0]['bounty_result']['uuid']
            assertions = artifact_instances[0]['bounty_result']['files'][0]['assertions']

            for assertion in assertions:
                for k, v in assertion.items():
                    if k == 'verdict' and v:
                        positives += 1
                total_scans += 1

            self.debug_print('Positives: {positives} - Total Scans: {total_scans}'.
                              format(positives=positives, total_scans=total_scans))

        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 404:
                # sample not found
                # returning default values == 0
                pass
            else:
                # we got another err - report it
                return action_result.\
                       set_status(phantom.APP_ERROR,
                                  'Error with endpoint: {err}'.
                                  format(err=err))

        self._update_results(action_result,
                             total_scans,
                             positives,
                             uuid)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file(self, param):
        self.save_progress('In action handler for: {0}'.
                            format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Polywarm API Response
        #  HTTP Response
        #   status code
        #   response
        status_code = 0
        response = ''

        try:
            status_code, response = self.polyswarm_api.get_file(param['hash'])

            if (phantom.is_fail(status_code)):
                return action_result.get_status()

            if hasattr(Vault, 'get_vault_tmp_dir'):
                temp_dir = Vault.get_vault_tmp_dir()
            else:
                temp_dir = 'opt/phantom/vault/tmp'
            temp_dir = temp_dir + '/{}'.format(uuid.uuid4())
            os.makedirs(temp_dir)
            file_path = os.path.join(temp_dir, param['hash'])

            with open(file_path, 'wb') as f:
                f.write(response)

            if self.cli:
                container_id = 1
            else:
                container_id = self.get_container_id()

            self.debug_print('file_path: {file_path}'.format(file_path=file_path))
            self.debug_print('container_id: {container_id}'.
                             format(container_id=container_id))

            vault_response = Vault.add_attachment(file_location=file_path,
                                                  container_id=container_id,
                                                  file_name=param['hash'])
            self.debug_print(vault_response)

            if vault_response['succeeded']:
                file_info = Vault.get_file_info(file_name=param['hash'])[0]
                self.debug_print('Vault File Info: {file_info}'.
                                 format(file_info=file_info))
                action_result.update_summary(file_info)
                action_result.add_data(file_info)
                return action_result.set_status(phantom.APP_SUCCESS,
                                                'File Downloaded Successfully')
            else:
                return action_result.set_status(phantom.APP_ERROR,
                                                vault_response['message'])
        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 404:
                # sample not found
                return action_result.set_status(phantom.APP_ERROR,
                                                'File Not Found')
            else:
                # we got another err - report it
                return action_result.\
                       set_status(phantom.APP_ERROR,
                                  'Error with endpoint: {err}'.
                                  format(err=err))

    def _handle_detonate_file(self, param):
        self.save_progress('In action handler for: {0}'.
                            format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # default values
        total_scans = 0
        positives = 0

        file_info = None

        # Polywarm API Response
        #  HTTP Response
        #   status_code
        #   response
        #  Result
        #   uuid = uuid from Polyswarm
        status_code = 0
        response = ''
        uuid = ''

        vault_id = param['vault_id']

        try:
            file_info = Vault.get_file_info(vault_id=vault_id)[0]

            self.debug_print(file_info)

        except:
            if not file_info:
                return action_result.set_status(phantom.APP_ERROR,
                        'Error: File not found in Vault')

        try:
            status_code, response, uuid = self.polyswarm_api.detonate_file(file_info['name'],
                                                          file_info['path'])

            if (phantom.is_fail(status_code)):
                return action_result.get_status()

            # load json response for iteration
            try:
                assertions = json.loads(response)['result']['files'][0]['assertions']
            except:
                return action_result.set_status(phantom.APP_ERROR,
                              'Error in response. Details: ' + (str(response)))

            # iterate for getting positives and total_scan number
            for assertion in assertions:
                for k, v in assertion.items():
                    if k == 'verdict' and v:
                        positives += 1
                total_scans += 1

            self.debug_print('Positives: {positives} - Total Scans: {total_scans}'.
                              format(positives=positives, total_scans=total_scans))

        except requests.exceptions.HTTPError as err:
            # we got another err - report it
            return action_result.\
                   set_status(phantom.APP_ERROR,
                              'Error with endpoint: {err}'.
                              format(err=err))

        self._update_results(action_result,
                             total_scans,
                             positives,
                             uuid)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_url_reputation(self, param, artifact):
        self.save_progress('In action handler for: {0}'.
                            format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # default values
        total_scans = 0
        positives = 0

        # Polywarm API Response
        #  HTTP Response
        #   status_code
        #   response
        #  Result
        #   uuid = uuid from Polyswarm
        status_code = 0
        response = ''
        uuid = ''

        try:
            status_code, response, uuid = self.polyswarm_api.search_url(param[artifact])

            if (phantom.is_fail(status_code)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # for now the return is commented out, but after implementation, return from here
                return action_result.get_status()

            # load json response for iteration
            try:
                assertions = json.loads(response)['result']['files'][0]['assertions']
            except:
                return action_result.set_status(phantom.APP_ERROR,
                              'Error in response. Details: ' + (str(response)))

            # iterate for getting positives and total_scan number
            for assertion in assertions:
                for k, v in assertion.items():
                    if k == 'verdict' and v:
                        positives += 1
                total_scans += 1

        except requests.exceptions.HTTPError as err:
            # err
            return action_result.\
                   set_status(phantom.APP_ERROR,
                              'Error with endpoint: {err}'.
                              format(err=err))

        self._update_results(action_result,
                             total_scans,
                             positives,
                             uuid)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):
        self.save_progress('In action handler for: {0}'.
                            format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # default values
        total_scans = 0
        positives = 0

        # Polywarm API Response
        #  HTTP Response
        #   status_code
        #   response
        status_code = 0
        response = ''

        try:
            status_code, response = self.polyswarm_api.lookup(param['scan_uuid'])

            if (phantom.is_fail(status_code)):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # for now the return is commented out, but after implementation, return from here
                return action_result.get_status()

            # load json response for iteration
            try:
                assertions = json.loads(response)['result']['files'][0]['assertions']
            except:
                return action_result.set_status(phantom.APP_ERROR,
                              'Error in response. Details: ' + (str(response)))

            # iterate for getting positives and total_scan number
            for assertion in assertions:
                for k, v in assertion.items():
                    if k == 'verdict' and v:
                        positives += 1
                total_scans += 1

        except requests.exceptions.HTTPError as err:
            # err
            return action_result.\
                   set_status(phantom.APP_ERROR,
                              'Error with endpoint: {err}'.
                              format(err=err))

        self._update_results(action_result,
                             total_scans,
                             positives,
                             param['scan_uuid'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print('action_id', self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'file_reputation':
            ret_val = self._handle_file_reputation(param)
        elif action_id == 'get_file':
            ret_val = self._handle_get_file(param)
        elif action_id == 'detonate_file':
            ret_val = self._handle_detonate_file(param)
        elif action_id == 'url_reputation':
            ret_val = self._handle_url_reputation(param, 'url')
        elif action_id == 'ip_reputation':
            ret_val = self._handle_url_reputation(param, 'ip')
        elif action_id == 'domain_reputation':
            ret_val = self._handle_url_reputation(param, 'domain')
        elif action_id == 'detonate_url':
            ret_val = self._handle_url_reputation(param, 'url')
        elif action_id == 'get_report':
            ret_val = self._handle_get_report(param)

        return ret_val


# standalone
if __name__ == '__main__':
    # import pu'b
    import argparse

    # pudb.set_trace()

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
            login_url = PolyswarmConnector._get_phantom_base_url() + '/login'

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
            print ('Unable to get session id from the platform. Error: {e}'.
                    format(e=str(e)))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = PolyswarmConnector(cli=True)
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
