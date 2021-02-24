#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals
import json
import base64
import os
import tempfile

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Usage of the consts file is recommended
from googlecloudiam_consts import *
import googleapiclient.discovery
from google.oauth2 import service_account
from googleapiclient import errors


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class GoogleCloudIamConnector(BaseConnector):

    def __init__(self):
        super(GoogleCloudIamConnector, self).__init__()
        self._state = None

    def _create_client(self, action_result):
        config = self.get_config()
        service_account_json = json.loads(config['key_json'])

        try:
            credentials = service_account.Credentials.from_service_account_info(
                service_account_json, scopes=[
                    "https://www.googleapis.com/auth/cloud-platform"])

            self._client = googleapiclient.discovery.build(
                IAM_SERVICE_NAME,
                IAM_SERVICE_VERSION,
                credentials=credentials
            )

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Could not create google api client: {0}".format(e))

        return phantom.APP_SUCCESS

    def _send_request(self, request, action_result):
        try:
            response = request.execute()
        except errors.HttpError as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Google API HTTP Error', e), None)
        except errors.Error as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Google API Request Error', e), None)

        return phantom.APP_SUCCESS, response

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")

        if not self._create_client(action_result):
            self.save_progress("Could not create API client.", e)
            return action_result.get_status()

        self.debug_print(self._client)

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_serviceaccountkey(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_client(action_result):
            self.save_progress("Could not create API client.", e)
            return action_result.get_status()

        # Required values can be accessed directly
        project = self.get_config()['project']
        account = param['account']

        name = f"projects/{project}/serviceAccounts/{account}"

        request = self._client.projects().serviceAccounts().keys().list(name=name)
        ret_val, response = self._send_request(request, action_result)

        self.debug_print(response)

        if (phantom.is_fail(ret_val)):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def _handle_get_serviceaccountkey(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_client(action_result):
            self.save_progress("Could not create API client.", e)
            return action_result.get_status()

        # Required values can be accessed directly
        project = self.get_config()['project']
        account = param['account']
        key = param['key']

        name = f"projects/{project}/serviceAccounts/{account}/keys/{key}"

        request = self._client.projects().serviceAccounts().keys().get(name=name)
        ret_val, response = self._send_request(request, action_result)

        self.debug_print(response)

        if (phantom.is_fail(ret_val)):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def _handle_delete_serviceaccountkey(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_client(action_result):
            self.save_progress("Could not create API client.", e)
            return action_result.get_status()

        # Required values can be accessed directly
        project = self.get_config()['project']
        account = param['account']
        key = param['key']

        name = f"projects/{project}/serviceAccounts/{account}/keys/{key}"

        request = self._client.projects().serviceAccounts().keys().delete(name=name)
        ret_val, response = self._send_request(request, action_result)

        self.debug_print(response)

        if (phantom.is_fail(ret_val)):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def _handle_create_serviceaccountkey(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_client(action_result):
            self.save_progress("Could not create API client.", e)
            return action_result.get_status()

        # Required values can be accessed directly
        project = self.get_config()['project']
        account = param['account']
        save_key = param.get("save_key_to_vault")

        name = f"projects/{project}/serviceAccounts/{account}"

        request = self._client.projects().serviceAccounts().keys().create(name=name)
        ret_val, response = self._send_request(request, action_result)

        if save_key:
            key_encoded = response["privateKeyData"]
            key_name = os.path.basename(response["name"])
            key_filename = f'{key_name}.json'
            key = base64.b64decode(key_encoded)
            vault_path = Vault.get_vault_tmp_dir()
            file_desc, file_path = tempfile.mkstemp(dir=vault_path)

            with open(file_path, "wb") as f:
                f.write(key)
            vault_ret = Vault.add_attachment(file_path, self.get_container_id(), key_filename)
            response["vault_id"] = vault_ret[phantom.APP_JSON_HASH]
            response["filename"] = key_filename
            action_result.set_summary({"created_vault_id": vault_ret[phantom.APP_JSON_HASH]})

        if (phantom.is_fail(ret_val)):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_serviceaccountkey':
            ret_val = self._handle_list_serviceaccountkey(param)

        elif action_id == 'get_serviceaccountkey':
            ret_val = self._handle_get_serviceaccountkey(param)

        elif action_id == 'delete_serviceaccountkey':
            ret_val = self._handle_delete_serviceaccountkey(param)

        elif action_id == 'create_serviceaccountkey':
            ret_val = self._handle_create_serviceaccountkey(param)

        return ret_val

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

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
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
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = GoogleCloudIamConnector._get_phantom_base_url() + '/login'

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
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = GoogleCloudIamConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
