# File: gcloudstorage_connector.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import json
import os
import tempfile
import magic
import requests

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault
import phantom.rules as Rules

from gcloudstorage_consts import *
import googleapiclient.discovery
from google.oauth2 import service_account
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from googleapiclient import errors


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class GCloudStorageConnector(BaseConnector):

    def __init__(self):
        super(GCloudStorageConnector, self).__init__()
        self._state = None

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG.format(key=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG.format(key=key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERR_CODE_MSG
                error_msg = ERR_MSG_UNAVAILABLE
        except:
            error_code = ERR_CODE_MSG
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _create_storage_client(self, action_result):
        config = self.get_config()
        try:
            service_account_json = json.loads(config['key_json'])
        except json.decoder.JSONDecodeError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid value in 'service account json' asset configuration parameter")

        try:
            credentials = service_account.Credentials.from_service_account_info(
                service_account_json, scopes=[
                    "https://www.googleapis.com/auth/cloud-platform"])

            self._client = googleapiclient.discovery.build(
                STORAGE_SERVICE_NAME,
                STORAGE_SERVICE_VERSION,
                credentials=credentials
            )

        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Could not create google api client: {0}".format(err))

        return phantom.APP_SUCCESS

    def _send_request(self, request, action_result):
        try:
            response = request.execute()
        except errors.HttpError as e:
            error_code = str(json.loads(e.content)["error"]["code"])
            error_reason = e._get_reason()

            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Google API HTTP Error: {}. {} '.format(error_code, error_reason)), None)
        except errors.Error as e:
            error_reason = e._get_reason()

            return RetVal(action_result.set_status(phantom.APP_ERROR, 'Google API Request Error. {}'.format(error_reason)), None)

        return phantom.APP_SUCCESS, response

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")

        if not self._create_storage_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        project = self.get_config()['project']
        request = self._client.buckets().list(project=project)
        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return ret_val

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_object(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_storage_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        # Required values can be accessed directly
        object = param['object']
        bucket = param['bucket']

        request = self._client.objects().delete(bucket=bucket, object=object)
        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def _handle_list_objects(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_storage_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        # Required values can be accessed directly
        bucket = param['bucket']

        # Optional values should use the .get() function
        prefix = param.get('prefix', '')
        max_objects = param.get('max_objects', 1000)
        ret_val, max_objects = self._validate_integer(self, max_objects, MAX_OBJECTS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        request = self._client.objects().list(bucket=bucket, prefix=prefix, maxResults=max_objects)
        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        summary = {
            'num_objects': len(response.get('items', []))
        }

        action_result.set_summary(summary)

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully listed objects")

    def _handle_get_object(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_storage_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        # Required values can be accessed directly
        object = param['object']
        bucket = param['bucket']
        download_file = param.get('download_file')

        request = self._client.objects().get(bucket=bucket, object=object)
        ret_val, response = self._send_request(request, action_result)

        if download_file:
            request = self._client.objects().get_media(bucket=bucket, object=object)
            vault_path = Vault.get_vault_tmp_dir()
            file_desc, file_path = tempfile.mkstemp(dir=vault_path)
            with open(file_path, "wb") as f:
                media_request = MediaIoBaseDownload(f, request)
                done = False
                while not done:
                    progress, done = media_request.next_chunk()
                    if progress:
                        self.save_progress("File Download: {}".format(progress.progress() * 100))
            try:
                vault_ret = Vault.add_attachment(file_path, self.get_container_id(), os.path.basename(object))
                if not vault_ret.get('succeeded'):
                    raise Exception
                response["vault_id"] = vault_ret[phantom.APP_JSON_HASH]
                response["filename"] = os.path.basename(object)
                action_result.set_summary({"created_vault_id": response["vault_id"]})
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                ret_val = action_result.set_status(phantom.APP_ERROR, 'Could not add file to vault', err)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def _handle_create_object(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_storage_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        # Required values can be accessed directly
        path = param.get('path')
        bucket = param['bucket']
        vault_id = param['vault_id']

        try:
            self.debug_print('Rules.vault_info start')
            success, message, vault_info = Rules.vault_info(vault_id=vault_id)
            self.debug_print(
                'Rules.vault_info results: success: {}, message: {}, info: {}'
                .format(success, message, vault_info)
            )
        except requests.exceptions.HTTPError:
            error_message = "Invalid Vault ID: %s" % (vault_id)
            return action_result.set_status(phantom.APP_ERROR, error_message)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error opening file. {}".format(err))

        try:
            vault_info = list(vault_info)
            file_info = vault_info[0]
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting 'File Info'. {}".format(err))

        file_path = file_info['path']
        mime = magic.Magic(mime=True)

        file_mime_type = mime.from_file(file_path)

        file = MediaFileUpload(file_path, mimetype=file_mime_type)

        if not file_path:
            return action_result.set_status(phantom.APP_ERROR, "Could not find given vault ID in vault")

        if path:
            target_path = os.path.join(path, file_info["name"])
        else:
            target_path = file_info["name"]
        request = self._client.objects().insert(bucket=bucket, name=target_path, media_body=file)
        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created object")

    def _handle_describe_bucket(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_storage_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        # Required values can be accessed directly
        bucket = param['bucket']

        request = self._client.buckets().get(bucket=bucket)
        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully described bucket")

    def _handle_list_buckets(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_storage_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        config = self.get_config()
        project = config['project']

        request = self._client.buckets().list(project=project)
        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        summary = {
            'total_objects': len(response.get('items', []))
        }

        action_result.set_summary(summary)
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS, "List buckets successful")

    def _handle_create_bucket(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_storage_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        config = self.get_config()
        project = config['project']

        # Required values can be accessed directly
        bucket = param['bucket']
        location = param['location']

        req_body = {
            "name": bucket,
            "location": location
        }

        request = self._client.buckets().insert(project=project, body=req_body)
        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created bucket")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'delete_object':
            ret_val = self._handle_delete_object(param)

        elif action_id == 'list_objects':
            ret_val = self._handle_list_objects(param)

        elif action_id == 'get_object':
            ret_val = self._handle_get_object(param)

        elif action_id == 'create_object':
            ret_val = self._handle_create_object(param)

        elif action_id == 'describe_bucket':
            ret_val = self._handle_describe_bucket(param)

        elif action_id == 'list_buckets':
            ret_val = self._handle_list_buckets(param)

        elif action_id == 'create_bucket':
            ret_val = self._handle_create_bucket(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

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
            login_url = GCloudStorageConnector._get_phantom_base_url() + '/login'

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
            r2 = requests.post(login_url, verify=False,
                               data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = GCloudStorageConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
