# File: gcloudcomputeengine_connector.py
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
# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

import json

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from googleapiclient import errors

from gcloudcomputeengine_consts import *

import googleapiclient.discovery
from google.oauth2 import service_account


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class GcloudComputeEngineConnector(BaseConnector):
    def __init__(self):
        super(GcloudComputeEngineConnector, self).__init__()
        self._state = None
        self._project = None
        self._key_json = None

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

    def _create_discovery_client(self, action_result):
        try:
            service_account_json = json.loads(self._key_json)

            credentials = service_account.Credentials.from_service_account_info(
                service_account_json,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )

            self._client = googleapiclient.discovery.build(
                COMPUTE, COMPUTE_VERSION, credentials=credentials
            )

        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Could not create google api client: {0}".format(err)
            )

        return phantom.APP_SUCCESS

    def _send_request(self, request, action_result):
        try:
            response = request.execute()
        except errors.HttpError as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Google API HTTP Error", err),
                None,
            )
        except errors.Error as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Google API Request Error", err),
                None,
            )

        return phantom.APP_SUCCESS, response

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")

        if not self._create_discovery_client(action_result):
            self.save_progress("Could not create API client")
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_tag_instance(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_discovery_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        zone = param["zone"]
        resourceid = param["id"]
        tags = param["tags"]
        tags = [tags.strip() for tags in tags.split(',')]
        tags = list(filter(None, tags))
        if not tags:
            tags = ""
        else:
            tags = ",".join(tags)

        try:
            request = self._client.instances().get(
                project=self._project, zone=zone, instance=resourceid
            )
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        ret_val, instance_details = self._send_request(request, action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        tags_body = {
            "fingerprint": instance_details.get("tags", {}).get("fingerprint"),
            "items": tags.split(","),
        }

        try:
            request = self._client.instances().setTags(
                project=self._project, zone=zone, instance=resourceid, body=tags_body
            )
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        ret_val, instance_details = self._send_request(request, action_result)

        action_result.add_data(instance_details)
        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def _handle_describe_instance(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_discovery_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        zone = param["zone"]
        resourceid = param["id"]

        try:
            request = self._client.instances().get(
                project=self._project, zone=zone, instance=resourceid
            )
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)

        summary = action_result.update_summary({})
        try:
            summary["id"] = response.get("id")
            summary["name"] = response.get("name")
            summary["machineType"] = response.get("machineType")
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def _handle_stop_instance(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_discovery_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        zone = param["zone"]
        resourceid = param["id"]

        try:
            request = self._client.instances().stop(
                project=self._project, zone=zone, instance=resourceid
            )
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def _handle_start_instance(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_discovery_client(action_result):
            self.save_progress("Could not create API client")
            return action_result.get_status()

        zone = param["zone"]
        resourceid = param["id"]

        try:
            request = self._client.instances().start(
                project=self._project, zone=zone, instance=resourceid
            )
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, err)

        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        elif action_id == "tag_instance":
            ret_val = self._handle_tag_instance(param)

        elif action_id == "describe_instance":
            ret_val = self._handle_describe_instance(param)

        elif action_id == "stop_instance":
            ret_val = self._handle_stop_instance(param)

        elif action_id == "start_instance":
            ret_val = self._handle_start_instance(param)

        return ret_val

    def initialize(self):
        self._state = self.load_state()

        config = self.get_config()

        self._key_json = config["key_json"]
        self._project = config["project"]

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import pudb
    import argparse
    import requests

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

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
            login_url = GcloudComputeEngineConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = GcloudComputeEngineConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
