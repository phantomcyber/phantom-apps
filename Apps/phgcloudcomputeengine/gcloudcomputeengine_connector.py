#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

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
            return action_result.set_status(
                phantom.APP_ERROR, "Could not create google api client: {0}".format(e)
            )

        return phantom.APP_SUCCESS

    def _send_request(self, request, action_result):
        try:
            response = request.execute()
        except errors.HttpError as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Google API HTTP Error", e),
                None,
            )
        except errors.Error as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Google API Request Error", e
                ),
                None,
            )

        return phantom.APP_SUCCESS, response

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")

        if not self._create_discovery_client(action_result):
            self.save_progress("Could not create API client.")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_tag_instance(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_discovery_client(action_result):
            self.save_progress("Could not create API client.", e)
            return action_result.get_status()

        zone = param["zone"]
        resourceid = param["id"]
        tags = param["tags"]

        request = self._client.instances().get(
            project=self._project, zone=zone, instance=resourceid
        )
        ret_val, instance_details = self._send_request(request, action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        tags_body = {
            "fingerprint": instance_details["tags"]["fingerprint"],
            "items": tags.split(","),
        }

        request = self._client.instances().setTags(
            project=self._project, zone=zone, instance=resourceid, body=tags_body
        )
        ret_val, instance_details = self._send_request(request, action_result)

        action_result.add_data(instance_details)
        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def _handle_describe_instance(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_discovery_client(action_result):
            self.save_progress("Could not create API client.", e)
            return action_result.get_status()

        zone = param["zone"]
        resourceid = param["id"]

        request = self._client.instances().get(
            project=self._project, zone=zone, instance=resourceid
        )
        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary["id"] = response["id"]
        summary["name"] = response["name"]
        summary["machineType"] = response["machineType"]

        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def _handle_stop_instance(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_discovery_client(action_result):
            self.save_progress("Could not create API client.", e)
            return action_result.get_status()

        zone = param["zone"]
        resourceid = param["id"]

        request = self._client.instances().stop(
            project=self._project, zone=zone, instance=resourceid
        )
        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def _handle_start_instance(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._create_discovery_client(action_result):
            self.save_progress("Could not create API client.", e)
            return action_result.get_status()

        zone = param["zone"]
        resourceid = param["id"]

        request = self._client.instances().start(
            project=self._project, zone=zone, instance=resourceid
        )
        ret_val, response = self._send_request(request, action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS, "Success")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
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
