# File: radar_connector.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import json
import os
import requests
from datetime import datetime
from pytz import timezone
from bs4 import BeautifulSoup
from radar_consts import *

# Phantom App imports
import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class RadarConnector(BaseConnector):

    def __init__(self):
        # Call the BaseConnectors init first
        super(RadarConnector, self).__init__()

        self._state = None

    def initialize(self):
        # Load any state in initialize
        self._state = self.load_state()

        # set asset config and env vars
        config = self.get_config()
        self._api_url = config.get("radar_api_url")
        self._verify_ssl = not os.getenv(ALLOW_SELF_SIGNED_CERTS)

        return phantom.APP_SUCCESS

    def _process_empty_response(self, response, action_result):
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response, no information in header"), None)

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception as ex:
            self.debug_print(f"Process HTML error during action: {self.get_action_identifier()}. Error:", ex)
            error_text = "Cannot parse error details"

        message = f"HTML Response Status Code: {status_code}: {error_text}\n"
        message = message.replace(u"{", "{{").replace(u"}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        resp_json = None
        try:
            resp_json = response.json()
            if response.links and response.links["ui"]:
                resp_json["url"] = response.links["ui"]["url"]
        except ValueError as ex:
            if 200 <= response.status_code < 399:
                return RetVal(action_result.set_status(phantom.APP_SUCCESS), {"headers": dict(response.headers)})
            else:
                self.debug_print(f"Parse JSON error during action: {self.get_action_identifier()}. Error:", ex)
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR,
                        f"Unable to parse JSON response. Error: {str(ex)} === {resp_json}"
                    ),
                    None
                )

        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = f"JSON Response Status Code: {response.status_code}: {response.text.replace(u'{', '{{').replace(u'}', '}}')}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, resp, action_result):
        self.save_progress(f"Process response")

        # store the r_text in debug data, it will get dumped in the logs if the action fail
        action_result.add_debug_data({"r_status_code": resp.status_code})
        action_result.add_debug_data({"r_text": resp.text})
        action_result.add_debug_data({"r_headers": resp.headers})

        # Process each "Content-Type" of response separately

        # Process a json response
        if "json" in resp.headers.get("Content-Type", ""):
            return self._process_json_response(resp, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in resp.headers.get("Content-Type", ""):
            return self._process_html_response(resp, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not resp.text:
            return self._process_empty_response(resp, action_result)

        # everything else is actually an error at this point
        message = f"Error from Radar API. Status Code: {resp.status_code} Data from server: {resp.text.replace('{', '{{').replace('}', '}}')}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        self.save_progress(f"Make rest call")

        url = f"{self._api_url}{endpoint}"
        config = self.get_config()
        resp_json = None
        request_headers = {
            "User-Agent": "Splunk Phantom",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config['radar_api_token']}"
        }

        self.save_progress(f"Send {method} request to {url}")

        try:
            request_func = getattr(requests, method)
        except AttributeError as aex:
            self.debug_print(f"Get request {method} attribute error during action: {self.get_action_identifier()}. Error:", aex)
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"), resp_json)

        try:
            resp = request_func(url, verify=self._verify_ssl, headers=request_headers, **kwargs)
            return self._process_response(resp, action_result)

        except Exception as ex:
            self.debug_print(f"Make REST call during action: {self.get_action_identifier()}. Error:", ex)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Error Connecting to server. Details: {str(ex)}"
                ),
                resp_json
            )

    def _handle_test_connectivity(self, param):
        self.save_progress("Connect to Radar")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        radar_val, response = self._make_rest_call("/incidents", action_result, method="get", params=None)
        if phantom.is_fail(radar_val):
            self.save_progress("Radar test connectivity fail.")
            return action_result.get_status()

        self.save_progress("Radar test connectivity success")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_incident(self, param):
        self.save_progress(f"Run action {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        name = param.get("name", "Default name")
        description = param.get("description", "Default description")

        # use timezone set in asset configuration to set discovered date_time timezone
        config = self.get_config()
        incident_group = int(config.get("radar_incident_group"))
        time_zone = config.get("time_zone", "UTC")
        date_time = datetime.now(timezone(time_zone)).strftime("%Y-%m-%dT%H:%M:%S")

        # get incident channel information
        phantom_base_url = self._get_system_settings()["company_info_settings"]["fqdn"]
        container_path = ""
        container_id = self.get_container_id()
        if container_id is not None:
            container_path = f"/mission/{container_id}"

        uri = f"{phantom_base_url}{container_path}"

        self.save_progress(f"Create payload")

        body = {
            "incident_group_id": incident_group,
            "channel": {
                "id": f"{container_id}",
                "source": "Splunk Phantom",
                "uri": uri
            },
            "name": name,
            "description": description,
            "discovered": {
                "date_time": date_time,
                "time_zone": time_zone
            }
        }

        radar_val, data = self._make_rest_call("/incidents", action_result, method="post", data=json.dumps(body))

        if phantom.is_fail(radar_val):
            return action_result.get_status()

        data["incident_id"] = data["id"]
        data["name"] = name
        data["description"] = description
        data["group"] = incident_group
        data["discovered"] = f"{date_time} / {time_zone}"

        self.save_progress("Add data to action result")
        action_result.add_data(data)

        # Return success, no need to set the message, only the status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_system_settings(self):
        self.save_progress("Get system settings")

        url = f"{self.get_phantom_base_url()}rest/system_settings"
        try:
            resp = requests.get(url, verify=False)
            resp_json = resp.json()
        except Exception as ex:
            self.debug_print(f"Get system settings during action: {self.get_action_identifier()}. Error:", ex)

        return resp_json

    def _handle_add_note(self, param):
        self.save_progress(f"Run action {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        content = param.get("content")
        category = "Splunk Phantom"
        incident_id = param.get("incident_id")

        body = {
            "content": content,
            "category": category,
        }

        # make rest call
        radar_val, data = self._make_rest_call(f"/incidents/{param.get('incident_id')}/notes", action_result, method="post", data=json.dumps(body))

        if phantom.is_fail(radar_val):
            return action_result.get_status()

        data["incident_id"] = incident_id
        data["id"] = data["headers"]["Location"].split("/")[4]
        data["content"] = content
        data["category"] = category

        self.save_progress("Add data to action result")
        action_result.add_data(data)

        # Return success, no need to set the message, only the status
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        elif action_id == "create_incident":
            ret_val = self._handle_create_incident(param)

        elif action_id == "add_note":
            ret_val = self._handle_add_note(param)

        return ret_val

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == "__main__":
    import pudb
    import argparse

    pudb.set_trace()

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("input_test_json", help="Input Test JSON file")
    arg_parser.add_argument("-u", "--username", help="username", required=False)
    arg_parser.add_argument("-p", "--password", help="password", required=False)

    args = arg_parser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = RadarConnector._get_phantom_base_url() + "/login"

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

        connector = RadarConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
