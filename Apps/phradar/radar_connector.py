# File: radar_connector.py
# Copyright (c) 2020-2021 RADAR, LLC
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import json
import os
import requests
from datetime import datetime
import pytz
from dateutil import parser
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
        self._api_url = config.get("radar_api_url").strip("/")
        self._verify_ssl = not os.getenv(ALLOW_SELF_SIGNED_CERTS)
        self._time_zone = config.get("time_zone", "UTC")
        self._request_headers = {
            "User-Agent": "Splunk Phantom",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config['radar_api_token']}"
        }

        return phantom.APP_SUCCESS

    def _process_empty_response(self, response, action_result):
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Status Code: {}. Empty response, no information in header".format(response.status_code)), None)

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception as ex:
            err = self._get_error_message_from_exception(ex)
            self.debug_print(f"Action: {self.get_action_identifier()} - Process HTML error: {err}")
            error_text = "Cannot parse error details"

        message = f"HTML Response Status Code: {status_code} Data from server: {error_text}\n"
        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        resp_json = None
        try:
            resp_json = response.json()
            if response.links and response.links["ui"]:
                resp_json["url"] = response.links["ui"]["url"]
        except ValueError as ex:
            err = self._get_error_message_from_exception(ex)
            if 200 <= response.status_code < 399:
                return RetVal(phantom.APP_SUCCESS, {"headers": dict(response.headers)})
            else:
                self.debug_print(f"Action: {self.get_action_identifier()} - Process JSON error: {err}")
                return RetVal(action_result.set_status(phantom.APP_ERROR, err), None)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. {0}".format(err)), None)

        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. {}".format(self._process_response_error_message(response))
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, resp, action_result):
        self.save_progress("Processing response")

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

        # If content-type cannot be parsed handle an empty response
        if not resp.text:
            return self._process_empty_response(resp, action_result)

        # handle remaining error
        return RetVal(action_result.set_status(phantom.APP_ERROR, self._process_response_error_message(resp)), None)

    def _process_response_error_message(self, error_resp):
        status_code = error_resp.status_code
        status_message = f"Error response: Status code: {status_code}"
        if status_code == 404:
            return f"{status_message}. Message: Not Found. Please double check request parameters"
        if status_code == 403:
            return f"{status_message}. Message: Forbidden. " \
                f"Please double check that your Radar API token, user, and permissions are configured correctly"
        if status_code == 401:
            return f"{status_message}. Message: Unauthorized. " \
                f"Please double check your Radar API token"

        try:
            resp_json = error_resp.json()
            # if there are field validation errors return the first one
            resp_errors = resp_json.get("errors")
            if len(resp_errors) > 0:
                invalid_field = resp_errors[0].get("fields")
                invalid_field_msg = resp_errors[0].get("message")
                if invalid_field and invalid_field_msg:
                    return f"{status_message}. Parameter error: {invalid_field[0]}. Message: {invalid_field_msg}"
            # return standard error message
            return f"{status_message}. Message: {resp_json['message']}"
        except (ValueError, KeyError) as ex:
            err = self._get_error_message_from_exception(ex)
            self.debug_print(f"Action: {self.get_action_identifier()} - Process error response error: {err}")
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print(f"Action: {self.get_action_identifier()} - Error occurred: {err}")

        return f"{status_message}. Response: {error_resp.text.replace('{', '{{').replace('}', '}}')}"

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
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

    def _get_system_settings(self):
        self.save_progress("Getting system settings")

        url = f"{self.get_phantom_base_url()}rest/system_settings"
        try:
            resp = requests.get(url, verify=False)
            resp_json = resp.json()
        except Exception as ex:
            err = self._get_error_message_from_exception(ex)
            self.debug_print(f"Action: {self.get_action_identifier()} - Get system settings error: {err}")
            return None

        return resp_json

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        self.save_progress("Inside Make rest call")

        url = f"{self._api_url}{endpoint}"
        resp_json = None

        self.save_progress(f"Sending {method} request to {url}")

        action = self.get_action_identifier()
        try:
            request_func = getattr(requests, method)
        except AttributeError as aex:
            err = self._get_error_message_from_exception(aex)
            self.debug_print(f"Action: {action} - {method} Request attribute error: {err}")
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"), resp_json)

        try:
            resp = request_func(url, verify=self._verify_ssl, headers=self._request_headers, **kwargs)
            return self._process_response(resp, action_result)
        except Exception as ex:
            err = self._get_error_message_from_exception(ex)
            self.debug_print(f"Action: {action} - Make REST call error: {err}")
            try:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, self._process_response_error_message(resp)), resp_json)
            except Exception:
                return RetVal(action_result.set_status(phantom.APP_ERROR, f"Unable to connect to the URL: {url}. Error Details: {err}"), resp_json)

    def _payload_err(self, ex, action_result, data):
        err = self._get_error_message_from_exception(ex)
        msg = f"Response payload is missing necessary fields: {err}"
        self.debug_print((f"{msg}\nresponse data:", data))
        return action_result.set_status(phantom.APP_ERROR, msg)

    def _validate_incident_id_param(self, action_result, parameter):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    self.debug_print(VALID_INTEGER_MSG)
                    return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG), None

                parameter = int(parameter)
            except:
                self.debug_print(VALID_INTEGER_MSG)
                return action_result.set_status(phantom.APP_ERROR, VALID_INTEGER_MSG), None

            if parameter <= 0:
                self.debug_print(NON_NEGATIVE_INTEGER_MSG)
                return action_result.set_status(phantom.APP_ERROR, NON_NEGATIVE_INTEGER_MSG), None

        return phantom.APP_SUCCESS, parameter

    def _localize_time(self, time: str) -> datetime:
        return parser.parse(time).astimezone(pytz.timezone(self._time_zone))

    def _format_display_time(self, time: datetime) -> str:
        return f"{time.strftime('%Y-%m-%d %H:%M:%S')} / {self._time_zone}"

    def _handle_test_connectivity(self, param):
        self.save_progress("Connecting to Radar")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        radar_val, response = self._make_rest_call("/incidents", action_result, method="get", params=None)
        if phantom.is_fail(radar_val):
            self.save_progress("Radar test connectivity failed")
            return action_result.get_status()

        self.save_progress("Radar test connectivity passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_privacy_incident(self, param):
        action = self.get_action_identifier()
        self.save_progress(f"Running action {action}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        name = param["name"]
        description = param.get("description", "Privacy incident created by Splunk Phantom")
        # use timezone set in asset configuration to set discovered date_time timezone
        discovered = datetime.now(pytz.timezone(self._time_zone))
        # get incident channel information
        system_settings = self._get_system_settings()
        try:
            phantom_base_url = system_settings["company_info_settings"]["fqdn"]
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to retrive system settings from Phantom appliance. Details: {}".format(err))
        if not phantom_base_url:
            return action_result.set_status(phantom.APP_ERROR, "Please configure base URL for Phantom appliance")
        container_path = ""
        container_id = self.get_container_id()
        if container_id:
            container_path = f"/mission/{container_id}"

        uri = f"{phantom_base_url}{container_path}"

        self.save_progress("Create payload")

        body = {
            "channel": {
                "id": f"{container_id}",
                "source": "Splunk Phantom",
                "uri": uri
            },
            "name": name,
            "description": description,
            "discovered": {
                "date_time": discovered.strftime("%Y-%m-%dT%H:%M:%S"),
                "time_zone": self._time_zone
            }
        }

        radar_val, data = self._make_rest_call("/incidents", action_result, method="post", data=json.dumps(body))

        if phantom.is_fail(radar_val):
            return action_result.get_status()

        # construct incident output with fields we want to render
        incident = dict()
        try:
            incident["incident_id"] = data["id"]
        # return errors for missing id, which should always be present
        except KeyError as ex:
            return self._payload_err(ex, action_result, data)

        incident["name"] = name
        incident["description"] = description
        incident["url"] = data.get("url", "No incident url present in response")
        incident["discovered"] = self._format_display_time(discovered)

        self.save_progress("Adding data to action result")
        action_result.add_data(incident)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created a privacy incident")

    def _handle_get_privacy_incident(self, param):
        action = self.get_action_identifier()
        self.save_progress(f"Running action {action}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = param.get("incident_id")
        result, incident_id = self._validate_incident_id_param(action_result, incident_id)
        if phantom.is_fail(result):
            return action_result.get_status()

        radar_val, data = self._make_rest_call(f"/incidents/{incident_id}", action_result, method="get")

        if phantom.is_fail(radar_val):
            return action_result.get_status()

        # construct incident output with fields we want to render
        incident = dict()
        try:
            incident["incident_id"] = data["id"]
            incident["name"] = data["name"]
            incident["description"] = data["description"]

            # localize the discovered time according to the time zone specified in the payload before
            # localizing according to the asset configuration.
            discovered = pytz.timezone(data["discovered"]["time_zone"]) \
                .localize(parser.parse(data["discovered"]["date_time"])) \
                .astimezone(pytz.timezone(self._time_zone))

            # localize and format time strings
            incident["discovered_at"] = self._format_display_time(discovered)
            incident["created_at"] = self._format_display_time(self._localize_time(data["created_at"]))
            incident["updated_at"] = self._format_display_time(self._localize_time(data["updated_at"]))
            incident["updated_by"] = data["updated_by"]
            incident["incident_status"] = data["status"]
            incident["assignee"] = f"{data['assignee']['given_name']} {data['assignee']['surname']}"
        # return errors for missing fields that should always be present
        except KeyError as ex:
            return self._payload_err(ex, action_result, data)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting data from API Response. {}".format(err))

        incident["url"] = data.get("url", "No incident url present in response")

        self.save_progress("Add data to action result")
        action_result.add_data(incident)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully fetched privacy incident")

    def _handle_add_note(self, param):
        action = self.get_action_identifier()
        self.save_progress(f"Running action {action}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = param.get("incident_id")
        result, incident_id = self._validate_incident_id_param(action_result, incident_id)
        if phantom.is_fail(result):
            return action_result.get_status()

        content = param.get("content", "")
        body = {
            "content": content,
            "category": "Splunk Phantom",
        }

        radar_val, data = self._make_rest_call(f"/incidents/{incident_id}/notes", action_result, method="post", data=json.dumps(body))

        if phantom.is_fail(radar_val):
            return action_result.get_status()

        # construct note output with fields we want to render
        note = dict()
        note["id"] = data["id"]
        note["incident_id"] = incident_id
        note["content"] = content

        self.save_progress("Adding data to action result")
        action_result.add_data(note)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully added note")

    def _handle_get_notes(self, param):
        action = self.get_action_identifier()
        self.save_progress(f"Running action {action}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        incident_id = param.get("incident_id")
        result, incident_id = self._validate_incident_id_param(action_result, incident_id)
        if phantom.is_fail(result):
            return action_result.get_status()

        radar_val, data = self._make_rest_call(f"/incidents/{incident_id}/notes", action_result, method="get")

        if phantom.is_fail(radar_val):
            return action_result.get_status()

        # construct note output with fields we want to render
        notes = []
        for note_data in data:
            try:
                if note_data["category"] == "Splunk Phantom":
                    notes.append({
                        "incident_id": incident_id,
                        "id": note_data["id"],
                        "content": note_data["content"],
                        "category": note_data["category"],
                        "created_at": self._format_display_time(self._localize_time(note_data["created_at"])),
                        "created_by": note_data["created_by"],
                        "updated_at": self._format_display_time(self._localize_time(note_data["updated_at"])),
                        "updated_by": note_data["updated_by"],
                    })
            # return errors for missing fields that should always be present
            except KeyError as ex:
                return self._payload_err(ex, action_result, data)
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while getting data from API Response. {}".format(err))

        self.save_progress("Adding data to action result")
        for note in notes:
            action_result.add_data(note)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully fetched notes")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        elif action_id == "create_privacy_incident":
            ret_val = self._handle_create_privacy_incident(param)

        elif action_id == "get_privacy_incident":
            ret_val = self._handle_get_privacy_incident(param)

        elif action_id == "add_note":
            ret_val = self._handle_add_note(param)

        elif action_id == "get_notes":
            ret_val = self._handle_get_notes(param)

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

            auth_data = dict()
            auth_data["username"] = username
            auth_data["password"] = password
            auth_data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=auth_data, headers=headers)
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
