#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from test_consts import *
import requests
import json
from bs4 import BeautifulSoup

from datetime import datetime, timezone, timedelta
import secrets
import string
import hashlib


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TestConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TestConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="post", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def authenticationHeaders(self):
        config = self.get_config()

        api_key = config['api_key']
        advanced = config['advanced']
        api_key_id = config['api_id']

        if advanced:
            # Generate a 64 bytes random string
            nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
            # Get the current timestamp as milliseconds
            timestamp = int(datetime.now(timezone.utc).timestamp()) * 1000
            # Generate the auth key
            auth_key = "%s%s%s" % (api_key, nonce, timestamp)
            # Convert to bytes object
            auth_key = auth_key.encode("utf-8")
            # Calculate sha256
            api_key_hash = hashlib.sha256(auth_key).hexdigest()
            headers = {
                "x-xdr-timestamp": str(timestamp),
                "x-xdr-nonce": nonce,
                "x-xdr-auth-id": str(api_key_id),
                "Authorization": api_key_hash
            }
        else:
            headers = {
                "x-xdr-auth-id": str(api_key_id),
                "Authorization": api_key
            }

        return headers

    def _handle_on_poll(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        polled_count = 0
        incidents = []

        while True:
            obj, sort, request_data, parameters = {}, {}, {}, {}
            filters = []
            obj["field"] = "creation_time"
            obj["operator"] = "gte"
            obj["value"] = self._state.get("last_incident", int((datetime.now(timezone.utc) - timedelta(days=7)).timestamp() * 1000))
            filters.append(obj)
            request_data["filters"] = filters
            sort["field"] = "creation_time"
            sort["keyword"] = "asc"
            request_data["sort"] = sort
            parameters["request_data"] = request_data

            # make rest call
            headers = self.authenticationHeaders()
            ret_val, response = self._make_rest_call(
                '/incidents/get_incidents/', action_result, headers=headers, json=parameters
            )

            if phantom.is_fail(ret_val):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                return action_result.get_status()

            reply = response["reply"]

            if reply["total_count"] == 0:
                break

            polled_count += reply["result_count"]
            incidents += reply["incidents"]
            self._state.update({"last_incident": incidents[-1]["creation_time"] + 1})
            self.save_state(self._state)

            if reply["total_count"] == reply["result_count"]:
                break

        for incident in incidents:
            cef, container = {}, {}
            container["name"] = "Cortex XDR Incident {0}".format(incident["incident_id"])
            container["description"] = "Cortex XDR Incident"

            first_cef = True

            for key, value in incident.items():
                if first_cef:
                    cef["cortex_xdr"] = True
                    first_cef = False
                cef[key] = value
                artifacts = []
                artifact = {"label": "incident", "cef": cef}
                artifacts.append(artifact)
                container["data"] = incident
                container["artifacts"] = artifacts

            status, message, container_id = self.save_container(container)
            if status == phantom.APP_ERROR:
                self.debug_print("Failed to store: {0}".format(message))
                self.debug_print("stat/msg {0}/{1}".format(status, message))
                return action_result.set_status(phantom.APP_ERROR, "Container creation failed: {0}".format(message))

        # Return success
        self.save_progress("{0} incident(s) polled".format(polled_count))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to API server")

        # make rest call
        headers = self.authenticationHeaders()
        parameters = {}
        ret_val, response = self._make_rest_call(
            '/endpoints/get_endpoints/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            self.save_progress("Test failed")
            return action_result.get_status()

        # Return success
        self.save_progress("Connected successfully, test passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_endpoints(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        parameters = {}
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/endpoints/get_endpoints/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["endpoint_count"] = str(len(reply))
        for x in range(len(reply)):
            summary["endpoint_{0}".format(x + 1)] = reply[x]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_policy(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        endpoint_id = param["endpoint_id"]

        request_data, parameters = {}, {}
        request_data["endpoint_id"] = endpoint_id
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/endpoints/get_policy/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["policy_name"] = reply["policy_name"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_action_status(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        action_id = param["action_id"]

        request_data, parameters = {}, {}
        if isinstance(action_id, int):
            request_data["group_action_id"] = action_id
        else:
            return action_result.set_status(phantom.APP_ERROR, "Action ID must be an integer")
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/actions/get_action_status/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["action_status"] = reply["data"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_retrieve_file(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        endpoint_id = param["endpoint_id"]
        files_windows = param.get("windows_path")
        files_linux = param.get("linux_path")
        files_macos = param.get("macos_path")

        obj, files, request_data, parameters = {}, {}, {}, {}
        endpoints, filters = [], []
        endpoints.append(endpoint_id)
        obj["field"] = "endpoint_id_list"
        obj["operator"] = "in"
        obj["value"] = endpoints
        filters.append(obj)
        request_data["filters"] = filters
        if files_windows:
            windows = []
            windows.append(files_windows)
            files["windows"] = windows
        if files_linux:
            linux = []
            linux.append(files_linux)
            files["linux"] = linux
        if files_macos:
            macos = []
            macos.append(files_macos)
            files["macos"] = macos
        if not files:
            return action_result.set_status(phantom.APP_ERROR, "Must provide at least one file path")
        request_data["files"] = files
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/endpoints/file_retrieval/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["action_id"] = reply["action_id"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_retrieve_file_details(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        action_id = param["action_id"]

        request_data, parameters = {}, {}
        if isinstance(action_id, int):
            request_data["group_action_id"] = action_id
        else:
            return action_result.set_status(phantom.APP_ERROR, "Action ID must be an integer")
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/actions/file_retrieval_details/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["file_url"] = reply["data"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_file(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        endpoint_id = param["endpoint_id"]
        file_path = param["file_path"]
        file_hash = param["file_hash"]

        obj, request_data, parameters = {}, {}, {}
        endpoints, filters = [], []
        endpoints.append(endpoint_id)
        obj["field"] = "endpoint_id_list"
        obj["operator"] = "in"
        obj["value"] = endpoints
        filters.append(obj)
        request_data["filters"] = filters
        request_data["file_path"] = file_path
        request_data["file_hash"] = file_hash
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/endpoints/quarantine/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["action_id"] = reply["action_id"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unquarantine_file(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        file_hash = param["file_hash"]
        endpoint_id = param["endpoint_id"]

        request_data, parameters = {}, {}
        request_data["file_hash"] = file_hash
        request_data["endpoint_id"] = endpoint_id
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/endpoints/restore/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["action_id"] = reply["action_id"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_hash(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        file_hash = param["file_hash"]
        comment = param.get("comment")
        incident_id = param.get("incident_id")

        request_data, parameters = {}, {}
        request_data["hash_list"] = [file_hash]
        if comment:
            request_data["comment"] = comment
        if incident_id:
            if isinstance(incident_id, int):
                request_data["incident_id"] = str(incident_id)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Incident ID must be an integer")
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/hash_exceptions/block_list/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary["list_updated"] = response["reply"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_allow_hash(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        file_hash = param["file_hash"]
        comment = param.get("comment")
        incident_id = param.get("incident_id")

        request_data, parameters = {}, {}
        request_data["hash_list"] = [file_hash]
        if comment:
            request_data["comment"] = comment
        if incident_id:
            if isinstance(incident_id, int):
                request_data["incident_id"] = str(incident_id)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Incident ID must be an integer")
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/hash_exceptions/allow_list/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary["list_updated"] = response["reply"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_device(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        endpoint_id = param["endpoint_id"]

        request_data, parameters = {}, {}
        request_data["endpoint_id"] = endpoint_id
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/endpoints/isolate/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["action_id"] = reply["action_id"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unquarantine_device(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        endpoint_id = param["endpoint_id"]

        request_data, parameters = {}, {}
        request_data["endpoint_id"] = endpoint_id
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/endpoints/unisolate/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["action_id"] = reply["action_id"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_scan_endpoint(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        scan_all = param["scan_all"]
        endpoint_id = param.get("endpoint_id")
        dist_name = param.get("dist_name")
        first_seen = param.get("first_seen")
        last_seen = param.get("last_seen")
        ip_list = param.get("ip_list")
        group_name = param.get("group_name")
        platform = param.get("platform")
        alias = param.get("alias")
        isolate = param.get("isolate")
        hostname = param.get("hostname")
        scan_status = param.get("scan_status")

        request_data, parameters = {}, {}
        if scan_all:
            request_data["filters"] = "all"
        else:
            filters = []
            if endpoint_id:
                endpoints = []
                obj = {}
                endpoints.append(endpoint_id)
                obj["field"] = "endpoint_id_list"
                obj["operator"] = "in"
                obj["value"] = endpoints
                filters.append(obj)
            if dist_name:
                dists = []
                obj = {}
                dists.append(dist_name)
                obj["field"] = "dist_name"
                obj["operator"] = "in"
                obj["value"] = dists
                filters.append(obj)
            if first_seen:
                if isinstance(first_seen, int):
                    obj = {}
                    obj["field"] = "first_seen"
                    obj["operator"] = "gte"
                    obj["value"] = first_seen
                    filters.append(obj)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "First seen must be an integer")
            if last_seen:
                if isinstance(last_seen, int):
                    obj = {}
                    obj["field"] = "last_seen"
                    obj["operator"] = "gte"
                    obj["value"] = last_seen
                    filters.append(obj)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Last seen must be an integer")
            if ip_list:
                ips = []
                obj = {}
                ips.append(ip_list)
                obj["field"] = "ip_list"
                obj["operator"] = "in"
                obj["value"] = ips
                filters.append(obj)
            if group_name:
                groups = []
                obj = {}
                groups.append(group_name)
                obj["field"] = "group_name"
                obj["operator"] = "in"
                obj["value"] = groups
                filters.append(obj)
            if platform:
                platforms = ["windows", "linux", "macos", "android"]
                if any(value == platform for value in platforms):
                    temp = []
                    obj = {}
                    temp.append(platform)
                    obj["field"] = "platform"
                    obj["operator"] = "in"
                    obj["value"] = temp
                    filters.append(obj)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Invalid platform")
            if alias:
                aliases = []
                obj = {}
                aliases.append(alias)
                obj["field"] = "alias"
                obj["operator"] = "in"
                obj["value"] = aliases
                filters.append(obj)
            if isolate is True or isolate is False:
                isolates = []
                obj = {}
                if isolate is True:
                    isolates.append("isolated")
                else:
                    isolates.append("unisolated")
                obj["field"] = "isolate"
                obj["operator"] = "in"
                obj["value"] = isolates
                filters.append(obj)
            if hostname:
                hostnames = []
                obj = {}
                hostnames.append(hostname)
                obj["field"] = "hostname"
                obj["operator"] = "in"
                obj["value"] = hostnames
                filters.append(obj)
            if scan_status:
                statuses = ["none", "pending", "in_progress", "canceled", "aborted", "pending_cancellation", "success", "error"]
                if any(value == scan_status for value in statuses):
                    status = []
                    obj = {}
                    status.append(scan_status)
                    obj["field"] = "scan_status"
                    obj["operator"] = "in"
                    obj["value"] = status
                    filters.append(obj)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Invalid platform")
            request_data["filters"] = filters
            if not filters:
                return action_result.set_status(phantom.APP_ERROR, "Must provide at least one filter criterion")
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/endpoints/scan/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["action_id"] = reply["action_id"]
        summary["endpoint_scanning"] = reply["endpoints_count"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_cancel_scan_endpoint(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        scan_all = param["scan_all"]
        endpoint_id = param.get("endpoint_id")
        dist_name = param.get("dist_name")
        first_seen = param.get("first_seen")
        last_seen = param.get("last_seen")
        ip_list = param.get("ip_list")
        group_name = param.get("group_name")
        platform = param.get("platform")
        alias = param.get("alias")
        isolate = param.get("isolate")
        hostname = param.get("hostname")
        scan_status = param.get("scan_status")

        request_data, parameters = {}, {}
        if scan_all:
            request_data["filters"] = "all"
        else:
            filters = []
            if endpoint_id:
                endpoints = []
                obj = {}
                endpoints.append(endpoint_id)
                obj["field"] = "endpoint_id_list"
                obj["operator"] = "in"
                obj["value"] = endpoints
                filters.append(obj)
            if dist_name:
                dists = []
                obj = {}
                dists.append(dist_name)
                obj["field"] = "dist_name"
                obj["operator"] = "in"
                obj["value"] = dists
                filters.append(obj)
            if first_seen:
                if isinstance(first_seen, int):
                    obj = {}
                    obj["field"] = "first_seen"
                    obj["operator"] = "gte"
                    obj["value"] = first_seen
                    filters.append(obj)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "First seen must be an integer")
            if last_seen:
                if isinstance(last_seen, int):
                    obj = {}
                    obj["field"] = "last_seen"
                    obj["operator"] = "gte"
                    obj["value"] = last_seen
                    filters.append(obj)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Last seen must be an integer")
            if ip_list:
                ips = []
                obj = {}
                ips.append(ip_list)
                obj["field"] = "ip_list"
                obj["operator"] = "in"
                obj["value"] = ips
                filters.append(obj)
            if group_name:
                groups = []
                obj = {}
                groups.append(group_name)
                obj["field"] = "group_name"
                obj["operator"] = "in"
                obj["value"] = groups
                filters.append(obj)
            if platform:
                platforms = ["windows", "linux", "macos", "android"]
                if any(value == platform for value in platforms):
                    temp = []
                    obj = {}
                    temp.append(platform)
                    obj["field"] = "platform"
                    obj["operator"] = "in"
                    obj["value"] = temp
                    filters.append(obj)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Invalid platform")
            if alias:
                aliases = []
                obj = {}
                aliases.append(alias)
                obj["field"] = "alias"
                obj["operator"] = "in"
                obj["value"] = aliases
                filters.append(obj)
            if isolate is True or isolate is False:
                isolates = []
                obj = {}
                if isolate is True:
                    isolates.append("isolated")
                else:
                    isolates.append("unisolated")
                obj["field"] = "isolate"
                obj["operator"] = "in"
                obj["value"] = isolates
                filters.append(obj)
            if hostname:
                hostnames = []
                obj = {}
                hostnames.append(hostname)
                obj["field"] = "hostname"
                obj["operator"] = "in"
                obj["value"] = hostnames
                filters.append(obj)
            if scan_status:
                statuses = ["none", "pending", "in_progress", "canceled", "aborted", "pending_cancellation", "success", "error"]
                if any(value == scan_status for value in statuses):
                    status = []
                    obj = {}
                    status.append(scan_status)
                    obj["field"] = "scan_status"
                    obj["operator"] = "in"
                    obj["value"] = status
                    filters.append(obj)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Invalid platform")
            request_data["filters"] = filters
            if not filters:
                return action_result.set_status(phantom.APP_ERROR, "Must provide at least one filter criterion")
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/endpoints/abort_scan/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["action_id"] = reply["action_id"]
        summary["endpoint_cancelling"] = reply["endpoints_count"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incidents(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self._state.update({"last_incident": 1000000000000})

        # Access action parameters passed in the 'param' dictionary
        modification_time = param.get("modification_time")
        creation_time = param.get("creation_time")
        incident_id = param.get("incident_id")
        description = param.get("description")
        alert_sources = param.get("alert_sources")
        status = param.get("status")
        search_from = param.get("search_from")
        search_to = param.get("search_to")
        sort = param["sort"]
        sort_field = param.get("sort_field", "creation_time")
        sort_order = param.get("sort_order", "desc")

        request_data, parameters = {}, {}
        filters = []
        if modification_time:
            if isinstance(modification_time, int):
                obj = {}
                obj["field"] = "modification_time"
                obj["operator"] = "gte"
                obj["value"] = modification_time
                filters.append(obj)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Modification time must be an integer")
        if creation_time:
            if isinstance(creation_time, int):
                obj = {}
                obj["field"] = "creation_time"
                obj["operator"] = "gte"
                obj["value"] = creation_time
                filters.append(obj)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Creation time must be an integer")
        if incident_id:
            incidents = []
            obj = {}
            incidents.append(str(incident_id))
            obj["field"] = "incident_id_list"
            obj["operator"] = "in"
            obj["value"] = incidents
            filters.append(obj)
        if description:
            obj = {}
            obj["field"] = "description"
            obj["operator"] = "contains"
            obj["value"] = description
            filters.append(obj)
        if alert_sources:
            sources = []
            obj = {}
            sources.append(alert_sources)
            obj["field"] = "alert_sources_list"
            obj["operator"] = "in"
            obj["value"] = sources
            filters.append(obj)
        if status:
            statuses = ["new", "under_investigation", "resolved_threat_handled", "resolved_known_issue", "resolved_false_positive", "resolved_other", "resolved_auto"]
            if any(value == status for value in statuses):
                obj = {}
                obj["field"] = "status"
                obj["operator"] = "eq"
                obj["value"] = status
                filters.append(obj)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Invalid status")
        if filters:
            request_data["filters"] = filters
        if search_from:
            if isinstance(search_from, int):
                request_data["search_from"] = search_from
            else:
                return action_result.set_status(phantom.APP_ERROR, "Search from must be an integer")
        if search_to:
            if isinstance(search_to, int):
                request_data["search_to"] = search_to
            else:
                return action_result.set_status(phantom.APP_ERROR, "Search to must be an integer")
        if sort:
            fields = ["modification_time", "creation_time"]
            if any(value == sort_field for value in fields):
                orders = ["asc", "desc"]
                if any(value == sort_order for value in orders):
                    sorting = {}
                    sorting["field"] = sort_field
                    sorting["keyword"] = sort_order
                    request_data["sort"] = sorting
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Invalid sort order")
            else:
                return action_result.set_status(phantom.APP_ERROR, "Invalid sort field")
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/incidents/get_incidents/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["total_count"] = reply["total_count"]
        summary["result_count"] = reply["result_count"]
        incidents = reply["incidents"]
        for x in range(len(incidents)):
            summary["result_{0}".format(x + 1)] = incidents[x]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incident_details(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        incident_id = param["incident_id"]
        alerts_limit = param.get("alerts_limit")

        request_data, parameters = {}, {}
        request_data["incident_id"] = str(incident_id)
        if alerts_limit:
            if isinstance(alerts_limit, int):
                request_data["alerts_limit"] = alerts_limit
            else:
                return action_result.set_status(phantom.APP_ERROR, "Alerts limit must be an integer")
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/incidents/get_incident_extra_data/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]["file_artifacts"]["data"][0]
        summary["alert_count"] = reply["alert_count"]
        summary["is_malicious"] = reply["is_malicious"]
        summary["file_name"] = reply["file_name"]
        summary["file_sha256"] = reply["file_sha256"]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alerts(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        alert_id = param.get("alert_id")
        alert_source = param.get("alert_source")
        severity = param.get("severity")
        creation_time = param.get("creation_time")
        search_from = param.get("search_from")
        search_to = param.get("search_to")
        sort = param["sort"]
        sort_field = param.get("sort_field", "creation_time")
        sort_order = param.get("sort_order", "desc")

        request_data, parameters = {}, {}
        filters = []
        if alert_id:
            if isinstance(alert_id, int):
                alerts = []
                obj = {}
                alerts.append(alert_id)
                obj["field"] = "alert_id_list"
                obj["operator"] = "in"
                obj["value"] = alerts
                filters.append(obj)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Alert ID must be an integer")
        if alert_source:
            sources = []
            obj = {}
            sources.append(alert_source)
            obj["field"] = "alert_source"
            obj["operator"] = "in"
            obj["value"] = sources
            filters.append(obj)
        if severity:
            severities = ["info", "low", "medium", "high", "unknown"]
            if any(value == severity for value in severities):
                temp = []
                obj = {}
                temp.append(severity)
                obj["field"] = "severity"
                obj["operator"] = "in"
                obj["value"] = temp
                filters.append(obj)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Invalid severity")
        if creation_time:
            if isinstance(creation_time, int):
                obj = {}
                obj["field"] = "creation_time"
                obj["operator"] = "gte"
                obj["value"] = creation_time
                filters.append(obj)
            else:
                return action_result.set_status(phantom.APP_ERROR, "Creation time must be an integer")
        if filters:
            request_data["filters"] = filters
        if search_from:
            if isinstance(search_from, int):
                request_data["search_from"] = search_from
            else:
                return action_result.set_status(phantom.APP_ERROR, "Search from must be an integer")
        if search_to:
            if isinstance(search_to, int):
                request_data["search_to"] = search_to
            else:
                return action_result.set_status(phantom.APP_ERROR, "Search to must be an integer")
        if sort:
            fields = ["severity", "creation_time"]
            if any(value == sort_field for value in fields):
                orders = ["asc", "desc"]
                if any(value == sort_order for value in orders):
                    sorting = {}
                    sorting["field"] = sort_field
                    sorting["keyword"] = sort_order
                    request_data["sort"] = sorting
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Invalid sort order")
            else:
                return action_result.set_status(phantom.APP_ERROR, "Invalid sort field")
        parameters["request_data"] = request_data
        self.save_progress("Request JSON: {0}".format(parameters))

        # make rest call
        headers = self.authenticationHeaders()
        ret_val, response = self._make_rest_call(
            '/alerts/get_alerts_multi_events/', action_result, headers=headers, json=parameters
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        self.save_progress("Response JSON: {0}".format(response))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        reply = response["reply"]
        summary["total_count"] = reply["total_count"]
        summary["result_count"] = reply["result_count"]
        alerts = reply["alerts"]
        event = alerts[0]["events"]
        summary["process_name"] = event[0]["actor_process_image_name"]
        summary["process_path"] = event[0]["actor_process_image_path"]
        summary["process_sha256"] = event[0]["actor_process_image_sha256"]
        summary["endpoint_id"] = alerts[0]["endpoint_id"]
        summary["host_name"] = alerts[0]["host_name"]
        summary["ip_address"] = alerts[0]["host_ip"]
        for x in range(len(alerts)):
            summary["Result {0}".format(x + 1)] = alerts[x]
        summary["raw"] = response

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        elif action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'list_endpoints':
            ret_val = self._handle_list_endpoints(param)

        elif action_id == 'get_policy':
            ret_val = self._handle_get_policy(param)

        elif action_id == 'get_action_status':
            ret_val = self._handle_get_action_status(param)

        elif action_id == 'retrieve_file':
            ret_val = self._handle_retrieve_file(param)

        elif action_id == 'retrieve_file_details':
            ret_val = self._handle_retrieve_file_details(param)

        elif action_id == 'quarantine_file':
            ret_val = self._handle_quarantine_file(param)

        elif action_id == 'unquarantine_file':
            ret_val = self._handle_unquarantine_file(param)

        elif action_id == 'block_hash':
            ret_val = self._handle_block_hash(param)

        elif action_id == 'allow_hash':
            ret_val = self._handle_allow_hash(param)

        elif action_id == 'quarantine_device':
            ret_val = self._handle_quarantine_device(param)

        elif action_id == 'unquarantine_device':
            ret_val = self._handle_unquarantine_device(param)

        elif action_id == 'scan_endpoint':
            ret_val = self._handle_scan_endpoint(param)

        elif action_id == 'cancel_scan_endpoint':
            ret_val = self._handle_cancel_scan_endpoint(param)

        elif action_id == 'get_incidents':
            ret_val = self._handle_get_incidents(param)

        elif action_id == 'get_incident_details':
            ret_val = self._handle_get_incident_details(param)

        elif action_id == 'get_alerts':
            ret_val = self._handle_get_alerts(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # self._base_url = "http://10.1.20.106:5000/api/{0}".format(config['fqdn'])
        self._base_url = "https://api-{0}/public_api/v1".format(config['fqdn'])

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
            login_url = TestConnector._get_phantom_base_url() + '/login'

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

        connector = TestConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
