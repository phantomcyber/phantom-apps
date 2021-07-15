#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# --

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
import bishopfox_consts as consts
import requests
import json
from bs4 import BeautifulSoup

import dateutil.parser
from datetime import datetime

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class BishopFoxConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(BishopFoxConnector, self).__init__()

        self._state = None

        return

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
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u"{", "{{").replace(u"}", "}}")
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
            r.text.replace(u"{", "{{").replace(u"}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each "Content-Type" of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY"s return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it"s not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None
        method = method.upper()
        url = "{0}/{1}".format(self._base_url, endpoint.strip("/"))

        try:
            r = self._request_session.request(
                method,
                url,
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _get_auth_token(self):
        self.save_progress("Getting Bishop Fox auth token")

        config = self.get_config()

        auth_token = None
        try:
            resp = requests.post(
                self._auth_token_url,
                verify=config.get("verify_server_cert", True),
                json={
                    "client_id": config["api_key"],
                    "client_secret": config["api_secret"],
                    "grant_type": "client_credentials",
                    "audience": "https://guardian"
                }
            )
            auth_token = resp.json()["access_token"]
        except Exception as e:
            self.save_progress("Failed to get Bishop Fox auth token: {0}".format(e))
            return RetVal(phantom.APP_ERROR, auth_token)

        self.save_progress("Successfully retrieved Bishop Fox auth token")
        return RetVal(phantom.APP_SUCCESS, auth_token)

    def _parse_finding_json(self, finding):
        subjects = []
        for subject in finding["subjects"]:
            subjects.append({
                "category": finding["category"],
                "clientId": subject["clientId"],
                "clientNote": subject["clientNote"],
                "createdAt": subject["createdAt"],
                "definition": finding["definition"],
                "details": finding["details"],
                "findingId": finding["findingId"],
                "findingUid": finding["uid"],
                "orgUid": finding["orgUid"],
                "recommendations": finding["recommendations"],
                "remediatedAt": subject["remediatedAt"],
                "remediatedDays": subject["remediatedDays"],
                "report": finding["report"],
                "resources": finding["additionalResources"],
                "severity": finding["severity"],
                "status": subject["status"],
                "subject": subject["subject"],
                "subjectUid": subject["uid"],
                "target": subject["target"],
                "updatedAt": subject["updatedAt"],
                "reportedAt": finding["reportedAt"]
            })
        return subjects

    def _parse_subject_json(self, subject, finding_uid):
        subject["findingUid"] = finding_uid
        subject["subjectUid"] = subject["uid"]
        del subject["uid"]
        return subject

    def _build_container_json(self, finding):
        label = self.get_config().get("ingest", {}).get("container_label")
        severity = consts.SEVERITY_MAP[finding["severity"]]
        container_json = {
            "name": finding["category"],
            "label": label,
            "severity": severity,
            "source_data_identifier": finding["subjectUid"],
            "artifacts": [{
                "name": finding["subject"],
                "label": label,
                "severity": severity,
                "source_data_identifier": finding["subjectUid"],
                "cef": finding
            }]
        }
        return container_json

    def _get_findings(self, action_result=ActionResult({}), **kwargs):
        """
        Adds a list of findings to the action_result data. Accepts same parameters as 'get_findings' action
        """
        params = {
            "page": 1,
            "limit": kwargs.get("limit", 100)
        }
        if kwargs.get("finding_uid"):
            params["uid"] = kwargs["finding_uid"]
        if kwargs.get("since"):
            # the 'since' parameter does not include time information, only the date
            params["since"] = dateutil.parser.isoparse(kwargs["since"]).strftime("%Y-%m-%d")
        if kwargs.get("status"):
            params["status"] = kwargs["status"]
        if kwargs.get("severity"):
            params["severity"] = kwargs["severity"]
        if kwargs.get("client_id"):
            params["clientId"] = kwargs["client_id"]

        subject_uid = kwargs.get("subject_uid")

        # response is paginated, so loop to get all findings
        findings = []
        while True:
            ret_val, response = self._make_rest_call(
                "/findings",
                action_result,
                params=params,
                timeout=10
            )

            if phantom.is_fail(ret_val):
                return RetVal(phantom.APP_ERROR, [])
            elif not response["data"]:
                # response will be empty after all pages are read
                break
            else:
                params["page"] += 1

            for finding in response["data"]:
                findings.extend(self._parse_finding_json(finding))

        # filter findings by subject_uid if that parameter was provided, else just return all the findings
        findings = [f for f in findings if f["subjectUid"] == subject_uid] if subject_uid else findings
        return RetVal(phantom.APP_SUCCESS, findings)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to Bishop Fox")

        # make rest call
        ret_val, response = self._make_rest_call(
            "/findings",
            action_result
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            self.save_progress("Test Connectivity Failed.")
            self.save_progress(action_result.get_message())
            return action_result.get_status()

        # Return success
        self.save_progress("Successfully connected to {0}".format(self._base_url))
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS, "Test Connectivity Passed")

    def _handle_get_findings(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the "param" dictionary
        ret_val, findings = self._get_findings(action_result=action_result, **param)

        if phantom.is_fail(ret_val):
            # action failed, this shoudl already be captured in the action result
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(findings)

        # Add a dictionary that is made up of the most important values from data into the summary
        action_result.update_summary({
            "total_findings": len(findings),
        })

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_status(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the "param" dictionary

        # Required values can be accessed directly
        finding_uid = param["finding_uid"]
        subject_uid = param["subject_uid"]
        status = param["status"]

        endpoint = "/findings/{0}/subjects/{1}/status".format(finding_uid, subject_uid)

        data = {
            "status": consts.STATUS_CODES[status]
        }

        # Optional values should use the .get() function
        # optional_parameter = param.get("optional_parameter", "default_value")

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint,
            action_result,
            method="put",
            json=data
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        data = [self._parse_subject_json(subj, finding_uid) for subj in response]
        action_result.add_data(data)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_client_id(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the "param" dictionary

        # Required values can be accessed directly
        finding_uid = param["finding_uid"]
        subject_uid = param["subject_uid"]
        client_id = param["client_id"]

        endpoint = "/findings/{0}/subjects/{1}/clientid".format(finding_uid, subject_uid)

        data = {
            "clientId": client_id
        }

        # Optional values should use the .get() function
        # optional_parameter = param.get("optional_parameter", "default_value")

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint,
            action_result,
            method="put",
            json=data
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        data = [self._parse_subject_json(subj, finding_uid) for subj in response]
        action_result.add_data(data)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_client_note(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the "param" dictionary

        # Required values can be accessed directly
        finding_uid = param["finding_uid"]
        subject_uid = param["subject_uid"]
        client_note = param["client_note"]

        endpoint = "/findings/{0}/subjects/{1}/clientnote".format(finding_uid, subject_uid)

        data = {
            "clientNote": client_note
        }

        # Optional values should use the .get() function
        # optional_parameter = param.get("optional_parameter", "default_value")

        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint,
            action_result,
            method="put",
            json=data
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        data = [self._parse_subject_json(subj, finding_uid) for subj in response]
        action_result.add_data(data)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCCESS)

    def _handle_on_poll(self, param):
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        action_params = {}
        last_ingest_date = self._state.get("last_ingest_date")

        if not self.is_poll_now():
            action_params["status"] = "new"

            if last_ingest_date:
                action_params["since"] = last_ingest_date

        self.save_progress("Retrieving latest findings...")

        ret_val, findings = self._get_findings(action_result=action_result, **action_params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress("Retrieved {0} findings".format(len(findings)))

        if self.is_poll_now():
            container_limit = min(param.get("container_count", 100), len(findings))
            findings = findings[:container_limit]
            self.save_progress("Only ingesting {0} finding(s)".format(len(findings)))
        else:
            self._state["last_ingest_date"] = str(datetime.now().isoformat())

        # Ingest findings here
        for finding in findings:
            container_json = self._build_container_json(finding)
            ret_val, msg, container_id = self.save_container(container_json)

            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, msg)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        elif action_id == "get_findings":
            ret_val = self._handle_get_findings(param)

        elif action_id == "update_status":
            ret_val = self._handle_update_status(param)

        elif action_id == "update_client_id":
            ret_val = self._handle_update_client_id(param)

        elif action_id == "update_client_note":
            ret_val = self._handle_update_client_note(param)

        elif action_id == "on_poll":
            ret_val = self._handle_on_poll(param)

        else:
            ret_val = phantom.APP_ERROR

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
        required_config_name = config["required_config_name"]

        # Optional values should use the .get() function
        optional_config_name = config.get("optional_config_name")
        """

        self._api_base_url = config["api_base_url"]
        self._auth_token_url = config["auth_token_url"]

        self._base_url = "{0}/orgs/{1}".format(self._api_base_url, config["org_id"])

        ret_val, auth_token = self._get_auth_token()

        # Initialize the requests session that will be used for rest requests
        self._request_session = requests.Session()
        self._request_session.verify = config.get("verify_server_cert", True)
        self._request_session.headers.update({
            "Authorization": "Bearer {0}".format(auth_token)
        })

        # Use the retry adapter to retry requests based on certain status codes
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[408, 429, 500, 502, 503, 504]
        )
        retry_adapter = HTTPAdapter(max_retries=retry)
        self._request_session.mount("http://", retry_adapter)
        self._request_session.mount("https://", retry_adapter)

        return ret_val

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        self._request_session.close()
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
            login_url = BishopFoxConnector._get_phantom_base_url() + "/login"

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

        connector = BishopFoxConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
