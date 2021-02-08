from __future__ import print_function, unicode_literals
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import requests
from requests.auth import HTTPBasicAuth
import json
from datetime import datetime, timedelta
import dateutil.parser
from subprocess import Popen, PIPE
from virtualsecurityoperationscenter_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class VirtualSecurityOperationsCenterConnector(BaseConnector):
    def __init__(self):
        super(VirtualSecurityOperationsCenterConnector, self).__init__()
        self._server = None
        self._user = None
        self._password = None
        self._customer_id = None

    def _process_json_response(self, r, action_result):
        """Process JSON responses from vSOC API"""
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to parse JSON response. Error: {0}".format(str(e)),
                ),
                None,
            )

        if 200 <= r.status_code < 399:
            self.debug_print("Request Body")
            self.debug_print(r.request.body)
            self.debug_print("Request Headers")
            self.debug_print(r.request.headers)
            self.debug_print("Response Headers")
            self.debug_print(r.headers)
            self.debug_print("Response Body")
            self.debug_print(r.text)
            return RetVal(phantom.APP_SUCCESS, resp_json)
        else:
            message = "Response Code: {0} Data: {1}".format(
                r.status_code, r.text.replace("{", "{{").replace("}", "}}")
            )
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        """Process responses from vSOC API"""
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)
        else:
            message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace("{", "{{").replace("}", "}}")
            )
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_curl_put_call(self, action_result, endpoint, body):
        url = f"https://{self._server}/rest{endpoint}?format=json"
        command = [
            "curl",
            "-X",
            "PUT",
            "--header",
            "'accept: application/json'",
            "--header",
            "'content-type: application/json'",
            "--user",
            f"{self._username}:{self._password}",
            "--data",
            f"'{body}'",
            f"{url}",
        ]
        self.debug_print(" ".join(command))
        p = Popen((" ".join(command)), stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
        output, err = p.communicate()
        if p.returncode != 0:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Error Curling server"),
                None,
            )
        else:
            self.debug_print(output)
            return RetVal(
                phantom.APP_SUCCESS,
                json.loads(output.decode("latin-1", errors="replace")),
            )

    def _make_rest_call(self, action_result, endpoint, method, body=None, **kwargs):
        """Makes HTTP requests to vSOC API"""
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if "headers" in kwargs:
            headers.update(kwargs.get("headers"))
            kwargs.pop("headers", None)
        auth = HTTPBasicAuth(self._username, self._password)
        url = f"http://{self._server}/rest{endpoint}"
        try:
            if body is not None:
                r = (requests.request)(
                    method, url, auth=auth, headers=headers, data=body, **kwargs
                )
            else:
                r = (requests.request)(
                    method, url, auth=auth, headers=headers, **kwargs
                )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e)),
                ),
                None,
            )

        return self._process_response(r, action_result)

    def _retrieve_ticket(self, action_result, id):
        """Retrieve an individual ticket from the vSOC API"""
        params = {
            "format": "json",
            "customerId": self._customer_id,
            "maxWorklogEntryCount": 100,
            "populate": "true",
        }
        if self._customer_id is not None:
            params["customerId"] = self._customer_id
        ret_val, ticket = self._make_rest_call(
            action_result, VSOC_TICKET_ENDPOINT.format(id=id), "GET", params=params
        )
        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            self.debug_print(message)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Could not retrieve ticket: {message}"
                ),
                None,
            )
        else:
            return (ret_val, ticket)

    def _retrieve_tickets(self, action_result, since=None, limit=None):
        """Retrieves a collection of tickets from the vSOC API"""
        params = {"format": "json", "maxWorklogEntryCount": 100, "populate": "true"}
        if self._customer_id is not None:
            params["customerId"] = self._customer_id
        if since is not None:
            date_range = "<start>{}</start>".format(since.isoformat())
            self.debug_print(date_range)
            params["lastModifiedOnRange"] = date_range
        if limit is not None:
            params["limit"] = limit
        ret_val, response = self._make_rest_call(
            action_result, VSOC_TICKETS_ENDPOINT, "GET", params=params
        )
        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            self.debug_print(message)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Could not retrieve tickets: {message}"
                ),
                None,
            )
        else:
            tickets = response["items"]
            return (ret_val, tickets)

    def _put_ticket(self, action_result, ticket):
        # Update a vSOC ticket
        # This needs to be run via cURL since vSOC API does not work
        # on this endpoint for python-based HTTP requests

        ticket_json = json.dumps(ticket, indent=4, sort_keys=True)
        self.debug_print(ticket_json)
        ret_val, updated_ticket = self._make_curl_put_call(
            action_result,
            VSOC_TICKET_ENDPOINT.format(id=(ticket["id"])),
            body=ticket_json,
        )
        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            self.debug_print(message)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, f"Could not update ticket: {message}"
                ),
                None,
            )
        else:
            return (ret_val, updated_ticket)

    def _update_ticket_artifact(self, container_id, updated_artifact):
        search_url = "{0}rest/artifact".format(self.get_phantom_base_url())
        params = {
            "_filter_container": container_id,
            "_filter_label": '"{}"'.format(VSOC_TICKET_ARTIFACT_LABEL),
        }
        try:
            r = requests.get(search_url, verify=False, params=params)
            resp_json = r.json()
            if len(resp_json["data"]) > 0:
                artifact_id = resp_json["data"][0]["id"]
                update_url = "{}rest/artifact/{}".format(
                    self.get_phantom_base_url(), artifact_id
                )
                r = requests.post(update_url, verify=False, json=updated_artifact)
                resp_json = r.json()
            return
        except Exception as e:
            self.debug_print("Unable to update incident artifact: ", e)
            return

        return artifact_id

    def _search_ticket_container(self, ticket):
        """Find the ticket container if it exists. Adapted from Jira App"""
        ticket_id = ticket[VSOC_TICKET_KEY]
        url = '{0}rest/container?_filter_source_data_identifier="{1}"&_filter_asset={2}'.format(
            self.get_phantom_base_url(), ticket_id, self.get_asset_id()
        )
        self.debug_print(url)
        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            self.debug_print("Unable to query vSOC ticket container: ", e)
            return

        if resp_json.get("count", 0) <= 0:
            self.debug_print("No container matched")
            return
        else:
            try:
                container_id = resp_json.get("data", [])[0]["id"]
                self.debug_print(f"Found container: {container_id}")
            except Exception as e:
                self.debug_print("Container results are not proper: ", e)
                return

            return container_id

    def _gen_ticket_container_title(self, ticket):
        primary = ticket[VSOC_TICKET_KEY]
        secondary = ticket.get("issueDescription")
        attack_name = ticket.get("attackName")
        if attack_name is not None:
            if attack_name != "N/A":
                secondary = attack_name
        return "{} - {}".format(primary, secondary)

    def _create_ticket_container_json(self, ticket):
        ticket_container = {
            "name": self._gen_ticket_container_title(ticket),
            "label": self.get_config().get("ingest", {}).get("container_label"),
            "source_data_identifier": ticket[VSOC_TICKET_KEY],
            "description": ticket["description"],
            "data": json.dumps(ticket),
        }
        return ticket_container

    def _save_ticket_container(self, ticket):
        """Create or update a ticket container."""
        container_id = self._search_ticket_container(ticket)
        if container_id:
            ret_val = self._update_ticket_container(container_id, ticket)
            if phantom.is_fail(ret_val):
                return phantom.APP_ERROR
            else:
                return phantom.APP_SUCCESS
        ticket_container = self._create_ticket_container_json(ticket)
        ret_val, message, container_id = self.save_container(ticket_container)
        if not ret_val:
            self.debug_print("Could not save container")
            return phantom.APP_ERROR
        else:
            ticket_artifacts = self._create_ticket_artifacts(
                ticket, container_id, extract_worklog=(self._worklog_artifacts)
            )
            ret_val, message, artifact_ids = self.save_artifacts(ticket_artifacts)
            if not ret_val:
                self.debug_print("Could not save container artifacts")
                return phantom.APP_ERROR
            return phantom.APP_SUCCESS

    def _create_ticket_artifacts(self, ticket, container_id, extract_worklog=False):
        artifacts = []
        ticket_artifact = {
            "container_id": container_id,
            "name": ticket[VSOC_TICKET_KEY],
            "label": VSOC_TICKET_ARTIFACT_LABEL,
            "source_data_identifier": ticket[VSOC_TICKET_KEY],
            "cef": {
                "issue": ticket.get("issue"),
                "queue": ticket.get("queue"),
                "rating": ticket.get("rating"),
                "status": ticket.get("status"),
                "priority": ticket.get("priority"),
                "issueDescription": ticket.get("issueDescription"),
                "issueType": ticket.get("issueType"),
                "issueTypeExtended": ticket.get("issueTypeExtended"),
                "securityAnalyst": ticket.get("securityAnalyst"),
                "createdOn": ticket.get("createdOn"),
                "lastModifiedOn": ticket.get("lastModifiedOn"),
                "description": ticket.get("description"),
            },
        }
        cef_mapping = [
            ("sourceIp", "sourceAddress"),
            ("sourceDnsName", "sourceDnsDomain"),
            ("destinationIp", "destinationAddress"),
            ("destinationDnsName", "destinationDnsDomain"),
            ("rawEventData", "rawEventData"),
        ]
        for source, target in cef_mapping:
            if ticket.get(source) is not None:
                ticket_artifact["cef"][target] = ticket[source]

        artifacts.append(ticket_artifact)
        if extract_worklog and ticket.get("worklog") and len(ticket["worklog"].get("entries", [])) > 0:
            for entry in ticket["worklog"]["entries"]:
                entry_artifact = {
                    "container_id": container_id,
                    "name": entry["timestamp"],
                    "source_data_identifier": "{}{}".format(
                        entry["timestamp"], entry["username"]
                    ),
                    "label": VSOC_WORKLOG_ENTRY_ARTIFACT_LABEL,
                    "cef": {
                        "text": entry["text"],
                        "timestamp": entry["timestamp"],
                        "username": entry["username"],
                        "type": entry["type"],
                    },
                }
                artifacts.append(entry_artifact)

        return artifacts

    def _update_ticket_container(self, container_id, new_ticket):
        """Update an existing ticket container with new ticket information. Adapted from Jira App"""
        self.debug_print(f"Updating existing container {container_id}")
        updated_container = self._create_ticket_container_json(new_ticket)
        url = "{0}rest/container/{1}".format(self.get_phantom_base_url(), container_id)
        try:
            r = requests.post(url, data=(json.dumps(updated_container)), verify=False)
            resp_json = r.json()
        except Exception as e:
            self.debug_print(e)
            self.debug_print("Error while updating the container")
            return phantom.APP_ERROR

        if r.status_code != 200 or resp_json.get("failed"):
            self.debug_print(
                "Error while updating the container. Error is: ",
                resp_json.get("failed"),
            )
            action_result.set_status(
                phantom.APP_ERROR,
                "Error occurred while updating the container for the issue key: {0}. Error message: {1}".format(
                    new_ticket[VSOC_TICKET_KEY], resp_json.get("failed")
                ),
            )
            return phantom.APP_ERROR
        else:
            artifacts = self._create_ticket_artifacts(
                new_ticket, container_id, extract_worklog=(self._worklog_artifacts)
            )
            self.debug_print(
                "Number of artifact on updating ticket {}".format(len(artifacts))
            )
            ticket_artifact = artifacts.pop(0)
            artifact_id = self._update_ticket_artifact(container_id, ticket_artifact)
            self.debug_print("Updated ticket artifact: {}".format(artifact_id))
            if len(artifacts) > 0:
                ret_val, message, artifact_ids = self.save_artifacts(artifacts)
            return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        """Handle test connectivity action"""
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Testing connectivity to Ticket resource")
        params = {"format": "json", "limit": 1}
        if self._customer_id is not None:
            params["customerId"] = self._customer_id
        ret_val, response = self._make_rest_call(
            action_result, VSOC_TICKETS_ENDPOINT, "GET", params=params
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            self.save_progress(action_result.get_message())
            return action_result.get_status()
        else:
            self.save_progress("Test Connectivity Passed")
            return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):
        """Handle on call action"""
        action_result = self.add_action_result(ActionResult(dict(param)))
        last_run = self._state.get("last_run")
        self.debug_print("Last Run: {}".format(last_run))
        max_tickets = None
        backfill = datetime.now() - timedelta(days=VSOC_BACKFILL_DAYS)
        if self.is_poll_now():
            self.debug_print("Run Mode: Poll Now")
            max_tickets = param.get(phantom.APP_JSON_CONTAINER_COUNT)
            last_run = backfill
        else:
            if last_run is None:
                self.debug_print("Run Mode: First Scheduled Poll")
                last_run = backfill
            else:
                self.debug_print("Run Mode: Scheduled Poll")
                last_run = dateutil.parser.isoparse(last_run)
        tickets = []
        try:
            ret_val, tickets = self._retrieve_tickets(
                action_result, last_run, max_tickets
            )
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, "Error while fetching tickets: {}".format(str(e)))

        self.debug_print(f"Total tickets fetched: {len(tickets)}")
        self.save_progress(f"Total tickets fetched: {len(tickets)}")
        for ticket in tickets:
            self._save_ticket_container(ticket)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_ticket(self, param):
        """Handle get ticket action"""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))
        id = param["id"]
        ret_val, ticket = self._retrieve_ticket(action_result, id)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        else:
            action_result.add_data(ticket)
            return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_ticket(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))
        id = param["id"]
        try:
            update_fields = json.loads(param["update_fields"])
        except:
            return action_result.set_status(
                phantom.APP_ERROR, "Could not parse update_fields into JSON format"
            )
        else:
            ret_val, ticket = self._retrieve_ticket(action_result, id)
            if phantom.is_fail(ret_val):
                message = action_result.get_message()
                return action_result.set_status(
                    phantom.APP_ERROR, f"Error updating ticket: {message}"
                )
            else:
                ticket.update(update_fields)
                ret_val, updated_ticket = self._put_ticket(action_result, ticket)
                if phantom.is_fail(ret_val):
                    message = action_result.get_message()
                    return action_result.set_status(
                        phantom.APP_ERROR, f"Error updating ticket: {message}"
                    )
                action_result.add_data(updated_ticket)
                return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_worklog_entry(self, param):
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))
        ticket_id = param["id"]
        worklog_text = param["text"]
        ret_val, ticket = self._retrieve_ticket(action_result, ticket_id)
        self.debug_print("Fetched_Ticket")
        self.debug_print(ticket)
        if phantom.is_fail(ret_val) or ticket.get("id") is None:
            message = action_result.get_message()
            return action_result.set_status(
                phantom.APP_ERROR, f"Error updating ticket: {message}"
            )
        else:
            worklog_entry = {"text": worklog_text}
            ticket["worklog"]["addition"] = worklog_entry
            ret_val, updated_ticket = self._put_ticket(action_result, ticket)
            if phantom.is_fail(ret_val):
                message = action_result.get_message()
                return action_result.set_status(
                    phantom.APP_ERROR, f"Error updating ticket: {message}"
                )
            action_result.add_data(updated_ticket)
            return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        self.debug_print("action_id", self.get_action_identifier())
        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)
        elif action_id == "on_poll":
            ret_val = self._handle_on_poll(param)
        elif action_id == "get_ticket":
            ret_val = self._handle_get_ticket(param)
        elif action_id == "update_ticket":
            ret_val = self._handle_update_ticket(param)
        elif action_id == "create_worklog_entry":
            ret_val = self._handle_create_worklog_entry(param)
        return ret_val

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()
        self._server = config["server"]
        self._username = config["username"]
        self._password = config["password"]
        self._customer_id = config.get("customer_id")
        self._worklog_artifacts = config["worklog_artifacts"]
        return phantom.APP_SUCCESS

    def finalize(self):
        new_state = {"last_run": datetime.now().isoformat()}
        self.save_state(new_state)
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
    if username is not None:
        if password is None:
            import getpass

            password = getpass.getpass("Password: ")
    if username and password:
        try:
            login_url = (
                VirtualSecurityOperationsCenterConnector._get_phantom_base_url() + "/login"
            )
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

    with open(args.input_test_json) as (f):
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = VirtualSecurityOperationsCenterConnector()
        connector.print_progress_message = True
        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps((json.loads(ret_val)), indent=4))
    exit(0)


if __name__ == "__main__":
    main()
# okay decompiling virtualsecurityoperationscenter_connector.pyc
