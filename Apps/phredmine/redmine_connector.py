# File: redmine_connector.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.rules as Rules

# Usage of the consts file is recommended
from redmine_consts import *
import requests
import json
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import dateutil.parser


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class RedmineConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(RedmineConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._username = None
        self._verify_ssl = None
        self._password = None
        self._project_id = None
        self._custom_fields_list = None

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

    # HTTP Utility Methods

    def _process_empty_response(self, response, action_result):
        if response.status_code in (200, 201, 204):
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ),
            None,
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
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text
        )

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
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

            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)
                ),
                resp_json,
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                auth=(self._username, self._password),
                verify=config.get("verify_server_cert", False),
                **kwargs,
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Error Connecting to server. Details: {0}".format(str(e)),
                ),
                resp_json,
            )

        return self._process_response(r, action_result)

    # Action Utility Methods

    def _save_ticket_container(self, action_result, ticket):
        """
        Save a ticket retrieved from redmine to a corresponding phantom container.
        If a container already exists, it is updated.
        """

        container_id = self._search_ticket_container(ticket)

        if container_id:
            self.debug_print("Updating existing ticket container")
            ret_val = self._update_ticket_container(container_id, ticket)
            ticket_artifacts = self._create_ticket_artifacts(ticket, container_id)
            self.save_artifacts(ticket_artifacts)

        ticket_container = self._create_ticket_container_json(ticket)
        ret_val, message, container_id = self.save_container(ticket_container)

        if not ret_val:
            self.debug_print("Could not save new ticket container")
            return RetVal(phantom.APP_ERROR)
        else:
            ticket_artifacts = self._create_ticket_artifacts(ticket, container_id)
            self.debug_print(len(ticket_artifacts))
            self.save_artifacts(ticket_artifacts)
            return RetVal(phantom.APP_SUCCESS)

    def _update_ticket_container(self, container_id, ticket):
        """Update an existing phantom container with new ticket information"""

        updated_container = self._create_ticket_container_json(ticket)
        url = "{0}rest/container/{1}".format(self.get_phantom_base_url(), container_id)

        try:
            requests.post(url, data=(json.dumps(updated_container)), verify=False)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.debug_print(f"Error while updating the container: {err}")

    def _search_ticket_container(self, ticket):
        "Find the phantom container corresponding to the redmine ticket"

        ticket_id = ticket[REDMINE_TICKET_JSON_ID]

        url = '{0}rest/container?_filter_source_data_identifier="{1}"&_filter_asset={2}'.format(
            self.get_phantom_base_url(), ticket_id, self.get_asset_id()
        )
        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            self.debug_print("Unable to query Phantom for containers: ", e)
            return

        if resp_json.get("count", 0) <= 0:
            self.debug_print("No container matched")
            return
        else:
            try:
                container_id = resp_json.get("data", [])[0]["id"]
                self.debug_print(f"Found container id:{container_id}")
            except Exception as e:
                self.debug_print("Container results are not proper", e)
                return

            return container_id

    def _gen_ticket_container_title(self, ticket):
        """Generate title for the new phantom container based on ticket information"""

        primary = ticket[REDMINE_TICKET_JSON_ID]
        secondary = ticket.get("subject")
        return "{} - {}".format(primary, secondary)

    def _create_ticket_container_json(self, ticket):
        """Creates a new phantom container based on ticket information"""
        ticket_container = {
            "name": self._gen_ticket_container_title(ticket),
            "label": self.get_config().get("ingest", {}).get("container_label"),
            "source_data_identifier": ticket[REDMINE_TICKET_JSON_ID],
            "description": ticket["description"],
            "data": json.dumps(ticket),
        }
        return ticket_container

    def _create_ticket_artifacts(self, ticket, container_id):
        """Creates artifacts for a given container based on ticket information"""

        artifacts = []

        ticket_updated_on = ticket["updated_on"]
        ticket_artifact = {
            "container_id": container_id,
            "name": f"ticket_fields_{ticket_updated_on}",
            "label": REDMINE_TICKET_ARTIFACT_LABEL,
            "source_data_identifier": ticket[REDMINE_TICKET_JSON_ID],
        }

        ticket_artifact_cef = {}
        ticket_artifact_cef[REDMINE_TICKET_JSON_PROJECT_ID] = ticket["project"]["id"]
        ticket_artifact_cef[REDMINE_TICKET_JSON_PROJECT_NAME] = ticket["project"][
            "name"
        ]

        ticket_artifact_cef[REDMINE_TICKET_JSON_TRACKER_ID] = ticket["tracker"]["id"]
        ticket_artifact_cef[REDMINE_TICKET_JSON_TRACKER_NAME] = ticket["tracker"][
            "name"
        ]

        ticket_artifact_cef[REDMINE_TICKET_JSON_STATUS_ID] = ticket["status"]["id"]
        ticket_artifact_cef[REDMINE_TICKET_JSON_STATUS_NAME] = ticket["status"]["name"]

        ticket_artifact_cef[REDMINE_TICKET_JSON_PRIORITY_ID] = ticket["priority"]["id"]
        ticket_artifact_cef[REDMINE_TICKET_JSON_PRIORITY_NAME] = ticket["priority"][
            "name"
        ]

        ticket_artifact_cef[REDMINE_TICKET_JSON_AUTHOR_ID] = ticket["author"]["id"]
        ticket_artifact_cef[REDMINE_TICKET_JSON_AUTHOR_NAME] = ticket["author"]["name"]

        ticket_artifact_cef[REDMINE_TICKET_JSON_SUBJECT] = ticket["subject"]
        ticket_artifact_cef[REDMINE_TICKET_JSON_DESCRIPTION] = ticket["description"]

        ticket_artifact_cef[REDMINE_TICKET_JSON_CREATED_ON] = ticket["created_on"]
        ticket_artifact_cef[REDMINE_TICKET_JSON_UPDATED_ON] = ticket["updated_on"]
        ticket_artifact_cef[REDMINE_TICKET_JSON_CLOSED_ON] = ticket.get("closed_on")

        if self._custom_fields_list and ticket.get("custom_fields"):
            for custom_field in ticket["custom_fields"]:
                if custom_field["name"] in self._custom_fields_list:
                    ticket_artifact_cef[custom_field["name"]] = custom_field["value"]

        ticket_artifact["cef"] = ticket_artifact_cef

        artifacts.append(ticket_artifact)

        return artifacts

    def _retrieve_tickets(self, action_result, since, limit=100):
        """Retrieves tickets from Redmine that recently have been updated"""
        date = since.strftime("%Y-%m-%dT%H:%M:%S")

        qs = {"updated_on": f">={date}", "limit": limit, "include": "attachments"}

        ret_val, response = self._make_rest_call(
            "/issues.json", action_result, method="get", params=qs
        )

        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            return (
                RetVal(
                    action_result.set_status(phantom.APP_ERROR),
                    f"Could not retrieve tickets: {message}",
                ),
                None,
            )

        return ret_val, response["issues"]

    def _retrieve_ticket(self, action_result, id):
        """Retrieves an individual ticket from Redmine"""

        ret_val, response = self._make_rest_call(
            f"/issues/{id}.json", action_result, headers=None
        )
        if phantom.is_fail(ret_val):
            return action_result.set_status(
                phantom.APP_ERROR, "Could not retrieve ticket"
            )
        return ret_val, response

    def _retrieve_enumeration_id(self, action_result, enum, enum_key, endpoint):
        """Given an enum string and a Redmine enumeration, retrieve the corresponding id from the matching endpoint"""

        ret_val, response = self._make_rest_call(
            endpoint, action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.set_status(
                phantom.APP_ERROR, f"Could not retrieve definitions on {endpoint}"
            )

        enum_values = response[enum_key]
        enum_obj = next(
            (s for s in enum_values if s["name"].lower() == enum.lower()), None
        )

        if not enum_obj:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Could not find mapping for provided value on {endpoint}",
            )

        return enum_obj["id"]

    def _upload_vault_file(self, action_result, vault_id):
        """Uploads a file from vault to Redmine and returns a dictionary suitable for attaching the uploaded file to an existing ticket"""

        try:
            self.debug_print("Rules.vault_info start")
            success, message, vault_info = Rules.vault_info(vault_id=vault_id)
            self.debug_print(
                "Rules.vault_info results: success: {}, message: {}, info: {}".format(
                    success, message, vault_info
                )
            )
        except requests.exceptions.HTTPError:
            error_message = "Invalid Vault ID: %s" % (vault_id)
            return action_result.set_status(phantom.APP_ERROR, error_message)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Error opening file. {}".format(err)
            )

        try:
            vault_info = list(vault_info)
            file_info = vault_info[0]
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR,
                "Error occurred while getting 'File Info'. {}".format(err),
            )

        file_path = file_info["path"]

        with open(file_path, "rb") as f:
            file_contents = f.read()

        ret_val, response = self._make_rest_call(
            "/uploads.json",
            action_result,
            params=None,
            method="post",
            headers={"Content-Type": "application/octet-stream"},
            data=file_contents,
        )

        if phantom.is_fail(ret_val):
            return action_result.set_status(
                phantom.APP_ERROR, "Could not upload attachment"
            )

        upload = {
            "token": response["upload"]["token"],
            "filename": file_info["name"],
            "content_type": file_info["mime_type"],
        }

        return upload

    # Action Handlers

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(
            "/my/account.json", action_result, params=None, headers=None
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.set_status(phantom.APP_ERROR, "Could not connect")

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):
        """
        Keep phantom containers up-to-date with data from redmine
        """

        # Add action result
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        last_run = self._state.get("last_run")
        max_tickets = None
        backfill = datetime.now() - timedelta(REDMINE_BACKFILL_DAYS)

        if self.is_poll_now():
            self.debug_print("Run Mode: Poll Now")
            max_tickets = param[phantom.APP_JSON_CONTAINER_COUNT]
            last_run = backfill
        else:
            if not last_run:
                self.debug_print("Run Mode: First Scheduled Poll")
                last_run = backfill
            else:
                self.debug_print("Run Mode: Scheduled Poll")
                last_run = dateutil.parser.isoparse(last_run)

        self.debug_print(f"Last Run: {last_run}")

        tickets = []
        try:
            ret_val, tickets = self._retrieve_tickets(
                action_result, last_run, max_tickets
            )
        except Exception as e:
            action_result.set_status(
                phantom.APP_ERROR, "Error while fetching tickets: {}".format(str(e))
            )

        self.debug_print(f"Total tickets fetched: {len(tickets)}")
        self.save_progress(f"Total tickets fetched: {len(tickets)}")

        for ticket in tickets:
            self._save_ticket_container(action_result, ticket)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_ticket(self, param):
        """Creates a new ticket on Redmine"""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Parameters
        subject = param["subject"]
        description = param["description"]
        priority = param.get("priority", None)
        tracker = param.get("tracker", None)
        custom_fields = param.get("custom_fields", "{}")

        payload = {
            "issue": {
                "project_id": self._project_id,
                "subject": subject,
                "description": description,
            }
        }

        try:
            parsed_custom_fields = json.loads(custom_fields)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Could not parse custom fields: {err}"
            )

        payload["issue"]["custom_fields"] = parsed_custom_fields

        if priority:
            payload["issue"]["priority_id"] = self._retrieve_enumeration_id(
                action_result,
                priority,
                "issue_priorities",
                "/enumerations/issue_priorities.json",
            )

        if tracker:
            payload["issue"]["tracker_id"] = self._retrieve_enumeration_id(
                action_result, tracker, "trackers", "/trackers.json"
            )

        ret_val, response = self._make_rest_call(
            "/issues.json",
            action_result,
            method="post",
            params=None,
            headers=None,
            json=payload,
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status(
                phantom.APP_ERROR, "Could not create ticket"
            )

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_ticket(self, param):
        """Updates a ticket bases on a provided JSON dictionary. Also allows attaching files from vault"""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Parameters
        id = param["id"]
        update_fields = param.get("update_fields", "{}")
        vault_id = param.get("vault_id", "")

        try:
            update_fields = json.loads(update_fields)
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, f"Could not parse update_fields into JSON: {err}"
            )

        payload = {"issue": {}}

        if len(update_fields) > 0:
            payload["issue"] = {**payload["issue"], **update_fields}

        if len(vault_id) > 0:
            upload = self._upload_vault_file(action_result, vault_id)
            payload["issue"]["uploads"] = [upload]

        ret_val, response = self._make_rest_call(
            f"/issues/{id}.json",
            action_result,
            params=None,
            method="put",
            headers={"Content-Type": "application/json"},
            json=payload,
        )

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Failed to update ticket")

        ret_val, response = self._retrieve_ticket(action_result, id)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Action Result
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_comment(self, param):
        """Creates a comment on an existing ticket"""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Parameters
        id = param["id"]
        comment = param["comment"]

        payload = {"issue": {"notes": comment}}

        ret_val, response = self._make_rest_call(
            f"/issues/{id}.json",
            action_result,
            method="put",
            params=None,
            headers=None,
            json=payload,
        )

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, f"Could not add comment to ticket {id}")

        ret_val, response = self._retrieve_ticket(action_result, id)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Action Result
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_tickets(self, param):
        """Retrieves a list of tickets"""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Parameters
        query = param.get("query", "")
        start_index = param.get("start_index", 0)
        max_results = param.get("max_results", 100)

        params = {
            "offset": start_index,
            "limit": max_results,
            "project_id": self._project_id
        }

        ret_val, response = self._make_rest_call(
            f"/issues.json{query}", action_result, params=params, headers=None
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Action Result
        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['num_tickets'] = len(response['issues'])
        summary['total_tickets'] = response['total_count']
        summary['offset'] = response['offset']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_ticket(self, param):
        """Get information about a single ticket from Redmine"""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Parameters
        id = param["id"]

        ret_val, response = self._retrieve_ticket(action_result, id)
        if phantom.is_fail(ret_val):
            return action_result.set_status(
                phantom.APP_ERROR, f"Could not get ticket {id}"
            )

        # Action Result
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_ticket(self, param):
        """Deletes a ticket in Redmine"""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Parameters
        id = param["id"]

        ret_val, response = self._make_rest_call(
            f"/issues/{id}.json",
            action_result,
            method="delete",
            params=None,
            headers=None,
        )

        if phantom.is_fail(ret_val):
            return action_result.set_status(
                phantom.APP_ERROR, f"Could not delete ticket {id}"
            )

        # Action Result
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_set_status(self, param):
        """Updates a tickets status in Redmin"""
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Parameters
        id = param["id"]
        status = param["status"]
        comment = param.get("comment", "")

        # Retrieve status_id based on provided status string
        status_id = self._retrieve_enumeration_id(
            action_result,
            status,
            REDMINE_TICKET_STATUSES_KEY,
            REDMINE_TICKET_STATUSES_ENDPONT,
        )
        if phantom.is_fail(status_id):
            return action_result.get_status()

        payload = {"issue": {"status_id": status_id, "notes": comment}}

        ret_val, response = self._make_rest_call(
            f"/issues/{id}.json",
            action_result,
            method="put",
            params=None,
            headers=None,
            json=payload,
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, response = self._retrieve_ticket(action_result, id)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Action Result
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        elif action_id == "create_ticket":
            ret_val = self._handle_create_ticket(param)

        elif action_id == "update_ticket":
            ret_val = self._handle_update_ticket(param)

        elif action_id == "add_comment":
            ret_val = self._handle_add_comment(param)

        elif action_id == "list_tickets":
            ret_val = self._handle_list_tickets(param)

        elif action_id == "get_ticket":
            ret_val = self._handle_get_ticket(param)

        elif action_id == "delete_ticket":
            ret_val = self._handle_delete_ticket(param)

        elif action_id == "set_status":
            ret_val = self._handle_set_status(param)

        elif action_id == "on_poll":
            ret_val = self._on_poll(param)

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

        self._base_url = config.get("base_url")
        self._username = config.get("username")
        self._password = config.get("password")
        self._project_id = config.get("project_id")

        if config.get("custom_fields"):
            self._custom_fields_list = config.get("custom_fields").split(",")

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        #
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

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = RedmineConnector._get_phantom_base_url() + "/login"

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

        connector = RedmineConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
