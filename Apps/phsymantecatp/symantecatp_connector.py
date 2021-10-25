# File: symantecatp_connector.py
#
# Copyright (c) 2017-2019 Splunk Inc.
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
from datetime import datetime
import json
import os
import inspect
import base64
import hashlib
import time
import requests

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
from symantecatp_consts import *


class SymantecatpConnector(BaseConnector):
    def __init__(self):

        super(SymantecatpConnector, self).__init__()
        self._client_details = None
        self._verify_server_cert_status = None
        self._base_url = None
        self._poll_now_ingestion_span = None
        self._first_scheduled_ingestion_limit = None
        self._first_scheduled_ingestion_span = None
        self._token = None
        self._state_file_path = None
        self._state = None
        return

    # Overriding sha256 validation for symantecatp
    # to allow (',') separated sha256 hashes as parameter
    def _validate_sha256(self, param):

        # Strip out white spaces and then split the string with (',') delimiter to obtain list
        hash_list = param.split(',')
        hash_list = [file_hash.strip() for file_hash in hash_list]
        # Validates whether all the hash are valid sha256
        return all([phantom.is_sha256(file_hash) for file_hash in hash_list])

    def initialize(self):

        config = self.get_config()

        # Making a list of parameters of server details and client_details
        self._client_details = [config[SYMANTEC_CONFIG_CLIENT_ID], config[SYMANTEC_CONFIG_CLIENT_SECRET]]
        self._verify_server_cert_status = config[SYMANTEC_CONFIG_SERVER_CERT]
        self._base_url = config[SYMANTEC_CONFIG_SERVER]
        self._poll_now_ingestion_span = int(config.get(SYMANTEC_CONFIG_POLL_NOW_INGESTION_SPAN,
                                                       SYMANTEC_DEFAULT_POLL_NOW_DAYS))
        self._first_scheduled_ingestion_limit = int(config.get(SYMANTEC_CONFIG_FIRST_SCHEDULED_INGESTION_LIMIT,
                                                               SYMANTEC_DEFAULT_FIRST_SCHEDULED_CONTAINER_COUNT))
        self._first_scheduled_ingestion_span = int(config.get(SYMANTEC_CONFIG_FIRST_SCHEDULED_INGESTION_SPAN,
                                                              SYMANTEC_DEFAULT_FIRST_SCHEDULED_DAYS))

        self._load_state()

        self.set_validator('sha256', self._validate_sha256)

        # return response_status
        return phantom.APP_SUCCESS

    # Loads the state of app stored in json file
    def _load_state(self):

        dirpath = os.path.dirname(inspect.getfile(self.__class__))
        asset_id = self.get_asset_id()
        self._state_file_path = '{0}/{1}_api_token.json'.format(dirpath, asset_id)
        self._state = {}
        response_status = phantom.APP_SUCCESS

        if os.path.isfile(self._state_file_path):
            try:
                with open(self._state_file_path, 'r') as state_file:
                    json_data = state_file.read()
                    self._state = json.loads(json_data)
                    self._token = self._state.get("token")
            except Exception as e:
                self.debug_print('In _load_state: Exception: {0}'.format(str(e)))
                response_status = phantom.APP_ERROR

            self.debug_print('Loaded state: ', self._state)

        return response_status

    # Generate new token based on the credentials provided
    # Token is valid for 60 minutes
    def _generate_api_token(self, action_result):

        encoded_client_details = base64.b64encode(":".join(self._client_details))

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'application/json',
                   'Authorization': 'Basic {}'.format(str(encoded_client_details))}
        payload = {'grant_type': 'client_credentials'}

        response_status, response = self._make_rest_call(SYMANTEC_TOKEN_ENDPOINT, action_result, headers=headers,
                                                         data=payload)

        if phantom.is_fail(response_status):
            return action_result.get_status()

        token = response.get("access_token")

        if not token:
            self.debug_print("Failed to generate token")
            return action_result.set_status(phantom.APP_ERROR, "Failed to generate token")

        # Saving the state of token to be used during subsequent actions
        self._state['token'] = self._token = token

        return phantom.APP_SUCCESS

    # Saves the state of app stored in json file
    def _save_state(self):

        self.debug_print('Saving state: ', self._state)
        try:
            with open(self._state_file_path, 'w+') as state_file:
                state_file.write(json.dumps(self._state))
        except Exception as e:
            self.debug_print("Error while saving token: {}".format(str(e)))

    # This method would generate a new token if not available
    # or existing token has expired
    def _make_rest_call_abstract(self, endpoint, action_result, data=None, params=None, auth_mode="Bearer",
                                 method="post"):

        # Use this object for make_rest_call
        # Final status of action_result would be determined
        # after retry if token expired
        intermediate_action_result = ActionResult()
        response = None

        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        # Generate new token if not available
        if not self._token:
            ret_code = self._generate_api_token(action_result)
            if phantom.is_fail(ret_code):
                return action_result.get_status(), response

        # Make rest call
        rest_ret_code, response = self._make_rest_call(endpoint, intermediate_action_result, headers,
                                                       data, params, auth_mode, method)

        # If token is invalid in case of api calls other than generate token, generate new token and retry
        if auth_mode != "Basic" and 'Detail: invalid_token' in str(intermediate_action_result.get_message()):
            ret_code = self._generate_api_token(action_result)
            if phantom.is_fail(ret_code):
                return action_result.get_status(), response

            # Retry the rest call with new token generated
            rest_ret_code, response = self._make_rest_call(endpoint, intermediate_action_result, headers, data, params,
                                                           auth_mode, method)

        # Assigning intermediate action_result to action_result,
        # since no further invocation required
        if phantom.is_fail(rest_ret_code):
            action_result.set_status(rest_ret_code, intermediate_action_result.get_message())
            return action_result.get_status(), response

        return phantom.APP_SUCCESS, response

    # Function which implements code to make API call to Symantec ATP Manager
    def _make_rest_call(self, endpoint, action_result, headers=None, data=None, params=None, auth_mode="Basic",
                        method="post"):

        response_data = None
        # Dictionary containing details of possible error codes in API Response
        error_dict = {
            SYMANTEC_BAD_REQUEST_ERROR_CODE: SYMANTEC_BAD_REQUEST_ERROR_MSG,
            SYMANTEC_FORBIDDEN_ERROR_CODE: SYMANTEC_FORBIDDEN_ERROR_MSG,
            SYMANTEC_REQUEST_TIMEOUT_ERROR_CODE: SYMANTEC_REQUEST_TIMEOUT_ERROR_MSG,
            SYMANTEC_INTERNAL_SERVER_ERROR_ERROR_CODE: SYMANTEC_INTERNAL_SERVER_ERROR_ERROR_MSG,
            SYMANTEC_REQUEST_TOO_LARGE_ERROR_CODE: SYMANTEC_REQUEST_TOO_LARGE_ERROR_MSG,
            SYMANTEC_NOT_FOUND_ERROR_CODE: SYMANTEC_NOT_FOUND_ERROR_MSG
        }

        # API used for generating token consist of Basic Authentication
        # All other APIs uses "Bearer {token}" as Authorization in header
        if auth_mode != "Basic":
            headers["Authorization"] = "{auth_mode} {token}".format(auth_mode=auth_mode, token=str(self._token))

        try:
            request_func = getattr(requests, method)

        except Exception as error:
            self.debug_print(str(error))
            # set the action_result status to error, the handler function
            # will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, str(error.message)), response_data

        try:
            response = request_func(self._base_url + endpoint, headers=headers, data=data, params=params,
                                    verify=self._verify_server_cert_status)

        except Exception as error:
            self.debug_print("Exception while making request: {}".format(str(error)))
            # set the action_result status to error, the handler function
            # will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, SYMANTEC_ERR_SERVER_CONNECTION, error.message), \
                response_data

        if response.status_code in error_dict.keys():
            self.debug_print(SYMANTEC_ERR_FROM_SERVER.format(status=response.status_code,
                                                             detail=error_dict[response.status_code]))
            # set the action_result status to error, the handler function
            # will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, SYMANTEC_ERR_FROM_SERVER, status=response.status_code,
                                            detail=error_dict[response.status_code]), response_data

        # Try parsing the json, even in the case of an HTTP error the data might
        # contain a json of details 'message'
        try:
            content_type = response.headers['content-type']
            if content_type.find('json') != -1:
                response_data = response.json()
            else:
                response_data = response.text
        except Exception as e:
            # r.text is guaranteed to be NON None, it will be empty,
            # but not None
            msg_string = SYMANTEC_ERR_JSON_PARSE.format(raw_text=response.text)
            self.debug_print(msg_string)
            # set the action_result status to error, the handler function
            # will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, msg_string, e), response_data

        if response.status_code == SYMANTEC_SUCCESS_API_CODE:
            return phantom.APP_SUCCESS, response_data

        # see if an error message is present
        if isinstance(response_data, dict):
            message = str(response_data.get('message', SYMANTEC_REST_RESP_OTHER_ERROR_MSG))
        else:
            message = response_data
        self.debug_print(SYMANTEC_ERR_FROM_SERVER.format(status=response.status_code, detail=message))

        # set the action_result status to error, the handler function
        # will most probably return as is
        return action_result.set_status(phantom.APP_ERROR, SYMANTEC_ERR_FROM_SERVER, status=response.status_code,
                                        detail=message), response_data

    # Function to test connectivity with Symantec ATP Manager
    # This action makes a request to generate a new token using the provided client credentials
    # If new token is generated action is successful else fail
    def _test_connectivity(self, param):

        action_result = ActionResult()

        self.save_progress(SYMANTEC_CONNECTION_TEST_MSG)

        response_status = self._generate_api_token(action_result)

        if phantom.is_fail(response_status):
            self.save_progress(SYMANTEC_CONNECTION_TEST_INVALID_URL_MSG.format(url=self._base_url))
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, SYMANTEC_CONNECTION_TEST_ERR_MSG)
            return action_result.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, SYMANTEC_CONNECTION_TEST_SUCC_MSG)

        return action_result.get_status()

    def _on_poll(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Getting optional parameters
        container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT, SYMANTEC_MAX_LIMIT))

        source_id = param.get("container_id")

        # Ignoring maximum artifacts count
        if self.is_poll_now():
            self.save_progress("Ignoring the maximum artifacts count")

        # Getting list of incidents according to the request parameters
        response_status, incident_list = self._get_incident_list(container_count, source_id, action_result, param)

        # Something went wrong
        if phantom.is_fail(response_status):
            return action_result.get_status()

        if incident_list:
            incident_uuids = [incident["uuid"] for incident in incident_list]

            # Getting list of incident related events according to the request parameters
            response_status, incident_events = self._get_event_list(incident_uuids, action_result)

            # Something went wrong
            if phantom.is_fail(response_status):
                return action_result.get_status()

            if incident_events:
                # Ingesting incidents and events as containers and artifacts respectively
                self._ingest_data(incident_list, incident_events)

        else:
            self.save_progress(SYMANTEC_NO_INCIDENTS_FOUND_MSG)

        # Setting first_run to false after first execution
        if self._state.get('first_run', True) and not self.is_poll_now():
            self._state['first_run'] = False

        return action_result.set_status(phantom.APP_SUCCESS)

    # This function would get the list of incidents
    # based on the time span and maximum incidents required
    def _get_incident_list(self, container_count, source_id, action_result, param):

        incident_list = []
        container_data_param = {"verb": "query"}

        # Variables indicating count and span in days pending for ingestion
        incidents_to_ingest_pending = None
        ingestion_span_days_pending = None
        # End Day starts with current day and fetches data in past
        end_day = 0
        current_time = time.time()

        # Poll Now
        if self.is_poll_now():
            incidents_to_ingest_pending = container_count
            total_incidents_to_ingest = container_count
            ingestion_span_days_pending = self._poll_now_ingestion_span
            # Get incident list matching the source_id
            if source_id:
                self.save_progress("Getting latest incident(s) from last {} day(s) for source ID(s) {}".format(
                    str(self._poll_now_ingestion_span),
                    str(source_id)
                ))
                # Source id can have multiple values ',' separated
                source_id_list = source_id.split(",")
                # Stripping white spaces
                source_id_list = [src_id.strip(' ') for src_id in source_id_list]

            else:
                self.save_progress("Getting latest {} incident(s) from last {} day(s)".format(
                    str(container_count),
                    str(self._poll_now_ingestion_span)
                ))
                # Only fetching incidents equal to container count

        # First scheduled polling
        elif self._state.get('first_run', True):
            incidents_to_ingest_pending = self._first_scheduled_ingestion_limit
            total_incidents_to_ingest = self._first_scheduled_ingestion_limit
            ingestion_span_days_pending = self._first_scheduled_ingestion_span

        # Code to set parameters in case of manual and first scheduled ingestion
        if self.is_poll_now() or self._state.get('first_run', True):
            # Continuing to fetch incidents till the requested ingestion span or incident count is match.
            while (incidents_to_ingest_pending > 0 and ingestion_span_days_pending > 0):

                limit = SYMANTEC_MAX_LIMIT if incidents_to_ingest_pending > SYMANTEC_MAX_LIMIT \
                    else incidents_to_ingest_pending
                span = SYMANTEC_MAX_SPAN_DAYS if ingestion_span_days_pending > SYMANTEC_MAX_SPAN_DAYS \
                    else ingestion_span_days_pending
                start_day = end_day + span

                # Converting the start_time and end_time to ISO 8601 format and updating the request parameters
                container_data_param["start_time"] = datetime.utcfromtimestamp(
                    current_time - 86400 * start_day).isoformat()[:-3] + 'Z'

                container_data_param["end_time"] = datetime.utcfromtimestamp(
                    current_time - 86400 * end_day).isoformat()[:-3] + 'Z'

                # Setting limit parameter
                container_data_param["limit"] = int(limit)

                # getting incident updates
                return_value, json_resp = self._make_rest_call_abstract(SYMANTEC_GET_INCIDENTS, action_result,
                                                                        data=json.dumps(container_data_param))

                # Something went wrong with the request
                if phantom.is_fail(return_value):
                    return action_result.get_status(), incident_list

                # Adding incidents obtained from each API in incident list
                incident_list += json_resp.get("result", [])

                incidents_to_ingest_pending = total_incidents_to_ingest - len(incident_list)

                if (source_id):
                    # Filter the incident list based on matching incidents
                    incident_list = [incident for incident in incident_list if str(incident["atp_incident_id"])
                                     in source_id_list]

                    if (len(incident_list) == len(source_id_list)):
                        # No more incidents to fetch since the matching incidents have been found
                        incidents_to_ingest_pending = 0

                # If the database has more records to fetch
                # query the api with "next" key to get next set of incidents
                while (json_resp.get("next") and incidents_to_ingest_pending > 0):

                    # getting incident updates with next key
                    container_data_param["next"] = json_resp["next"]
                    return_value, json_resp = self._make_rest_call_abstract(SYMANTEC_GET_INCIDENTS, action_result,
                                                                            data=json.dumps(container_data_param))

                    # Something went wrong with the request
                    if phantom.is_fail(return_value):
                        return action_result.get_status(), incident_list

                    # Adding incidents obtained from each API in incident list
                    incident_list += json_resp.get("result", [])

                    incidents_to_ingest_pending = total_incidents_to_ingest - len(incident_list)

                    if (source_id):
                        # Filter the incident list based on matching incidents
                        incident_list = [incident for incident in incident_list if str(incident["atp_incident_id"])
                                         in source_id_list]

                        if (len(incident_list) == len(source_id_list)):
                            # No more incidents to fetch since the matching incidents have been found
                            incidents_to_ingest_pending = 0

                # Updating the ingestion_span_pending to reflect pending span to traverse
                ingestion_span_days_pending -= span
                end_day = start_day

            # Inform user if incident list obtained during the requested ingestion
            # span is less than the number of containers requested
            if container_count > len(incident_list) and not source_id:
                self.save_progress("The total number of incident update retrieved is less than maximum containers \
                count")

        # For scheduled polling second time onwards
        else:
            start_time = param.get(phantom.APP_JSON_START_TIME)
            end_time = param.get(phantom.APP_JSON_END_TIME)

            # Converting the start_time and end_time to ISO 8601 format and updating the request parameters
            container_data_param["start_time"] = datetime.fromtimestamp(
                start_time / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            container_data_param["end_time"] = datetime.fromtimestamp(
                end_time / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

            container_data_param["limit"] = 1000

            # getting incident updates
            return_value, json_resp = self._make_rest_call_abstract(SYMANTEC_GET_INCIDENTS, action_result,
                                                                    data=json.dumps(container_data_param))

            # Something went wrong with the request
            if phantom.is_fail(return_value):
                return action_result.get_status(), incident_list

            # Adding incidents obtained
            incident_list += json_resp.get("result", [])

            # If the database has more records to fetch
            # query the api with "next" key to get next set of incidents
            while (json_resp.get("next")):

                # getting incident updates
                container_data_param["next"] = json_resp["next"]
                return_value, json_resp = self._make_rest_call_abstract(SYMANTEC_GET_INCIDENTS, action_result,
                                                                        data=json.dumps(container_data_param))

                # Something went wrong with the request
                if phantom.is_fail(return_value):
                    return action_result.get_status(), incident_list

                # Adding incidents obtained from each API in incident list
                incident_list += json_resp.get("result", [])

        return action_result.set_status(phantom.APP_SUCCESS), incident_list

    # This function returns incident_events dictionary with uuid as key and
    # list of events have that uuid as as value
    def _get_matching_events(self, incident_uuids, incident_events, json_resp):

        # Compare uuid of incident with incident field of event and return the list of matching events
        for event in json_resp.get("result", []):
            if event.get("incident") in incident_uuids:
                if event.get("incident") in incident_events.keys():
                    incident_events[event.get("incident")].append(event)
                else:
                    incident_events[event.get("incident")] = [event]
        return incident_events

    def _fetch_events(self, action_result, event_data_param, incident_uuids, incident_events):

        # getting incident updates
        return_value, json_resp = self._make_rest_call_abstract(SYMANTEC_GET_EVENTS, action_result,
                                                                data=json.dumps(event_data_param))

        # Something went wrong with the request
        if phantom.is_fail(return_value):
            return action_result.get_status()

        # Get list of matching events
        incident_events = self._get_matching_events(incident_uuids, incident_events, json_resp)

        # If the database has more records to fetch
        # query the api with "next" key to get next set of incidents
        while (json_resp.get("next")):

            # getting incident updates
            event_data_param["next"] = json_resp["next"]
            return_value, json_resp = self._make_rest_call_abstract(SYMANTEC_GET_INCIDENTS, action_result,
                                                                    data=json.dumps(event_data_param))

            # Something went wrong with the request
            if phantom.is_fail(return_value):
                return phantom.APP_ERROR

            # Get list of matching events
            incident_events = self._get_matching_events(incident_uuids, incident_events, json_resp)

        return phantom.APP_SUCCESS

    # This function sets the required parameters for the events api request according to the ingestion type i.e.
    # manual ingestion, first scheduled ingestion or scheduled ingestion after first time
    def _get_event_list(self, incident_uuids, action_result):

        incident_events = {}
        event_data_param = {"verb": "query"}

        current_time = time.time()
        end_day = 0

        # Poll Now or First Scheduled Ingestion
        if self.is_poll_now() or self._state.get('first_run', True):

            if self.is_poll_now():
                ingestion_span_pending = self._poll_now_ingestion_span
            else:
                ingestion_span_pending = self._first_scheduled_ingestion_span
            # Continuing to fetch events till the requested ingestion span is met
            while (ingestion_span_pending > 0):

                span = SYMANTEC_MAX_SPAN_DAYS if ingestion_span_pending > SYMANTEC_MAX_SPAN_DAYS \
                    else ingestion_span_pending
                start_day = end_day + span

                # Converting the start_time and end_time to ISO 8601 format and updating the request parameters
                event_data_param["start_time"] = datetime.utcfromtimestamp(
                    current_time - 86400 * start_day).isoformat()[:-3] + 'Z'

                event_data_param["end_time"] = datetime.utcfromtimestamp(
                    current_time - 86400 * end_day).isoformat()[:-3] + 'Z'

                # Setting limit parameter
                event_data_param["limit"] = int(SYMANTEC_MAX_LIMIT)

                # Obtain required incident related events
                response_status = self._fetch_events(action_result, event_data_param, incident_uuids, incident_events)

                if phantom.is_fail(response_status):
                    return action_result.get_status(), incident_events

                ingestion_span_pending -= span
                end_day = start_day

        # Scheduled Ingestion post first occurrence
        else:
            start_time = action_result.get_param().get(phantom.APP_JSON_START_TIME)
            end_time = action_result.get_param().get(phantom.APP_JSON_END_TIME)

            # Converting the start_time and end_time to ISO 8601 format and updating the request parameters
            event_data_param["start_time"] = datetime.fromtimestamp(
                start_time / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            event_data_param["end_time"] = datetime.fromtimestamp(
                end_time / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

            event_data_param["limit"] = int(SYMANTEC_MAX_LIMIT)

            # Obtain required incident related events
            response_status = self._fetch_events(action_result, event_data_param, incident_uuids, incident_events)

            if phantom.is_fail(response_status):
                return action_result.get_status(), incident_events

        return action_result.set_status(phantom.APP_SUCCESS), incident_events

    def _ingest_data(self, incident_data, event_data):

        container = {}

        # In the API, following are the representations for the priority level of incident:
        # 1: LOW, 2: MEDIUM, 3: HIGH
        # Based on the above value, we have mapped the severity of container
        container_severity_mapping = {
            1: "low",
            2: "medium",
            3: "high"
        }

        # In the API, following are the representations for the status:
        # 1: OPEN, 2: WAITING, 3: IN_WORK, 4: CLOSED
        # Based on the above status, we have mapped the status of container
        # container_status_mapping = {
        #     1: "open",
        #     2: "new",
        #     3: "open",
        #     4: "closed"
        # }

        for incident in incident_data:
            self.send_progress("Ingesting data for incident ID {}".format(str(incident.get("atp_incident_id"))))
            container["name"] = incident.get("log_name")
            container["description"] = incident.get("summary")
            container['data'] = incident
            container["severity"] = container_severity_mapping[incident.get("priority_level")]
            # container["status"] = container_status_mapping[incident.get("state")]
            container["start_time"] = incident.get("time")
            container['source_data_identifier'] = str(incident.get("atp_incident_id"))
            artifacts = container['artifacts'] = []

            # Creating Endpoint Artifact for deviceUuid
            for device_uid in incident.get('deviceUid', []):
                artifact_details = {
                    "cef": {'deviceUid': device_uid},
                    "cef_types": {'deviceUid': ["symantecatp target endpoint"]}
                }
                artifacts.append(self._create_artifact("Endpoint Artifact", artifact_details))

            # Loop for creating artifacts from data obtained by hitting incidents API
            artifacts.extend(self._create_event_artifact(event_data[incident["uuid"]]))

            return_value, response, container_id = self.save_container(container)

            # Something went wrong while creating container
            if phantom.is_fail(return_value):
                self.save_progress("Error while creating container for {}".format(str(incident.get("atp_incident_id"))))
                self.debug_print(SYMANTEC_CONTAINER_ERROR, dump_object=container)
                continue

        return phantom.APP_SUCCESS

    # function used to create artifacts from event data
    # even if artifact creation fails, proceed to the next artifact creation
    def _create_event_artifact(self, event_list):

        # List of keys to consider from the event data to create IP, URL and domain artifacts
        # All keys whose values can be accessed directly
        artifact_attributes_map_1 = {
            "IP Artifact": {
                "device_ip": {"cef_name": "deviceAddress", "cef_contains": ["ip"]},
                "internal_ip": {"cef_name": "internalAddress", "cef_contains": ["ip"]},
                "external_ip": {"cef_name": "externalAddress", "cef_contains": ["ip"]},
                "target_ip": {"cef_name": "destinationAddress", "cef_contains": ["ip"]},
                "source_ip": {"cef_name": "sourcefileAddress", "cef_contains": ["ip"]},
                "data_source_ip": {"cef_name": "dataSourceIPAddress", "cef_contains": ["ip"]}
            },
            "URL Artifact": {
                "data_source_url": {"cef_name": "dataSourceURL", "cef_contains": ["url"]},
                "intrusion_url": {"cef_name": "intrusionURL", "cef_contains": ["url"]}
            },
            "Domain Artifact": {
                "data_source_url_domain": {"cef_name": "sourceDnsDomain", "cef_contains": ["domain"]}
            }
        }

        # List of keys to consider from the event data to create file and email artifact
        # All keys whose values are to fetched from nested keys
        artifact_attributes_map_2 = {
            "File Artifact": {
                "file": {"name": {"cef_name": "fileName", "cef_contains": ["file name"]},
                         "sha2": {"cef_name": "fileHashSha256", "cef_contains": ["hash", "sha256"]},
                         "md5": {"cef_name": "fileHashMd5", "cef_contains": ["hash", "md5"]}}
            },
            "Email Artifact": {
                "Sender": {"EmailAddress": {"cef_name": "sourceEmailAddress", "cef_contains": ["email"]},
                           "SenderIP": {"cef_name": "sourceAddress", "cef_contains": ["ip"]}},
                "Receivers": {"EmailAddress": {"cef_name": "receiverAddress", "cef_contains": ["email"]}}
            }
        }

        artifacts = []
        # Iterate over all the events
        for event in event_list:
            # Loop to create IP, URL and domain artifacts
            for artifact_name, artifact_keys in artifact_attributes_map_1.items():
                attribute_avail = False
                # Adding eventTypeId and eventUUID in each artifact
                cef = {"eventTypeId": event["type_id"], "eventUUID": event["uuid"]}
                cef_types = {}
                # Iterate over the attributes that need to be added in IP, URL and domain artifact
                # If present in event add it in the artifact and also associate the corresponding contains
                for attribute in artifact_keys:
                    if attribute in event and event.get(attribute):
                        attribute_avail = True
                        attribute_details = artifact_attributes_map_1[artifact_name][attribute]
                        cef[attribute_details["cef_name"]] = event[attribute]
                        cef_types[attribute_details["cef_name"]] = attribute_details["cef_contains"]

                artifact_details = {"cef": cef, "cef_types": cef_types, "data": event}
                # Create artifact
                if attribute_avail:
                    artifacts.append(self._create_artifact(artifact_name, artifact_details))

            # Loop to create file and email artifacts
            for artifact_name, artifact_keys in artifact_attributes_map_2.items():
                # Iterate over the parent attributes of file and email artifacts
                # for example file, sender
                attribute_avail = False
                for parent_attribute in artifact_keys:
                    if parent_attribute in event:
                        # Adding eventTypeId and eventUUID in each artifact
                        cef = {"eventTypeId": event["type_id"], "eventUUID": event["uuid"]}
                        cef_types = {}
                        # Iterate over the attributes that need to be added in file and email artifact.
                        # If present in event add it in the artifact and also associate the corresponding contains
                        # Skip the artifacts which are blank
                        for child_attribute in artifact_attributes_map_2[artifact_name][parent_attribute]:
                            if child_attribute in event[parent_attribute] and \
                                    event[parent_attribute].get(child_attribute):
                                attribute_avail = True
                                attribute_details = \
                                    artifact_attributes_map_2[artifact_name][parent_attribute][child_attribute]
                                cef[attribute_details["cef_name"]] = event[parent_attribute][child_attribute]
                                cef_types[attribute_details["cef_name"]] = attribute_details["cef_contains"]

                        artifact_details = {"cef": cef, "cef_types": cef_types, "data": event}
                        # Create artifact
                        if attribute_avail:
                            artifacts.append(self._create_artifact(artifact_name, artifact_details))

        return artifacts

    # function used to create artifacts based on given data
    def _create_artifact(self, artifact_name, artifact_details, severity=None):

        cef = artifact_details["cef"]
        cef_types = artifact_details["cef_types"]
        data = artifact_details.get('data')

        artifact = {
            'name': artifact_name,
            'description': SYMANTEC_ARTIFACTS_DESC,
            'cef_types': cef_types,
            'cef': cef
        }

        if severity:
            artifact["severity"] = severity
        if data:
            artifact['data'] = data

        artifact['source_data_identifier'] = self._create_dict_hash(artifact)

        return artifact

    # Function used to generate hash value of the data provided
    def _create_dict_hash(self, input_dict):

        input_dict_str = None

        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            print str(e)
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str).hexdigest()

    # To check the status of command id.
    def _check_status(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        response_status, response = self._make_rest_call_abstract(SYMANTEC_COMMAND_ENDPOINT + str(param['command_id']),
                                                                  action_result, method="get")

        # If the action fails
        if phantom.is_fail(response_status):
            return action_result.get_status()

        response_dict = {}

        # Add result of each endpoint into summary
        for status_index in range(len(response['status'])):
            response_dict[str(response['status'][status_index]['target'])] = \
                str(response['status'][status_index]['message'])

        summary_data['target_status'] = response_dict

        # Adds data into action_result
        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to isolate the endpoint
    def _quarantine_endpoint(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Strip out white spaces and then split the string with (',') delimiter to obtain list
        target_list = param['targets'].split(",")
        target_list = [uid.strip() for uid in target_list]

        # Prepare request body
        data_body = {'action': 'isolate_endpoint', 'targets': target_list}

        response_status, response = self._make_rest_call_abstract(SYMANTEC_QUARANTINE_ENDPOINT,
                                                                  action_result, data=json.dumps(data_body))

        # If the action fails
        if phantom.is_fail(response_status):
            return action_result.get_status()

        # Adds data into action_result and summary
        action_result.add_data(response)
        summary_data['command_id'] = response.get('command_id')

        self.debug_print(SYMANTEC_QUARANTINE_RESPONSE_COMMAND_ID.format(command_id=response.get('command_id')))

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to rejoin the endpoint
    def _unquarantine_endpoint(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Strip out white spaces and then split the string with (',') delimiter to obtain list
        target_list = param['targets'].split(",")
        target_list = [uid.strip() for uid in target_list]

        # Prepare request body
        data_body = {'action': 'rejoin_endpoint', 'targets': target_list}

        response_status, response = self._make_rest_call_abstract(SYMANTEC_QUARANTINE_ENDPOINT,
                                                                  action_result, data=json.dumps(data_body))

        # If action fails
        if phantom.is_fail(response_status):
            return action_result.get_status()

        # Adds data into action_result and summary
        action_result.add_data(response)
        summary_data['command_id'] = response.get('command_id')

        self.debug_print(SYMANTEC_QUARANTINE_RESPONSE_COMMAND_ID.format(command_id=response.get('command_id')))

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to delete the file
    def _delete_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Strip out white spaces and then split the string with (',') delimiter to obtain list
        hash_list = param['hash'].split(',')
        hash_list = [file_hash.strip() for file_hash in hash_list]
        # Get device uid
        device_uid = param['device_uid']

        target_list = []
        for file_hash in hash_list:
            target_list.append({'hash': file_hash, 'device_uid': device_uid})

        # Prepare request body
        data_body = {'action': 'delete_endpoint_file', 'targets': target_list}

        response_status, response = self._make_rest_call_abstract(SYMANTEC_QUARANTINE_ENDPOINT,
                                                                  action_result, data=json.dumps(data_body))

        if phantom.is_fail(response_status):
            return action_result.get_status()

        # Adds data into action_result and summary
        action_result.add_data(response)
        summary_data['command_id'] = response.get('command_id')

        self.debug_print(SYMANTEC_QUARANTINE_RESPONSE_COMMAND_ID.format(command_id=response.get('command_id')))

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to hunt a file
    def _hunt_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        ret_val = self._generate_api_token(action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        the_hash = param['hash']
        if phantom.is_md5(the_hash):
            hash_type = 'md5'
        elif phantom.is_sha256(the_hash):
            hash_type = 'sha256'
        else:
            return action_result.set_status(phantom.APP_ERROR, "The given hash appears to be malformed")

        ret_val, response = self._make_rest_call(SYMANTEC_HUNT_FILE.format(the_hash, hash_type), action_result, auth_mode='Bearer', headers={}, method='get')

        if phantom.is_fail(ret_val):
            return ret_val

        # Adds data into action_result and summary
        action_result.add_data(response)
        summary_data['files_found'] = response.get('total')

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to handle actions supported by app
    def handle_action(self, param):

        # Dictionary containing function name of each action
        action_details = {
            "on_poll": self._on_poll,
            "hunt_file": self._hunt_file,
            "delete_file": self._delete_file,
            "check_status": self._check_status,
            "test_connectivity": self._test_connectivity,
            "quarantine_endpoint": self._quarantine_endpoint,
            "unquarantine_endpoint": self._unquarantine_endpoint
        }

        action = self.get_action_identifier()
        return_value = phantom.APP_SUCCESS

        if action in action_details.keys():
            action_function = action_details[action]
            return_value = action_function(param)

        return return_value

    def finalize(self):

        self._save_state()
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SymantecatpConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
