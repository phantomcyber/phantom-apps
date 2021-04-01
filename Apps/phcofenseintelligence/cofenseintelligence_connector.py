# File: cofenseintelligence_connector.py
# Copyright (c) 2020-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
from cofenseintelligence_consts import *

import requests
import json
import time
import hashlib
from datetime import datetime
from bs4 import UnicodeDammit


class PhishMeConnector(BaseConnector):

    def __init__(self):

        # Calling the BaseConnector's init function
        super(PhishMeConnector, self).__init__()
        self._api_username = None
        self._api_password = None
        self._num_days = None
        self._state_file_path = None
        self._state = {}
        self._first_ingestion_span = None

        return

    def is_non_zero_positive_int(self, value):
        try:
            value = int(value)
            return True if value > 0 else False
        except Exception:
            return False

    # Initialize variables and load the previous state that
    # that will be used during ingestion
    def initialize(self):

        self._state = self.load_state()
        config = self.get_config()
        self._api_username = UnicodeDammit(config[PHISHME_CONFIG_API_USERNAME]).unicode_markup.encode('utf-8')
        self._api_password = config[PHISHME_CONFIG_API_PASSWORD]

        num_days = config.get(PHISHME_CONFIG_POLL_NOW_DAYS, PHISHME_DEFAULT_POLL_NOW_SPAN_DAYS)
        first_ingestion_span = config.get(PHISHME_CONFIG_INGEST, PHISHME_DEFAULT_FIRST_INGEST_SPAN_DAYS)

        if not (self.is_non_zero_positive_int(num_days) and self.is_non_zero_positive_int(first_ingestion_span)):
            return self.set_status(
                phantom.APP_ERROR,
                PHISHME_INVALID_LIMIT_MSG
            )

        self._num_days = int(num_days)
        self._first_ingestion_span = int(first_ingestion_span)

        return phantom.APP_SUCCESS

    def finalize(self):

        self.save_state(self._state)
        return phantom.APP_SUCCESS

    # Function to handle actions supported by app
    def handle_action(self, param):

        # Dictionary containing function name of each action
        action_details = {
            "hunt_url": self._hunt_url,
            "hunt_ip": self._hunt_ip,
            "hunt_file": self._hunt_file,
            "hunt_domain": self._hunt_domain,
            "get_report": self._get_report,
            "on_poll": self._on_poll,
            "test_asset_connectivity": self._test_asset_connectivity
        }

        action = self.get_action_identifier()
        return_value = phantom.APP_SUCCESS

        if action in list(action_details.keys()):
            action_function = action_details[action]
            return_value = action_function(param)

        return return_value

    # Function that makes the REST call to the device,
    # generic function that can be called from various action handlers
    def _make_rest_call(self, endpoint, action_result, params=None, body=None, method="post"):

        auth = (self._api_username, self._api_password)

        resp_data = None

        # Dictionary containing message for errors in response of API call
        error_resp_dict = {
            PHISHME_REST_RESP_SYNTAX_INCORRECT: PHISHME_REST_RESP_SYNTAX_INCORRECT_MSG,
            PHISHME_REST_RESP_FAILED_AUTHORIZATION: PHISHME_REST_RESP_FAILED_AUTHORIZATION_MSG,
            PHISHME_REST_RESP_SERVER_ERROR: PHISHME_REST_RESP_SERVER_ERROR_MSG,
            PHISHME_REST_RESP_SERVER_UNREACHABLE: PHISHME_REST_RESP_SERVER_UNREACHABLE_MSG
        }

        # get, post or put, whatever the caller asked us to use,
        # if not specified the default will be 'post'
        try:
            request_func = getattr(requests, method)
        except:
            self.debug_print(PHISHME_ERR_API_UNSUPPORTED_METHOD.format(method=str(method)))
            # set the action_result status to error, the handler function
            # will most probably return as is
            return (action_result.set_status(phantom.APP_ERROR, PHISHME_ERR_API_UNSUPPORTED_METHOD, method=str(method)),
                    resp_data)

        # Make the call
        try:
            response = request_func(PHISHME_API_SEARCH + endpoint, auth=auth, params=params, data=body)

        except Exception as e:
            self.debug_print("Exception while making request: {}".format(str(e)))
            # set the action_result status to error, the handler function
            # will most probably return as is
            return (action_result.set_status(phantom.APP_ERROR, PHISHME_ERR_SERVER_CONNECTION, e),
                    resp_data)

        if response.status_code in list(error_resp_dict.keys()):
            # set the action_result status to error, the handler function
            # will most probably return as is
            return (action_result.set_status(phantom.APP_ERROR, PHISHME_ERR_FROM_SERVER, status=response.status_code,
                                             detail=error_resp_dict[response.status_code]),
                    resp_data)

        # Return code 404 is not considered as failed action.
        # The requested resource is unavailable
        if response.status_code == PHISHME_REST_RESP_RESOURCE_NOT_FOUND:
            return phantom.APP_SUCCESS, {PHISHME_JSON_RESOURCE_NOT_FOUND: True}

        content_type = response.headers['content-type']
        if content_type.find('json') != -1:
            try:
                resp_data = response.json()
            except Exception as e:
                return (action_result.set_status(
                    phantom.APP_ERROR,
                    PHISHME_ERR_JSON_PARSE.format(raw_text=response.text),
                    e), resp_data)
        else:
            resp_data = response.text

        if response.status_code == PHISHME_REST_RESP_SUCCESS:
            return phantom.APP_SUCCESS, resp_data

        # In case of json response get the response message from exception key if it is present
        if type(resp_data) is dict and resp_data.get("data"):
            message = resp_data["data"].get("exception", PHISHME_REST_RESP_OTHER_ERROR_MSG)

        # If data key is not available in json response
        else:
            message = PHISHME_REST_RESP_OTHER_ERROR_MSG

        # All other response codes from Rest call are failures
        self.debug_print(PHISHME_ERR_FROM_SERVER.format(status=response.status_code, detail=message))

        # set the action_result status to error, the handler function
        # will most probably return as is
        return (action_result.set_status(phantom.APP_ERROR, PHISHME_ERR_FROM_SERVER, status=response.status_code,
                                         detail=message), resp_data)

    # Function to test connectivity of asset
    def _test_asset_connectivity(self, param):

        action_result = ActionResult()
        self.save_progress(PHISHME_CONNECTION_TEST_MSG)

        params = {'threatType': 'malware'}

        return_value, json_resp = self._make_rest_call(PHISHME_ENDPOINT, action_result, params=params)

        if phantom.is_fail(return_value):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, PHISHME_CONNECTION_TEST_ERR_MSG)
            return action_result.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, PHISHME_CONNECTION_TEST_SUCC_MSG)
        return action_result.get_status()

    # Function to search threats from PhishMe database based on
    # given parameters
    # Use pagination to get list of all threats
    # Threats per page: 100
    def _threat_search(self, data, max_threat_cnt, action_result):

        # Considering results_per_page as 100
        results_per_page = 100
        data.update({'resultsPerPage': results_per_page, 'threatType': 'malware'})

        aggr_resp = dict()
        last_page_index = int(max_threat_cnt / results_per_page)

        # max_threat_cnt validation
        if max_threat_cnt <= 0:
            self.debug_print(PHISHME_THREAT_COUNT_ERROR)
            return action_result.set_status(phantom.APP_ERROR, PHISHME_THREAT_COUNT_ERROR), aggr_resp

        # Paginate through list of threats till maximum count is
        # reached or all threats retrieved
        for curr_page_index in range(last_page_index + 1):
            data.update({'page': curr_page_index})

            return_value, rest_resp = self._make_rest_call(PHISHME_ENDPOINT, action_result, params=data)

            # Something went wrong with the request
            if phantom.is_fail(return_value):
                return action_result.get_status(), aggr_resp

            # Resource not found is treated as app success
            # Empty list of threats is also treated as app success
            if rest_resp.get(PHISHME_JSON_RESOURCE_NOT_FOUND) or not rest_resp["data"]["threats"]:
                return phantom.APP_SUCCESS, rest_resp

            if aggr_resp:
                # Appending threats to available threat list
                aggr_resp["data"]["threats"] += (rest_resp["data"]["threats"])
                aggr_resp["data"]["page"] = rest_resp["data"].get("page", aggr_resp["data"]["page"])
            else:
                # During the first page index
                aggr_resp = rest_resp

            # Maximum number of threats to fetch reached
            if curr_page_index == last_page_index and len(aggr_resp["data"]["threats"]) >= max_threat_cnt:
                # Since results per page is 100, total number of threats
                # retrieved could be more than maximum count
                # Trimming the threat list to retrieve maximum count
                aggr_resp["data"]["threats"] = aggr_resp["data"]["threats"][0:max_threat_cnt]
                return phantom.APP_SUCCESS, aggr_resp

            # All available threats retrieved
            if len(rest_resp["data"]["threats"]) < results_per_page:
                return phantom.APP_SUCCESS, aggr_resp

        # Return empty list
        return phantom.APP_SUCCESS, []

    # Function to parse the json response and return the required data to dump in the action result.
    def _parse_response(self, json_resp, ioc_type=None, param_value=None):

        # Response structure
        data_to_add = {'data': {'threats': []}}

        # List of data keys that are common for all actions
        required_keys = ['apiReportURL', 'campaignBrandSet', 'executiveSummary', 'firstPublished', 'hasReport',
                         'id', 'label', 'lastPublished', 'malwareFamilySet', 'reportURL', 'threatDetailURL',
                         'threatType']

        # Action specific ioc keys
        action_ioc_keys = {'hunt_file': ['executableSet'], 'hunt_ip': ['blockSet'],
                           'hunt_url': ['blockSet'], 'hunt_domain': ['blockSet']}

        # Get action name
        action_name = self.get_action_identifier()

        # Add the required IOC keys according to the action to the existing list of common keys
        if action_name in action_ioc_keys:
            required_keys += action_ioc_keys[action_name]

        # Iterate over every threat in the json response
        for threat in json_resp['data']['threats']:
            # Dict to dump the required threat details
            threat_dict = {}
            # Iterate over the list of keys in required_keys list
            for required_key in required_keys:
                # Include only those blockSet that are related to the action (for hunt ip, url and domain actions)
                if required_key == 'blockSet':
                    ioc_details = []
                    if threat.get('blockSet'):
                        for block_set in threat['blockSet']:
                            if block_set.get('blockType') == ioc_type and block_set.get('data') == param_value:
                                ioc_details.append(block_set)
                        threat_dict[required_key] = ioc_details
                # Add executableSet in data in case of hunt file action
                elif required_key == 'executableSet':
                    file_details = []
                    if threat.get('executableSet'):
                        for executable_set in threat['executableSet']:
                            if executable_set.get('md5Hex') == param_value:
                                file_details.append(executable_set)
                        threat_dict[required_key] = file_details
                # Add other set of required keys that are common for all actions
                else:
                    if threat.get(required_key):
                        threat_dict[required_key] = threat[required_key]
            # Add dictionary containing threat details to the threat list
            data_to_add['data']['threats'].append(threat_dict)

        # return data to dump into action result
        return data_to_add

    # Function to get threats associated with file hash provided
    # Number of threats to get can be restricted based on max_threat_cnt parameter
    def _hunt_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        filehash = param[PHISHME_JSON_FILE]

        # Getting optional parameter
        max_threat_cnt = int(param.get(PHISHME_JSON_MAX_THREAT_COUNT, PHISHME_DEFAULT_MAX_THREAT_COUNT))

        data = {'allMD5': filehash}

        return_value, json_resp = self._threat_search(data, max_threat_cnt, action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_value):
            self.debug_print(action_result.get_message())
            return action_result.get_status()

        # Resource not found is treated as app success
        # Empty threats is also treated as app success
        if not json_resp or not json_resp["data"]["threats"]:
            return action_result.set_status(phantom.APP_SUCCESS, PHISHME_REST_RESP_RESOURCE_NOT_FOUND_MSG)

        data_to_add = self._parse_response(json_resp, param_value=filehash)

        action_result.add_data(data_to_add)
        total_threats = len(json_resp["data"]["threats"])

        summary_data['total_threats'] = total_threats

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to get threats associated with url provided
    # Number of threats to get can be restricted based on max_threat_cnt parameter
    def _hunt_url(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        url = param[PHISHME_JSON_URL]

        # Getting optional parameter
        max_threat_cnt = int(param.get(PHISHME_JSON_MAX_THREAT_COUNT, PHISHME_DEFAULT_MAX_THREAT_COUNT))

        data = {'urlSearch': url}

        return_value, json_resp = self._threat_search(data, max_threat_cnt, action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_value):
            self.debug_print(action_result.get_message())
            return action_result.get_status()

        # Resource not found is treated as app success
        # Empty threats is also treated as app success
        if not json_resp or not json_resp["data"]["threats"]:
            return action_result.set_status(phantom.APP_SUCCESS, PHISHME_REST_RESP_RESOURCE_NOT_FOUND_MSG)

        data_to_add = self._parse_response(json_resp, ioc_type='URL', param_value=url)

        action_result.add_data(data_to_add)
        total_threats = len(json_resp["data"]["threats"])

        summary_data['total_threats'] = total_threats

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to get threats associated with IPv4 Address provided
    # Number of threats to get can be restricted based on max_threat_cnt parameter
    def _hunt_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        ip = param[PHISHME_JSON_IP]

        # Getting optional parameters
        max_threat_cnt = int(param.get(PHISHME_JSON_MAX_THREAT_COUNT, PHISHME_DEFAULT_MAX_THREAT_COUNT))

        data = {'ip': ip}

        return_value, json_resp = self._threat_search(data, max_threat_cnt, action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_value):
            self.debug_print(action_result.get_message())
            return action_result.get_status()

        # Resource not found is treated as app success
        # Empty threats is also treated as app success
        if not json_resp or not json_resp["data"]["threats"]:
            return action_result.set_status(phantom.APP_SUCCESS, PHISHME_REST_RESP_RESOURCE_NOT_FOUND_MSG)

        data_to_add = self._parse_response(json_resp, ioc_type='IPv4 Address', param_value=ip)

        action_result.add_data(data_to_add)
        total_threats = len(json_resp["data"]["threats"])

        summary_data['total_threats'] = total_threats

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to get threats associated with domain name provided
    # Number of threats to get can be restricted based on max_threat_cnt parameter
    def _hunt_domain(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        domain = param[PHISHME_JSON_DOMAIN]

        # Convert URL to domain
        if phantom.is_url(domain):
            domain = phantom.get_host_from_url(domain)

        # Getting optional parameter
        max_threat_cnt = int(param.get(PHISHME_JSON_MAX_THREAT_COUNT, PHISHME_DEFAULT_MAX_THREAT_COUNT))

        data = {'domain': domain}

        return_value, json_resp = self._threat_search(data, max_threat_cnt, action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_value):
            self.debug_print(action_result.get_message())
            return action_result.get_status()

        # Resource not found is treated as app success
        # Empty threats is also treated as app success
        if not json_resp or not json_resp["data"]["threats"]:
            return action_result.set_status(phantom.APP_SUCCESS, PHISHME_REST_RESP_RESOURCE_NOT_FOUND_MSG)

        # Get the required data to dump in action result
        data_to_add = self._parse_response(json_resp, ioc_type='Domain Name', param_value=domain)

        action_result.add_data(data_to_add)
        total_threats = len(json_resp["data"]["threats"])

        summary_data['total_threats'] = total_threats

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to generate report of threat ID provided
    def _get_report(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        threat_id = param['threat_id']

        return_value, json_resp = self._make_rest_call(PHISHME_ENDPOINT_GET_REPORT_MALWARE + str(threat_id),
                                                       action_result, method="get")

        # Something went wrong with the request
        if phantom.is_fail(return_value):
            self.debug_print(PHISHME_THREAT_DATA_ERROR.format(id=param["threat_id"],
                                                              message=action_result.get_message()))
            return action_result.get_status()

        # Resource not found is treated as app success
        if json_resp.get(PHISHME_JSON_RESOURCE_NOT_FOUND):
            return action_result.set_status(
                phantom.APP_SUCCESS,
                PHISHME_REST_RESP_RESOURCE_NOT_FOUND_MSG
            )

        action_result.add_data(json_resp)

        summary_data['threat_type'] = json_resp['data']['threatType']
        summary_data['threat_label'] = json_resp['data']['label']

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to create containers and artifacts
    def _ingest_threat_data(self, endpoint, threat_id):

        # Not adding action_result to base connector, use this object for rest calls only
        # even if individual threat ingestion fails, ingestion should continue for other threats
        action_result = ActionResult()
        container = {}

        # dictionary used to determine severity of artifacts
        phantom_severity_mapping = {
            "Major": "high",
            "Moderate": "medium"
        }

        # Getting report details
        return_value, json_resp = self._make_rest_call(endpoint + threat_id, action_result, method="get")

        # Something went wrong with the request
        if phantom.is_fail(return_value):
            self.save_progress(PHISHME_THREAT_DATA_ERROR.format(id=str(threat_id), message=action_result.get_message()))
            self.debug_print(PHISHME_THREAT_DATA_ERROR.format(id=str(threat_id), message=action_result.get_message()))
            return action_result.get_status()

        # Resource not found is treated as app success
        if json_resp.get(PHISHME_JSON_RESOURCE_NOT_FOUND):
            self.save_progress(PHISHME_REST_RESP_RESOURCE_NOT_FOUND_MSG)
            return phantom.APP_SUCCESS

        # getting name and description of container from threat report obtained
        if json_resp.get("data"):
            container_details = {
                "container_name": json_resp["data"].get("label"),
                "container_description": json_resp["data"].get("executiveSummary")
            }

        # default value of name and description of container
        else:
            container_details = {
                "container_name": "threat_" + str(threat_id),
                "container_description": PHISHME_CONTAINER_DESC.format(
                    str(threat_id)
                )
            }

        # Creating container
        container["name"] = container_details["container_name"]
        container["description"] = container_details["container_description"]
        container['data'] = json_resp
        container['source_data_identifier'] = threat_id
        return_value, response, container_id = self.save_container(
            container
        )

        # Something went wrong while creating container
        if phantom.is_fail(return_value):
            self.debug_print(PHISHME_CONTAINER_ERROR, container)

            # Not setting action_result to error, as there may be other data to ingest
            return phantom.APP_ERROR

        # This dictionary contains the mapping of cefs to create. It lists down all the keys to look for in
        # response object and map it with potential cefs to create. This dictionary contains mappings for
        # executableSet key
        # Key: executableSet
        # Value: {child key name: {cef name of value, contains for cef name}}
        executableset_cef_mapping = {
            "md5Hex": {"cef_name": "fileHashMd5", "cef_contains": ["hash", "md5"]},
            "sha1Hex": {"cef_name": "fileHashSha1", "cef_contains": ["hash", "sha1"]},
            "sha384Hex": {"cef_name": "fileHashSha384", "cef_contains": ["hash"]},
            "sha512Hex": {"cef_name": "fileHashSha512", "cef_contains": ["hash"]},
            "sha224Hex": {"cef_name": "fileHashSha224", "cef_contains": ["hash"]},
            "sha256Hex": {"cef_name": "fileHashSha256", "cef_contains": ["hash", "sha256"]},
            "fileName": {"cef_name": "fileName", "cef_contains": ["file name"]},
            "type": {"cef_name": "fileType", "cef_contains": []},
            "dateEntered": {"cef_name": "fileModificationTime", "cef_contains": []}
        }

        response_data = json_resp["data"]

        # Iterate through the executableSet key from response data and
        # look for applicable cef to create in an artifact
        for executableset_data in response_data.get("executableSet", []):
            cef = {}
            cef_types = {}
            for threat_data_key in list(executableset_cef_mapping.keys()):

                cef_details = executableset_cef_mapping[threat_data_key]

                # Adding cef if found from executableSet key
                if executableset_data.get(threat_data_key):
                    cef_value = executableset_data[threat_data_key]
                    # Converting date from epoch format to human readable format
                    if threat_data_key == "dateEntered":
                        cef_value = datetime.fromtimestamp(
                            int(cef_value) / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

                    cef[cef_details["cef_name"]] = cef_value
                    cef_types[cef_details["cef_name"]] = cef_details["cef_contains"]

            # Making artifacts after gathering data for artifacts
            return_value, artifact = self._create_artifact("File Artifact", cef, cef_types, container_id)

            # Something went wrong while creating artifacts
            # continue creating next artifact
            if phantom.is_fail(return_value):
                self.debug_print(PHISHME_ARTIFACTS_ERROR, artifact)

        # dictionary containing details of blockSet key from the response obtained
        # Key: Value of blockType key in elements of blockSet key
        # Value: {artifact name, cef name of value, contains for cef name}
        blockset_cef_mapping = {
            "IPv4 Address": {"artifact_name": "IP Artifact", "cef_name": "destinationAddress", "cef_contains": ["ip"]},
            "Domain Name": {"artifact_name": "Domain Artifact", "cef_name": "destinationDnsDomain",
                            "cef_contains": ["domain"]},
            "URL": {"artifact_name": "URL Artifact", "cef_name": "requestURL", "cef_contains": ["url"]}
        }

        # creating artifacts from data in blockSet key.
        # Checking if blockType key is present
        # Checking if value of blockType is any one of 'IPv4 Address', 'Domain Name' or 'URL'
        # Checking if impact key is present and its value must be 'Major' or 'Moderate'
        for blockset_data in response_data.get("blockSet", []):
            if blockset_data.get('blockType') in blockset_cef_mapping and \
                    blockset_data.get("impact") in ["Major", "Moderate"]:
                cef_details = blockset_cef_mapping[blockset_data["blockType"]]

                cef = {cef_details["cef_name"]: blockset_data["data"]}
                cef_types = {cef_details["cef_name"]: cef_details["cef_contains"]}

                severity = phantom_severity_mapping[blockset_data.get("impact")]
                return_value, artifact = self._create_artifact(cef_details["artifact_name"],
                                                               cef, cef_types, container_id, severity)

                # Something went wrong while creating artifacts
                # continue creating next artifact
                if phantom.is_fail(return_value):
                    self.debug_print(PHISHME_ARTIFACTS_ERROR, artifact)
                    continue

        # Adding threat details as artifact
        cef = {"CofenseIntelligenceThreatId": threat_id, "threatType": response_data.get("threatType")}

        cef_types = {"CofenseIntelligenceThreatId": ["cofense intelligence threat id"]}

        return_value, artifact = self._create_artifact("Threat Artifact", cef, cef_types, container_id)

        # Something went wrong while creating artifacts
        # continue creating next artifact
        if phantom.is_fail(return_value):
            self.debug_print(PHISHME_ARTIFACTS_ERROR, artifact)

        return phantom.APP_SUCCESS

    # Function to ingest new threat updates in phantom environment
    def _on_poll(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        next_position = None

        # Getting optional parameters
        container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT, PHISHME_DEFAULT_POLL_NOW_CONTAINER_COUNT))
        source_id = param.get("container_id")
        start_time = param.get(phantom.APP_JSON_START_TIME)

        if source_id:
            self.save_progress("Ignoring the maximum containers count")

        self.save_progress("Ignoring the maximum artifacts count")

        # Code to ingest data by manual polling
        if self.is_poll_now():
            num_days = int(self._num_days)
            start_time = int(time.time()) - (86400 * num_days)

            if not source_id:
                self.save_progress("Getting updates for last {} day(s)".format(str(num_days)))

        # Code to ingest data by scheduled polling for the first time
        elif self._state.get('first_run', True):
            self._state['first_run'] = False
            num_days = int(self._first_ingestion_span)

            start_time = int(time.time() - (86400 * num_days))
            self.debug_print("Getting updates for last {} day(s)".format(str(num_days)))

        # Code to ingest data by scheduled polling after first time
        else:
            next_position = str(self._state.get('next_position'))
            self.debug_print("Getting updates for last {} day(s)".format(str(next_position)))

        if next_position:
            rest_params = {"position": next_position}
        else:
            rest_params = {"timestamp": start_time}

        # getting formatted threat list based on the 'container count'
        return_value, threat_list = self._get_threat_updates(action_result, rest_params, source_id, container_count)

        # Something went wrong with the request
        if phantom.is_fail(return_value):
            self.debug_print(action_result.get_message())
            return action_result.get_status()

        for threat_index in range(0, len(threat_list)):

            threat_type = threat_list[threat_index]["threatType"]
            threat_id = str(threat_list[threat_index]["threatId"])

            if threat_type == "malware":
                endpoint = PHISHME_ENDPOINT_GET_REPORT_MALWARE

                self.send_progress("Ingesting data for threat # {0} ID {1}".format(threat_index + 1, str(threat_id)))

                # Even if ingest_threat_data fails, continue to next threat data ingestion
                self._ingest_threat_data(
                    endpoint,
                    str(threat_id)
                )

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to create artifacts based on the details provided
    def _create_artifact(self, artifact_name, cef, cef_types, container_id, severity=None):

        # Threat Artifact is the last artifact to be created for any contianer
        artifact = {'name': artifact_name, "description": PHISHME_ARTIFACTS_DESC, "cef_types": cef_types, 'cef': cef,
                    'container_id': container_id}

        if artifact_name == "Threat Artifact":
            artifact.update({'run_automation': True})

        if severity:
            artifact["severity"] = severity

        # The source_data_identifier should be created _after_ all the keys have been set.
        artifact['source_data_identifier'] = self._create_dict_hash(artifact)

        return_value, status_string, artifact_id = self.save_artifact(artifact)

        # Something went wrong while creating artifacts
        if phantom.is_fail(return_value):
            self.debug_print(status_string, artifact)
            return phantom.APP_ERROR, artifact

        return phantom.APP_SUCCESS, artifact

    # Function used to sort threat list in descending order, and deleting duplicate entries
    # from the list based on 'threat id' and 'threat type'
    def _get_threat_updates(self, action_result, rest_params, source_id, container_count):

        threat_list = []

        # Fetching threat list for specific threat IDs
        if source_id:
            # Making list of all threat IDs and stripping spaces from values if present
            source_id_list = source_id.split(",")
            source_id_list = [id.strip(' ') for id in source_id_list]

            # params_list with all specific threat IDs to pass in the API
            params_list = []

            for id in source_id_list:
                params_list = params_list + ["m_{}".format(str(id))]

            # Searching threat ID in the database to get its threat type
            # Endpoint used is /threat/search
            return_value, json_resp = self._make_rest_call(
                PHISHME_ENDPOINT,
                action_result,
                params={"threatId": params_list, "threatType": "malware"}
            )

            # Something went wrong with the request
            if phantom.is_fail(return_value):
                return action_result.get_status(), threat_list

            # Given source ID not found in the database
            if not json_resp["data"]["threats"]:
                self.save_progress("Requested threat ID is not available in the Cofense Intelligence database")
                return phantom.APP_SUCCESS, threat_list

            # Making a list of all threat IDs and its threatType to generate report
            for threat in json_resp["data"]["threats"]:
                # Fetching threatType from the elements of threats list
                # All the elements will have same threat type
                threat_list.append({
                    "threatId": threat["id"],
                    "threatType": str(threat.get("threatType")).lower()
                })

            return phantom.APP_SUCCESS, threat_list

        # getting threat updates
        # Endpoint used is /threat/updates
        return_value, json_resp = self._make_rest_call(PHISHME_API_THREAT_UPDATE, action_result, body=rest_params)

        # Something went wrong with the request
        if phantom.is_fail(return_value):
            return action_result.get_status(), threat_list

        change_log = json_resp["data"]["changelog"]

        # If threat updates are available, the unique list of threat updates
        # will be sorted based on 'occurredOn' parameter
        if change_log:
            threat_list = list({
                (threat_detail['threatId'], threat_detail["threatType"]): threat_detail for threat_detail in change_log
            }.values())

            threat_list.sort(key=lambda x: x["occurredOn"])

        # Filtering out the threats which are deleted from database
        # threat_list = filter(lambda x: x['deleted'] is False, threat_list)
        threat_list = [x for x in threat_list if x['deleted'] is False and x['threatType'] == 'malware']

        self.save_progress("{} malware threat update(s) retrieved".format(str(len(threat_list))))

        # Get the next position and save its state during scheduled polling
        if not self.is_poll_now():
            self.debug_print("Saving next_position parameter for next polling")
            self._state['next_position'] = str(json_resp["data"]["nextPosition"])

        total_containers = container_count
        if container_count > len(threat_list):
            total_containers = len(threat_list)
            self.save_progress("The total number of threat update retrieved is less than maximum containers count")

        # filtering the threat list based on maximum container count given
        threat_list = threat_list[-total_containers:]

        return phantom.APP_SUCCESS, threat_list

    # Function used to generate hash value of the data provided
    def _create_dict_hash(self, input_dict):

        input_dict_str = None

        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            print(str(e))
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str.encode()).hexdigest()


if __name__ == '__main__':
    import sys
    import pudb

    pudb.set_trace()
    if len(sys.argv) < 2:
        print('No test json specified as input')
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = PhishMeConnector()
        connector.print_progress_message = True
        return_value = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(return_value), indent=4))
    exit(0)
