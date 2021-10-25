# File: redseal_connector.py
#
# Copyright (c) 2019 Splunk Inc.
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
import json
import requests
import xmltodict
import time
import hashlib

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from redseal_consts import *
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class RedsealConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(RedsealConnector, self).__init__()

        self._state = None
        self._server_url = None
        self._verify_server_cert = False
        self._username = None
        self._password = None

    def _process_empty_response(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR,
                                               "Empty response and no information in the header"), None)

    def _process_xml_response(self, r, action_result):
        """ This function is used to process empty response.

        :param r: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a xml parse
        try:
            text = (xmltodict.parse(r.text))
            if 200 <= r.status_code < 399:
                return RetVal(phantom.APP_SUCCESS, text)
        except Exception as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR,
                                         "Unable to parse XML response. Error: {0}".format(str(e))), None)

        # You should process the error returned in the xml
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

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

        message = u"Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        if status_code == 401:
            error_text = "Invalid credentials"
            message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        elif len(message) > 500:
            message = 'Data from server: Invalid Server URL'

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        """ This function is used to process json response.

        :param r: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".\
                  format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        """ This function is used to process response.

        :param r: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a xml response
        if 'xml' in r.headers.get('Content-Type', ''):
            return self._process_xml_response(r, action_result)

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

        # While getting data from status_url in on_poll we get
        # content-type as text/plain but data is in XML
        # So try to parse it
        try:
            text = (xmltodict.parse(r.text))
            if 200 <= r.status_code < 399:
                return RetVal(phantom.APP_SUCCESS, text)
        except:
            pass

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".\
                  format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None,
                        method="get", timeout=None):
        """ Function that makes the REST call to the device. It's a generic function that can be called from various
            action handlers.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE (Default will be GET)
        :param timeout: Timeout for API call
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        url = endpoint

        # For on poll while getting the status of query the endpoint contains whole URL
        if self._server_url not in endpoint:
            # Create a URL to connect to
            url = "{}{}{}".format(self._server_url, REDSEAL_DATA_ENDPOINT, endpoint)

        try:
            r = request_func(url, auth=(self._username, self._password), data=data, headers=headers, params=params,
                             verify=self._verify_server_cert, timeout=timeout)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".
                                                   format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        """ This function is used to test the connectivity of an asset with given credentials.

        :param param: (not used in this method)
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(REDSEAL_TEST_CONNECTION)

        # test connectivity
        endpoint = ""
        ret_val, response = self._make_rest_call(endpoint=endpoint, action_result=action_result,
                                                 timeout=REDSEAL_TEST_CONNECTIVITY_TIMEOUT)

        # Something went wrong
        if phantom.is_fail(ret_val):
            self.save_progress(REDSEAL_TEST_CONNECTIVITY_FAILED)
            return action_result.get_status()

        self.save_progress(REDSEAL_TEST_CONNECTIVITY_PASSED)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_dict_hash(self, input_dict):
        """ This function is used to generate the hash from dictionary.

        :param input_dict: Dictionary for which we have to generate the hash
        :return: hash
        """

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

    def _ingest_policy_data(self, policy_name, policy_data):
        """ This function is used to ingest the data into Phantom platform.

        :param policy_name: Name of the policy
        :param policy_data: Policy data to ingest into Phantom
        :return: phantom.APP_ERROR/phantom.APP_SUCCESS
        """

        container = dict()

        container['name'] = policy_name
        container['source_data_identifier'] = policy_name
        return_value, message_container, container_id = self.save_container(container)

        if phantom.is_fail(return_value):
            self.save_progress(REDSEAL_CONTAINER_ERROR)
            return phantom.APP_ERROR, message_container

        artifacts = []
        cef_mapping = {
            'Source Address Range': 'SourceAddressRange',
            'Destination Address Range': 'DestAddressRange',
            'Destination ports': 'DestPorts',
            'Source Tree ID': 'SourceSubnetId',
            'Destination Tree ID': 'DestSubnetId',
            'Protocols': 'Protocols'
        }

        cef_types_mapping = {
            'Source Address Range': ['ip', 'redseal address range'],
            'Destination Address Range': ['ip', 'redseal address range'],
            'Destination ports': ['port'],
            'Source Tree ID': ['redseal tree id'],
            'Destination Tree ID': ['redseal tree id'],
            'Protocols': []
        }

        for zone in policy_data:
            temp_dict = {}
            cef = {}
            cef_types = {}

            for key, value in cef_mapping.iteritems():
                cef[key] = zone[value]
                cef_types[key] = cef_types_mapping[key]

            temp_dict['cef'] = cef
            temp_dict['cef_types'] = cef_types
            temp_dict['container_id'] = container_id
            temp_dict['name'] = 'Zone Access Details Artifact'
            temp_dict['source_data_identifier'] = self._create_dict_hash(temp_dict)
            artifacts.append(temp_dict)

        status, message_artifact, artifact_ids = self.save_artifacts(artifacts)

        if phantom.is_fail(status):
            self.save_progress(REDSEAL_ARTIFACT_ERROR)
            return phantom.APP_ERROR, message_artifact

        return phantom.APP_SUCCESS, "Successfully created container and artifacts"

    def _get_policy_list(self, action_result):
        """ This function is used to get a list of policies.

        :param action_result: Object of ActionResult class
        :return: status, list of policies
        """

        # Make REST call
        ret_val, response = self._make_rest_call(endpoint=REDSEAL_POLICY_ENDPOINT, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Get list of policies from the response
        policies = response.get('list', {}).get('Policy', [])

        return phantom.APP_SUCCESS, policies

    def _get_zone_pairs(self, zone_details):
        """ This function is used to get the zone pairs for which the ZonePairStatus is Warning or Fail.

        :param zone_details: List of ZonePairCompliance for particular policy
        :return: List of tuples (source_zone, destination_zone)
        """

        zone_list = []
        if isinstance(zone_details, list):
            for zone in zone_details:
                # If zone pair status is warning or fail append it into the list as a tuple
                if zone['ZonePairStatus'] == 'Warning' or zone['ZonePairStatus'] == 'Fail':
                    # First item of tuple is source_zone and second item is destination_zone
                    temp_tuple = (zone['SourceZone']['Name'], zone['DestinationZone']['Name'])
                    zone_list.append(temp_tuple)

        elif isinstance(zone_details, dict):
            if zone_details['ZonePairStatus'] == 'Warning' or zone_details['ZonePairStatus'] == 'Fail':
                # First item of tuple is source_zone and second item is destination_zone
                temp_tuple = (zone_details['SourceZone']['Name'], zone_details['DestinationZone']['Name'])
                zone_list.append(temp_tuple)

        return zone_list

    def _get_query_response(self, status_url, action_result):
        """ This function is used to get query response from status_url.

        :param status_url: Status URL for particular query
        :param action_result: Object of ActionResult class
        :return: status, query result
        """

        response_data = []
        result_url = None

        # Retry for 6 times at interval of 5 seconds
        ret_val, response = self._make_rest_call(endpoint=status_url, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        for i in range(5):

            # If task status is success, get result URL and break out of loop
            if response.get('WebAppAsyncTaskStatus', {}).get('taskStatus') == 'SUCCEEDED':
                result_url = response.get('WebAppAsyncTaskStatus', {}).get('resultsUrl')
                if result_url:
                    break

            time.sleep(5)

            ret_val, response = self._make_rest_call(endpoint=status_url, action_result=action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        if not result_url:
            return phantom.APP_SUCCESS, None

        # Get response from result_url
        ret_val, response = self._make_rest_call(endpoint=result_url, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        # Convert OrderedDict to normal dict
        response = json.loads(json.dumps(response))

        # Iterate through access details
        for item in response.get('Data', {}).get('ZonePairAccessDetails-array', []):
            # If access details is approved, continue
            if item:
                if isinstance(item.get('ZonePairAccessDetails'), list):
                    for inner_item in item['ZonePairAccessDetails']:
                        if inner_item['status'] == 'APPROVED':
                            continue

                        # Append response_data to list
                        response_data += inner_item['flows']['ZonePairAccessDetail']
                elif isinstance(item.get('ZonePairAccessDetails'), dict):
                    if item['ZonePairAccessDetails']['status'] == 'APPROVED':
                        continue

                    response_data += item['ZonePairAccessDetails']['flows']['ZonePairAccessDetail']

        return phantom.APP_SUCCESS, response_data

    def _create_zone_query(self, policy_name, zone_pairs, action_result):
        """ This function is used to query the query for all the items in zone_pairs.

        :param policy_name: Name of the policy
        :param zone_pairs: List of tuple containing source_zone and destination_zone
        :param action_result: Object of ActionResult Class
        :return: status, query result data
        """

        query_data = []
        # Iterate through zone pairs and post a query
        for zone_item in zone_pairs:
            endpoint = REDSEAL_ZONE_QUERY_ENDPOINT.format(policy_name=policy_name)
            params = {
                'from': zone_item[0],
                'to': zone_item[1],
                'maxRows': 0
            }

            ret_val, response = self._make_rest_call(endpoint=endpoint, params=params, action_result=action_result,
                                                     method='post')

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            status_url = response.get('WebAppAsyncTaskStatus', {}).get('statusUrl')

            if not status_url:
                return action_result.set_status(phantom.APP_ERROR,
                                                status_message='Error while getting data for policy'), None

            # Get the query response using status_url
            ret_val, query_response = self._get_query_response(status_url=status_url, action_result=action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            if query_response:
                query_data += query_response

        return phantom.APP_SUCCESS, query_data

    def _on_poll(self, param):
        """ This function is used to ingest data using poll.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_limit = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))

        # Getting list of incidents according to the request parameters
        response_status, policies_list = self._get_policy_list(action_result)

        # If policy list is not successfully retrieved
        if phantom.is_fail(response_status):
            return action_result.get_status()

        if not policies_list:
            self.save_progress('No policies available')
            return action_result.set_status(phantom.APP_ERROR, status_message='No policies available')

        # If Maximum container count is provided
        if container_limit:
            policies_list = policies_list[:container_limit]

        # Iterate through each policy
        for policy in policies_list:
            # If count of Warning rules and failed rules are zero
            if policy['WarningRules'] == '0' and policy['FailedRules'] == '0':
                continue

            policy_name = policy.get("Name", "")
            self.save_progress('Getting data for policy {}'.format(policy_name))

            # Get the list of tuples consist of zone pairs
            zone_pairs = self._get_zone_pairs(policy['ZonePairCompliance'])

            # Create the query for all zone pairs of particular policy
            response_status, policy_data = self._create_zone_query(policy_name, zone_pairs, action_result)

            # Something went wrong
            if phantom.is_fail(response_status):
                return action_result.get_status()

            if policy_data:
                self.save_progress('Ingesting data for policy {}'.format(policy_name))
                # Ingesting incidents and events as containers and artifacts respectively
                status, message = self._ingest_policy_data(policy_name, policy_data)

                # Something went wrong
                if phantom.is_fail(status):
                    return action_result.set_status(phantom.APP_ERROR, message)

        return action_result.set_status(phantom.APP_SUCCESS, status_message="success")

    @staticmethod
    def _process_impact_response(response_impact):
        """ This function is used to process response of security impact

        :param response_impact: Dictionary of impact response
        :return: report_impact_dict: Dictionary updated with processed impact response
        """

        # Creating report for security impact
        report_impact_dict = {}

        report_impact_dict.update({
            'PathStatus': response_impact['SecurityImpact']['PathStatus'],
            'SourceExposureType': response_impact['SecurityImpact']['SourceExposureType'],
            'DestinationExposureType': response_impact['SecurityImpact']['DestinationExposureType'],
            'Destination': response_impact['SecurityImpact']['Destination']
        })

        if response_impact['SecurityImpact'].get('DownStream', {}):
            if isinstance(response_impact['SecurityImpact'].get('DownStream', {}).get('DownstreamQuery', {})
                          .get('Sources', {}).get('Targets', {}).get('Target'), dict):

                source_target_list = []
                source_target_list.append(response_impact['SecurityImpact']['DownStream']['DownstreamQuery']['Sources']
                                          ['Targets']['Target'])
                response_impact['SecurityImpact']['DownStream']['DownstreamQuery']['Sources']['Targets']['Target'] \
                    = source_target_list

            if isinstance(response_impact['SecurityImpact'].get('DownStream', {}).get('DownstreamQuery', {})
                          .get('Destinations', {}).get('Targets', {}).get('Target'), dict):

                dest_target_list = []
                dest_target_list.append(response_impact['SecurityImpact']['DownStream']['DownstreamQuery']
                                        ['Destinations']['Targets']['Target'])
                response_impact['SecurityImpact']['DownStream']['DownstreamQuery']['Destinations']['Targets']['Target'] \
                    = dest_target_list

            report_impact_dict.update({
                'DownStream': response_impact['SecurityImpact']['DownStream']
            })

        return report_impact_dict

    @staticmethod
    def _process_access_response(response_access):
        """ This function is used to process response of access analysis

        :param response_access: Dictionary of access response
        :return: report_access_list: List updated with processed access response
        """

        report_access_list = []
        traffic_segment_list = []

        # Check for dict
        if isinstance(response_access.get('AccessResults', {}).get('TrafficSegment'), dict):
            traffic_segment_list.append(response_access['AccessResults']['TrafficSegment'])

        # Check for list
        elif isinstance(response_access.get('AccessResults', {}).get('TrafficSegment'), list):
            for segments in response_access['AccessResults']['TrafficSegment']:
                traffic_segment_list.append(segments)

        # Iterate through Traffic segment to find individual traffic object
        for segment in traffic_segment_list:
            traffic_list = []
            if isinstance(segment.get('Traffic'), dict):
                traffic_list.append(segment['Traffic'])
            elif isinstance(segment.get('Traffic'), list):
                for traffic in segment['Traffic']:
                    traffic_list.append(traffic)

            # Add data to report list of access details
            report_access_list.append({
                'Source': segment.get('Source', {}),
                'Destination': segment.get('Destination', {}),
                'Traffic': traffic_list
            })

        return report_access_list

    @staticmethod
    def _process_threat_response(response_threats):
        """ This function is used to process response of threat analysis

        :param response_threats: Dictionary of threat response
        :return: report_threats_list: List updated with processed threat response
        """

        # List for data of threats details
        report_threats_list = []
        threat_segment_list = []

        # Check for dict
        if isinstance(response_threats.get('ThreatResults', {}).get('ThreatSegment'), dict):
            threat_segment_list.append(response_threats['ThreatResults']['ThreatSegment'])

        # Check for list
        elif isinstance(response_threats.get('ThreatResults', {}).get('ThreatSegment'), list):
            for segments in response_threats['ThreatResults']['ThreatSegment']:
                threat_segment_list.append(segments)

        # Iterate through Threats segment to find individual threat object
        for segment in threat_segment_list:
            threat_list = []
            if isinstance(segment.get('Threat'), dict):
                threat_list.append(segment['Threat'])
            elif isinstance(segment.get('Threat'), list):
                for threat in segment['Threat']:
                    threat_list.append(threat)

            # Add data to report list of threats details
            report_threats_list.append({
                'Source': segment.get('Source', {}),
                'Destination': segment.get('Destination', {}),
                'Threat': threat_list,
                'LinkStatus': segment.get('LinkStatus', []),
                'totalRowCount': segment.get('totalRowCount', {}),
                'highVulnCount': segment.get('totalRowCount', {}),
                'medVulnCount': segment.get('medVulnCount', {}),
                'lowVulnCount': segment.get('lowVulnCount', {})
            })

        return report_threats_list

    def _handle_run_query(self, param):
        """ This function is used to submit a query to fetch security impact, access details and threats between two
        endpoints.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Setting source id, destination id, source type and destination type.
        source = param.get(REDSEAL_SOURCE_ID, "")
        destination = param.get(REDSEAL_DESTINATION_ID, "")
        source_type = param[REDSEAL_SOURCE_TYPE].replace(" ", "")
        destination_type = param[REDSEAL_DESTINATION_TYPE].replace(" ", "")

        # Endpoints for REST call
        endpoint_impact = REDSEAL_QUERY_IMPACT_ENDPOINT
        endpoint_access = REDSEAL_QUERY_ACCESS_ENDPOINT
        endpoint_threats = REDSEAL_QUERY_THREATS_ENDPOINT

        # API request data to be sent in XML format
        data_impact = REDSEAL_PUT_REQUEST_DATA_BODY.format(source=source, source_type=source_type,
                                                           destination=destination, destination_type=destination_type,
                                                           query_type=REDSEAL_QUERY_TYPE_IMPACT)

        data_access = REDSEAL_PUT_REQUEST_DATA_BODY.format(source=source, source_type=source_type,
                                                           destination=destination, destination_type=destination_type,
                                                           query_type=REDSEAL_QUERY_TYPE_ACCESS)

        data_threats = REDSEAL_PUT_REQUEST_DATA_BODY.format(source=source, source_type=source_type,
                                                            destination=destination, destination_type=destination_type,
                                                            query_type=REDSEAL_QUERY_TYPE_THREATS)

        # Setting up headers
        headers = {'Content-Type': 'application/xml'}

        # Make REST call
        ret_val_impact, response_impact = self._make_rest_call(endpoint=endpoint_impact, action_result=action_result,
                                                               headers=headers, method="put", data=data_impact)

        if phantom.is_fail(ret_val_impact):
            return action_result.get_status()

        # Check if response contains a message for invalid request
        if response_impact.get('Message'):
            message = REDSEAL_NO_ID_MESSAGE
            if response_impact.get('Message', {}).get('Text') == REDSEAL_SUBMIT_PUT_ERROR:
                message = REDSEAL_INVALID_URL_ERROR
            return action_result.set_status(phantom.APP_ERROR, message)

        # Make REST call
        ret_val_access, response_access = self._make_rest_call(endpoint=endpoint_access, action_result=action_result,
                                                               headers=headers, method="put", data=data_access)

        if phantom.is_fail(ret_val_access):
            return action_result.get_status()

        # Check if response contains a message for invalid request
        if response_access.get('Message'):
            message = REDSEAL_NO_ID_MESSAGE
            if response_access.get('Message', {}).get('Text') == REDSEAL_SUBMIT_PUT_ERROR:
                message = REDSEAL_INVALID_URL_ERROR
            return action_result.set_status(phantom.APP_ERROR, message)

        # Make REST call
        ret_val_threats, response_threats = self._make_rest_call(endpoint=endpoint_threats, action_result=action_result,
                                                                 headers=headers, method="put", data=data_threats)

        if phantom.is_fail(ret_val_threats):
            return action_result.get_status()

        if response_threats.get('Message'):
            message = REDSEAL_NO_ID_MESSAGE
            if response_threats.get('Message', {}).get('Text') == REDSEAL_SUBMIT_PUT_ERROR:
                message = REDSEAL_INVALID_URL_ERROR
            return action_result.set_status(phantom.APP_ERROR, message)

        # Check if any detailed data is found between two given endpoints

        message_impact = 'Impact details found'
        if response_impact.get('SecurityImpact', {}).get('Message'):
            message_impact = response_impact['SecurityImpact']['Message'].get('Text', '')

        message_access = 'Access details found'
        if response_access.get('AccessResults', {}).get('Message'):
            message_access = response_access['AccessResults']['Message'].get('Text', '')

        message_threat = 'Threat details found'
        if response_threats.get('ThreatResults', {}).get('Message'):
            message_threat = response_threats['ThreatResults']['Message'].get('Text', '')

        # Creating report for security impact
        report_impact = {}
        if response_impact.get('SecurityImpact', {}):
            report_impact = self._process_impact_response(response_impact)

        # List for data of access details
        report_access_list = self._process_access_response(response_access)

        # List for data of threats details
        report_threats_list = self._process_threat_response(response_threats)

        # Dict for data of impact, access and threats
        data_details = {}

        if report_impact:
            data_details['impact'] = report_impact

        if report_access_list:
            data_details['access'] = report_access_list

        if report_threats_list:
            data_details['threats'] = report_threats_list

        message = '{}. {}. {}.'.format(message_impact, message_access, message_threat)

        if not data_details:
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        # Add data for impact, access and threats
        action_result.add_data(data_details)

        return action_result.set_status(phantom.APP_SUCCESS, status_message=message)

    def _handle_list_subnets(self, param):
        """ This function is used to list the subnets.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        type = param[REDSEAL_TYPE]

        endpoint = '{}/{}'.format(REDSEAL_SUBNET_ENDPOINT, type)
        ret_val, response = self._make_rest_call(endpoint=endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if type == 'Unmapped Hosts':
            # Iterate through all the hosts
            for host in response.get('FullGroup', {}).get('Computers', {}).get('Host', []):
                action_result.add_data(host)

        else:
            # no subnet found
            if not response.get('FullGroup', {}).get('Subnets', {}):
                return action_result.set_status(phantom.APP_ERROR, 'No subnet(s) found')

            # Iterate through all the groups
            for group in response.get('FullGroup', {}).get('Subnets', {}).get('Subnet', []):
                action_result.add_data(group)

        summary = action_result.update_summary({})
        summary['total_subnets'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_devices(self, param):
        """ This function is used to list all the devices.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        device_type = param[REDSEAL_TYPE]

        device_endpoint = '{}/{}'.format(REDSEAL_DEVICE_ENDPOINT, device_type)
        ret_val, response = self._make_rest_call(endpoint=device_endpoint, action_result=action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if device_type == 'Host':
            # Iterate through all the devices
            for device in response.get('FullGroup', {}).get('Computers', {}).get('Host', []):
                action_result.add_data(device)
        else:
            if isinstance(response.get('FullGroup', {}).get('Computers', {}).get('Device', []), dict):
                device = response.get('FullGroup', {}).get('Computers', {}).get('Device', {})
                action_result.add_data(device)

            else:
                # Iterate through all the devices
                for device in response.get('FullGroup', {}).get('Computers', {}).get('Device', []):
                    action_result.add_data(device)

        summary = action_result.update_summary({})
        summary['total_devices'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'list_subnets': self._handle_list_subnets,
            'list_devices': self._handle_list_devices,
            'run_query': self._handle_run_query,
            'on_poll': self._on_poll
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        # Access values in asset config by the name
        self._server_url = config[REDSEAL_CONFIG_SERVER_URL].strip('/')
        self._verify_server_cert = config.get(REDSEAL_CONFIG_VERIFY_SERVER_CERT, False)
        self._username = config[REDSEAL_CONFIG_USERNAME]
        self._password = config[REDSEAL_CONFIG_PASSWORD]

        return phantom.APP_SUCCESS

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """

        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

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
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print "Unable to get session id from the platform. Error: {0}".format(str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = RedsealConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
