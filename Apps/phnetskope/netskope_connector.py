# File: netskope_connector.py
# Copyright (c) 2018-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

import json
import time
import hashlib
import os
from datetime import datetime
from urlparse import urlparse
from bs4 import BeautifulSoup
import requests

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

from netskope_consts import *


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class NetskopeConnector(BaseConnector):

    def __init__(self):

        super(NetskopeConnector, self).__init__()

        self._state = None
        self._server_url = None
        self._api_key = None

    @staticmethod
    def _process_empty_response(response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

    @staticmethod
    def _process_html_response(response, action_result):
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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text.encode('utf-8'))

        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = NETSKOPE_ERROR_CONNECTING_SERVER
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    @staticmethod
    def _process_json_response(response, action_result):
        """ This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(str(e))), None)

        if 200 <= response.status_code < 399 and resp_json.get('error', '') == 'error':

            error_message = response.text.replace('{', '{{').replace('}', '}}')

            if resp_json.get('errors') and isinstance(resp_json['errors'], list):
                error_message = ' '.join(resp_json['errors'])
            elif resp_json.get('errors'):
                error_message = resp_json['errors']
            # You should process the error returned in the json
            message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                         error_message)
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        error_message = response.text.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, error_message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data') and (self.get_action_identifier() != "get-file" or
                                                         not (200 <= response.status_code < 399)):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the API talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, params=None, timeout=None):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param params: request parameters
        :param timeout: wait for REST call to complete
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        if not params:
            params = {}

        config = self.get_config()

        try:
            self._server_url = config[NETSKOPE_CONFIG_SERVER_URL].strip('/').encode('utf-8')
            self._api_key = config[NETSKOPE_CONFIG_API_KEY]
        except:
            self.debug_print('Error while encoding server URL')
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error while encoding server URL"),
                          resp_json)

        params.update({'token': self._api_key})

        try:
            request_func = getattr(requests, 'get')
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format('get')), resp_json)

        # Create a URL to connect to
        url = "{server_url}{endpoint}".format(server_url=self._server_url, endpoint=endpoint)

        # Setting path for temp file
        temp_file_path = '{dir}{asset}_temp_file'.format(dir=self.get_state_dir(), asset=self.get_asset_id())
        try:
            if self.get_action_identifier() == 'get_file' and params.get('op', '') == 'download-url':
                with (request_func(url, params=params, timeout=timeout, stream=True)) as requests_response:
                    # API returns 200 in all cases, so for get-file check whether the content-type is 'json'
                    # and field 'error' is available, consider it as an error
                    error_response_expr = 'json' in requests_response.headers.get('Content-Type', '') and \
                                          requests_response.json().get('error', '') == 'error'

                    # Check if API response is success, and write it into temp file in case of success
                    if 200 <= requests_response.status_code < 399 and not error_response_expr:
                        # Store response into file
                        with open(temp_file_path, 'wb') as temp_file:
                            for chunk in requests_response.iter_content(chunk_size=1024):
                                if chunk:
                                    temp_file.write(chunk)

                        return RetVal(phantom.APP_SUCCESS, resp_json)
            else:
                requests_response = request_func(url, params=params, timeout=timeout)
        except Exception as e:
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
            # It was throwing exception on str(e) in some cases,
            # So if it throws exception while handling the exception,
            # return message without using exception message
            try:
                message = 'Error connecting to server. Details: {0}'.format(str(e))
            except:
                return RetVal(action_result.
                              set_status(phantom.APP_ERROR,
                                         "Error connecting to server. Please check for valid server URL"), resp_json)
            # Added this check as default exception message was showing api_key in exception message
            if 'token=' in str(e):
                message = 'Error while connecting to the server'
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

        return self._process_response(requests_response, action_result)

    def _handle_test_connectivity(self, param):
        """ This function is used to handle the test connectivity.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(NETSKOPE_CONNECTION_MSG)

        request_param = {
            'limit': NETSKOPE_TEST_CONNECTIVITY_LIMIT
        }

        # make rest call
        ret_val, _ = self._make_rest_call(endpoint=NETSKOPE_CONNECTIVITY_ENDPOINT, action_result=action_result,
                                          params=request_param, timeout=30)

        if phantom.is_fail(ret_val):
            self.save_progress(NETSKOPE_CONNECTIVITY_FAIL_MSG)
            return action_result.get_status()

        self.save_progress(NETSKOPE_CONNECTIVITY_PASS_MSG)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file(self, param):
        """ This function is used to handle get_file action.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        file_param = param[NETSKOPE_JSON_FILE]
        profile_param = param[NETSKOPE_JSON_PROFILE]

        details_status, file_id, file_name, profile_id = self._get_file_and_profile_details(action_result=action_result,
                                                                                            file_param=file_param,
                                                                                            profile_param=profile_param)

        if phantom.is_fail(details_status):
            return action_result.get_status()

        request_param = {
            'op': 'download-url',
            'file_id': file_id,
            'quarantine_profile_id': profile_id
        }

        self.save_progress('Downloading file')
        # make rest call
        ret_val, _ = self._make_rest_call(endpoint=NETSKOPE_QUARANTINE_ENDPOINT, action_result=action_result,
                                          params=request_param)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        temp_file_path = '{dir}{asset}_temp_file'.format(dir=self.get_state_dir(), asset=self.get_asset_id())

        generate_file_hash_status, file_hash = self._generate_file_hash(file_path=temp_file_path)

        if phantom.is_fail(generate_file_hash_status):
            return action_result.set_status(phantom.APP_ERROR, status_message='Downloaded file does not exist')

        vault_file_list = Vault.get_file_info(vault_id=file_hash, container_id=self.get_container_id())

        for vault_file_item in vault_file_list:
            if vault_file_item['vault_id'] == file_hash and vault_file_item['name'] == file_name:
                vault_id = vault_file_item['vault_id']
                break
        # If vault item not found in the file list
        else:
            vault_add_file_dict = Vault.add_attachment(file_location=temp_file_path,
                                                       container_id=self.get_container_id(), file_name=file_name)
            vault_id = vault_add_file_dict['vault_id']

        action_result.add_data({
            'vault_id': vault_id,
            'file_name': file_name
        })

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['vault_id'] = vault_id

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_file_and_profile_details(self, action_result, file_param, profile_param):
        """ This action is used to get the file and profile details based on the input provided by user.

        :param action_result: Object of ActionResult class
        :param file_param: Input provided by the user (file id or file name)
        :param profile_param: Input provided by the user (profile param)
        :return: status (success, failure), file_id, file_name, profile_id
        """

        request_params = {
            'op': 'get-files'
        }
        request_status, request_response = self._make_rest_call(endpoint=NETSKOPE_QUARANTINE_ENDPOINT,
                                                                action_result=action_result, params=request_params)

        if phantom.is_fail(request_status):
            return action_result.get_status(), None, None, None

        if not request_response.get('data', {}).get('quarantined'):
            return action_result.set_status(phantom.APP_ERROR, status_message='No data found'), None, None, None

        for item in request_response['data']['quarantined']:
            # Check for matching profile_id
            if item['quarantine_profile_id'].lower() == profile_param.lower() or \
                    item['quarantine_profile_name'].lower() == profile_param.lower():
                # Set the profile_id
                profile_id = item['quarantine_profile_id']
                # Check for file in the resultant profile
                for file_item in item['files']:
                    if file_item['file_id'] == file_param or \
                            file_item['quarantined_file_name'].lower() == file_param.lower():
                        file_id = file_item['file_id']
                        file_name = file_item['quarantined_file_name']
                        return phantom.APP_SUCCESS, file_id, file_name, profile_id

        return action_result.set_status(phantom.APP_ERROR, status_message='No file or profile found'), None, None, None

    @staticmethod
    def _generate_file_hash(file_path):
        """ This function will read file from the file_path and generate the sha1 hash for the file

        :param file_path: Location of the file
        :return: phantom.APP_SUCCESS/phantom.APP_ERROR, file_hash
        """

        if not os.path.exists(file_path):
            return phantom.APP_ERROR, None

        sha1_hash = hashlib.sha1()

        with open(file_path, 'rb') as file_obj:
            for chunk in iter(file_obj.read(1024)):
                sha1_hash.update(chunk)

        sha1_hash = sha1_hash.hexdigest()

        return phantom.APP_SUCCESS, sha1_hash

    def _handle_list_files(self, param):
        """ This function is used to list files.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = {'op': NETSKOPE_PARAM_LIST_FILES}

        request_status, request_response = self._make_rest_call(endpoint=NETSKOPE_QUARANTINE_ENDPOINT,
                                                                action_result=action_result, params=params)

        if phantom.is_fail(request_status):
            return action_result.get_status()

        if not request_response.get('data', {}).get('quarantined', []):
            return action_result.set_status(phantom.APP_ERROR, "No quarantine file data found")

        for quarantine_profile in request_response['data']['quarantined']:
            file_list = quarantine_profile.get('files', [])
            for file_info in file_list:
                file_info.update(
                    {
                        'quarantine_profile_id': quarantine_profile['quarantine_profile_id'],
                        'quarantine_profile_name': quarantine_profile['quarantine_profile_name']
                    })
                action_result.add_data(file_info)

        summary = action_result.update_summary({})
        summary['total_files'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _verify_time(self, start_time, end_time):
        """ This function is used to verify time parameters.

        :param start_time: start_time epoch
        :param end_time: end_time epoch
        :return: status success/failure with appropriate message
        """

        # Validate start_time parameter
        try:
            start_time = int(float(start_time))
        except:
            self.debug_print(NETSKOPE_INVALID_START_TIME)
            return phantom.APP_ERROR, NETSKOPE_INVALID_START_TIME

        # Validate end_time parameter
        try:
            end_time = int(float(end_time))
        except:
            self.debug_print(NETSKOPE_INVALID_END_TIME)
            return phantom.APP_ERROR, NETSKOPE_INVALID_END_TIME

        # Validate start_time and end_time for negation
        if start_time < 0 or end_time < 0:
            self.debug_print(NETSKOPE_INVALID_TIME)
            return phantom.APP_ERROR, NETSKOPE_INVALID_TIME

        # Compare value of start_time and end_time
        if start_time >= end_time:
            self.debug_print(NETSKOPE_INVALID_TIME_RANGE)
            return phantom.APP_ERROR, NETSKOPE_INVALID_TIME_RANGE

        return phantom.APP_SUCCESS, NETSKOPE_VALID_TIME

    def _handle_run_query(self, param):
        """ This function is used to run query against a given IP.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # param values for IP, start_time and end_time
        ip = param[NETSKOPE_PARAM_IP]

        start_time = param.get(NETSKOPE_PARAM_START_TIME)
        if start_time and not isinstance(start_time, (float, int)):
            return action_result.set_status(phantom.APP_ERROR, NETSKOPE_INVALID_START_TIME)

        # If end time not available, set current time as end_time
        end_time = param.get(NETSKOPE_PARAM_END_TIME, time.time())

        if not isinstance(end_time, (float, int)):
            return action_result.set_status(phantom.APP_ERROR, NETSKOPE_INVALID_END_TIME)
        end_time = int(end_time)

        if not start_time:
            # If start time not available, set time prior to 24 hours as start_time
            start_time = end_time - NETSKOPE_24_HOUR_GAP
        start_time = int(start_time)

        # number of values to skip for pagination
        skip_value = NETSKOPE_INITIAL_SKIP_VALUE
        params = {
            'query': NETSKOPE_QUERY_PARAM.format(srcip=ip, dstip=ip),
            'type': 'page',
            'skip': str(skip_value)
        }

        # verify start_time and end_time parameters
        time_status, time_response = self._verify_time(start_time, end_time)

        if phantom.is_fail(time_status):
            return action_result.set_status(phantom.APP_ERROR, time_response)

        params.update(
            {
                'starttime': start_time,
                'endtime': end_time
            }
        )

        # List for data of page and application events
        page_event_list = []
        application_event_list = []

        # Dict for event details
        event_details = {}

        while True:
            request_status_page, request_response_page = self._make_rest_call(endpoint=NETSKOPE_EVENTS_ENDPOINT,
                                                                              action_result=action_result,
                                                                              params=params)

            if phantom.is_fail(request_status_page):
                return action_result.get_status()

            if request_response_page.get('status') == 'error':
                return action_result.set_status(phantom.APP_ERROR, "Error finding data")

            if not request_response_page.get('data', []):
                break

            for event in request_response_page.get('data', []):
                page_event_list.append(event)

            # Skip 5000 values to move to next page
            skip_value += NETSKOPE_UPDATE_SKIP_VALUE

            params.update(
                {
                    'skip': str(skip_value)
                }
            )

        if page_event_list:
            event_details['page'] = page_event_list

        # Update skip value back to 0 for application data
        skip_value = NETSKOPE_INITIAL_SKIP_VALUE

        params.update(
            {
                'type': 'application',
                'skip': str(skip_value)
            }
        )

        while True:

            request_status_application, request_response_application = self.\
                _make_rest_call(endpoint=NETSKOPE_EVENTS_ENDPOINT, action_result=action_result, params=params)

            if phantom.is_fail(request_status_application):
                return action_result.get_status()

            if request_response_application.get('status') == 'error':
                return action_result.set_status(phantom.APP_ERROR, "Error finding data")

            if not request_response_application.get('data', []):
                break

            for event in request_response_application.get('data', []):
                application_event_list.append(event)

            # Skip 5000 values to move to next page
            skip_value += NETSKOPE_UPDATE_SKIP_VALUE

            params.update(
                {
                    'skip': str(skip_value)
                }
            )

        if application_event_list:
            event_details['application'] = application_event_list

        if not event_details:
            return action_result.set_status(phantom.APP_ERROR, status_message='No Data found')

        # Add data for page and application
        action_result.add_data(event_details)

        summary = action_result.update_summary({})
        summary['total_page_events'] = len(page_event_list)
        summary['total_application_events'] = len(application_event_list)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):
        """ This function is used to handle on_poll.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))

        # end time is current time for both scenarios
        end_time = int(time.time())

        # If it is a manual poll or first run, ingest data of last 24 hours
        if self.is_poll_now() or self._state.get('first_run', True):
            start_time = end_time - NETSKOPE_24_HOUR_GAP

        # If it is a scheduled poll, ingest from last_ingestion_time
        else:
            start_time = self._state.get('last_ingestion_time', end_time - NETSKOPE_24_HOUR_GAP)

        # Get the alerts based on start_time and end_time
        response_status, alerts_list = self._get_alerts(action_result=action_result, start_time=start_time,
                                                        end_time=end_time, max_limit=container_count)

        if phantom.is_fail(response_status):
            return action_result.get_status()

        if alerts_list:
            self.save_progress('Ingesting data')
        else:
            self.save_progress('No alerts found')

        for alert in alerts_list:
            # Create a container for each alert
            container_id = self._create_container(alert)

            # If there is any error during creation of alert, skip that alert
            if not container_id:
                continue

            # Create artifacts for specific alert
            artifacts_creation_status, artifacts_creation_msg = self._create_artifacts(alert=alert,
                                                                                       container_id=container_id)

            if phantom.is_fail(artifacts_creation_status):
                self.debug_print('Error while creating artifacts for container with ID {container_id}. {error_msg}'.
                                 format(container_id=container_id, error_msg=artifacts_creation_msg))

        # Store it into state_file, so that it can be used in next ingestion
        self._state['first_run'] = False
        self._state['last_ingestion_time'] = end_time

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_alerts(self, action_result, start_time, end_time, max_limit=None):
        """ This function is used to get the list of alerts in specified time period.

        :param action_result: Object of ActionResult class
        :param start_time: Start time in epoch
        :param end_time: End time in epoch
        :return: status (success/failure), list of alerts
        """

        default_limit = NETSKOPE_DEFAULT_LIMIT
        alerts_list = []
        skip = NETSKOPE_INITIAL_SKIP_VALUE

        self.save_progress('Getting alerts data')

        while True:

            # If max_limit is greater than default_limit, use default_limit as limit otherwise use max_limit as limit
            if max_limit and max_limit > default_limit:
                limit = default_limit
            else:
                limit = max_limit

            request_params = {
                'limit': limit,
                'skip': skip,
                'starttime': start_time,
                'endtime': end_time,
                'type': "Malware"
            }

            request_status, request_response = self._make_rest_call(endpoint=NETSKOPE_ON_POLL_ENDPOINT,
                                                                    action_result=action_result, params=request_params)

            if phantom.is_fail(request_status):
                return action_result.get_status(), None

            # If data is empty, we have retrieved all the alerts
            if not request_response.get('data'):
                break

            alerts_list += request_response['data']
            # Increase the count so that we can skip that many alerts in next iteration
            skip += limit

            if max_limit:
                max_limit -= limit

                # If max_limit is reached, break
                if max_limit <= 0:
                    break

        return phantom.APP_SUCCESS, alerts_list

    def _create_container(self, alert):
        """ This function is used to create the container in Phantom using alert data.

        :param alert: Data of single alert
        :return: container_id
        """

        container_dict = dict()
        container_dict['name'] = '{alert_name}-{id}'.format(alert_name=alert['alert_name'], id=alert['_id'])
        container_dict['source_data_identifier'] = container_dict['name']
        container_dict['start_time'] = '{time}Z'.format(time=datetime.utcfromtimestamp(alert['timestamp']).isoformat())

        container_creation_status, container_creation_msg, container_id = self.save_container(container=container_dict)

        if phantom.is_fail(container_creation_status):
            self.debug_print(container_creation_msg)
            self.save_progress('Error while creating container for alert {alert_name}. '
                               '{error_message}'.format(alert_name=alert['alert_name'],
                                                        error_message=container_creation_msg))
            return None

        return container_id

    def _create_artifacts(self, alert, container_id):
        """ This function is used to create artifacts in given container using alert data.

        :param alert: Data of single alert
        :param container_id: ID of container in which we have to create the artifacts
        :return: status(success/failure), message
        """

        artifacts_list = []

        artifacts_mapping = {
            'IP Artifact': {
                'Source IP': ('srcip', ['ip']),
                'Destination IP': ('dstip', ['ip'])
            },
            'Email Artifact': {
                'Email': ('user', ['email']),
                'Source Email': ('from_user', ['email'])
            },
            'URL Artifact': {
                'URL': ('url', ['url'])
            },
            'Domain Artifact': {
                'Organization': ('org', ['domain']),
                'Page': ('page', ['domain']),
                'Domain': ('domain', ['domain'])
            }
        }

        for artifact_name, artifact_keys in artifacts_mapping.iteritems():
            temp_dict = {}
            cef = {}
            cef_types = {}

            # If it is a URL artifact get create URL and domain both from URL and
            # add it as an artifact
            if artifact_name == 'URL Artifact':

                alert['domain'] = self._get_domain_from_url(alert['url'])

                if not phantom.is_url(alert['url']):
                    alert['url'] = 'http://{url}'.format(url=alert['url'])

            for artifact_key, artifact_tuple in artifact_keys.iteritems():
                if alert.get(artifact_tuple[0]):
                    cef[artifact_key] = alert[artifact_tuple[0]]
                    cef_types[artifact_key] = artifact_tuple[1]

            # Add into artifacts dictionary if it is available
            if cef:
                temp_dict['cef'] = cef
                temp_dict['cef_types'] = cef_types
                temp_dict['name'] = artifact_name
                temp_dict['container_id'] = container_id
                temp_dict['source_data_identifier'] = self._create_dict_hash(temp_dict)

                artifacts_list.append(temp_dict)

        create_artifact_status, create_artifact_msg, _ = self.save_artifacts(artifacts_list)

        if phantom.is_fail(create_artifact_status):
            return phantom.APP_ERROR, create_artifact_msg

        return phantom.APP_SUCCESS, 'Artifacts created successfully'

    @staticmethod
    def _get_domain_from_url(url):
        """ This function is used to get the domain from given URL. It uses urlparse if url is valid Phantom URL,
        otherwise splits with / and considers first part as a domain

        :param url: URL from which we have to extract the domain
        :return: Extracted domain
        """

        if phantom.is_url(url):
            return urlparse(url)[1]

        return url.split('/')[0]

    def _create_dict_hash(self, input_dict):
        """ This function is used to generate the hash from dictionary.

        :param input_dict: Dictionary for which we have to generate the hash
        :return: hash
        """

        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            print str(e)
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str).hexdigest()

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        self.debug_print("action_id", self.get_action_identifier())

        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'get_file': self._handle_get_file,
            'list_files': self._handle_list_files,
            'run_query': self._handle_run_query,
            'on_poll': self._handle_on_poll
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
        extra initialization of any internal modules. This function MUST return a value phantom.APP_SUCCESS.
        """

        self._state = self.load_state()

        return phantom.APP_SUCCESS

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """

        # Save the state
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
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print ("Accessing the Login page")
            response = requests.get(login_url, verify=False)
            csrftoken = response.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print ("Logging into Platform to get the session id")
            response2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = response2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: {}".format(str(e)))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = NetskopeConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
