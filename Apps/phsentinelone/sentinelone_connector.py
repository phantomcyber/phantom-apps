# File: sentinelone_connector.py
# Copyright (c) SentinelOne, 2018-2021
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from __future__ import print_function, unicode_literals
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from sentinelone_consts import *
from sentinelone_utilities import KennyLoggins, logging
import requests
import json
import time
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import unquote


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SentineloneConnector(BaseConnector):

    def __init__(self):
        super(SentineloneConnector, self).__init__()
        self._state = None
        self._base_url = None
        self.HEADER = {"Content-Type": "application/json"}
        kl = KennyLoggins()
        self._log = kl.get_logger(app_name='phsentinelone', file_name='connector', log_level=logging.DEBUG, version='2.1.0')
        self._log.info('initialize_client=complete')

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

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Status Code {}. Empty response and no information in the header".format(response.status_code)
            ), None
        )

    def _process_html_response(self, response, action_result):
        status_code = response.status_code
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)
        message = unquote(message)
        message = message.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        try:
            resp_json = r.json()
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(err_msg)
                ), None
            )
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)
        if not r.text:
            return self._process_empty_response(r, action_result)
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        config = self.get_config()
        resp_json = None
        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )
        url = "{}{}".format(self._base_url, endpoint)
        self._log.info(('action=make_rest_call url={}').format(url))
        try:
            r = request_func(
                url,
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except requests.exceptions.ConnectionError:
            err_msg = 'Error Details: Connection Refused from the Server'
            return RetVal(action_result.set_status(phantom.APP_ERROR, err_msg), resp_json)
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(err_msg)
                ), resp_json
            )
        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to SentinelOne Console/API")
        header = self.HEADER
        header["Authorization"] = "APIToken %s" % self.token
        body = {
                "data": {
                    "apiToken": self.token
                }
        }
        ret_val, response = self._make_rest_call('/web/api/v2.1/users/login/by-api-token', action_result, params=None, headers=header, data=json.dumps(body), method='post')
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()
        self.save_progress("Test Connectivity Passed")
        self.save_progress("Login to SentinelOne Console/API was successful")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_hash(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        hash = param['hash']
        description = param['description']
        os_family = param['os_family']
        summary = action_result.update_summary({})
        summary['hash'] = hash
        summary['description'] = description
        header = self.HEADER
        header["Authorization"] = "APIToken %s" % self.token
        params = {"value": hash, "type": "black_hash"}
        ret_val, response = self._make_rest_call('/web/api/v2.1/restrictions', action_result, headers=header, params=params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            if response.get('pagination', {}).get('totalItems') != 0:
                return action_result.set_status(phantom.APP_ERROR, "Hash already exists")
            else:
                body = {
                    "data": {
                        "description": description,
                        "osType": os_family,
                        "type": "black_hash",
                        "value": hash,
                        "source": "phantom"
                    },
                    "filter": {
                        "tenant": "true"
                    }
                }
                ret_val, response = self._make_rest_call('/web/api/v2.1/restrictions', action_result, headers=header, method='post', data=json.dumps(body))
                if phantom.is_fail(ret_val):
                    return action_result.get_status()
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Did not get proper response from the server")

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully Added Hash to Block List")

    def _handle_unblock_hash(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        hash = param['hash']
        summary = action_result.update_summary({})
        summary['hash'] = hash
        header = self.HEADER
        header["Authorization"] = "APIToken %s" % self.token
        hash_id = ""
        params = {"value": hash, "type": "black_hash"}
        ret_val, response = self._make_rest_call('/web/api/v2.1/restrictions', action_result, headers=header, params=params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            if response['pagination']['totalItems'] == 0:
                return action_result.set_status(phantom.APP_ERROR, "Hash not found")
            elif response['pagination']['totalItems'] > 1:
                return action_result.set_status(phantom.APP_ERROR, "Multiple IDs for {hash}: {total_items}".format(hash=hash, total_items=response['pagination']['totalItems']))
            else:
                hash_id = response['data'][0]['id']
                body = {
                    "data": {
                        "ids": [hash_id],
                        "type": "black_hash"
                    }
                }
                ret_val, response = self._make_rest_call('/web/api/v2.1/restrictions', action_result, headers=header, data=json.dumps(body), params=params, method='delete')
                if phantom.is_fail(ret_val):
                    self.save_progress("Deleting Hash Failed.  Error: {0}".format(action_result.get_message()))
                    return action_result.get_status()
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Did not get proper response from the server")

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully Deleted hash")

    def _handle_quarantine_device(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip_hostname = param['ip_hostname']
        try:
            ret_val = self._get_agent_id(ip_hostname, action_result)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Did not get proper response from the server")
        self.save_progress('Agent query: {}'.format(ret_val))
        if ret_val == '0':
            return action_result.set_status(phantom.APP_ERROR, "Endpoint not found")
        elif ret_val == '99':
            return action_result.set_status(phantom.APP_ERROR, "More than one endpoint found")
        else:
            summary = action_result.update_summary({})
            summary['ip_hostname'] = ip_hostname
            summary['agent_id'] = ret_val
            header = self.HEADER
            header["Authorization"] = "APIToken %s" % self.token
            body = {
                "data": {},
                "filter": {
                    "isActive": "true",
                    "ids": [ret_val],
                }
            }
            ret_val, response = self._make_rest_call('/web/api/v2.1/agents/actions/disconnect', action_result, params=None, headers=header, data=json.dumps(body), method='post')
            if phantom.is_fail(ret_val):
                self.save_progress("Quarantine Device Failed.  Error: {0}".format(action_result.get_message()))
                return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully Quarantined device")

    def _handle_unquarantine_device(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip_hostname = param['ip_hostname']
        try:
            ret_val = self._get_agent_id(ip_hostname, action_result)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Did not get proper response from the server")
        self.save_progress('Agent query: {}'.format(ret_val))
        if ret_val == '0':
            return action_result.set_status(phantom.APP_ERROR, "Endpoint not found")
        elif ret_val == '99':
            return action_result.set_status(phantom.APP_ERROR, "More than one endpoint found")
        else:
            summary = action_result.update_summary({})
            summary['ip_hostname'] = ip_hostname
            summary['agent_id'] = ret_val
            header = self.HEADER
            header["Authorization"] = "APIToken %s" % self.token
            body = {
                "data": {},
                "filter": {
                    "isActive": "true",
                    "ids": [ret_val],
                }
            }
            ret_val, response = self._make_rest_call('/web/api/v2.1/agents/actions/connect', action_result, params=None, headers=header, data=json.dumps(body), method='post')
            if phantom.is_fail(ret_val):
                self.save_progress("Unquarantine Device Failed.  Error: {0}".format(action_result.get_message()))
                return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully Unquarantined device")

    def _handle_mitigate_threat(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        s1_threat_id = param['s1_threat_id']
        action = param['action']
        summary = action_result.update_summary({})
        summary['s1_threat_id'] = s1_threat_id
        summary['action'] = action
        header = self.HEADER
        header["Authorization"] = "APIToken %s" % self.token
        body = {
            "data": {},
            "filter": {
                "ids": [s1_threat_id],
            }
        }
        ret_val, response = self._make_rest_call('/web/api/v2.1/threats/mitigate/{}'.format(action), action_result, headers=header, data=json.dumps(body), method='post')
        if phantom.is_fail(ret_val):
            self.save_progress("Failed to mitigate threat. Error: {0}".format(action_result.get_message()))
            return action_result.get_status()
        action_result.add_data(response)
        try:
            if response.get('data', {}).get('affected') == 0:
                self.save_progress("Failed to mitigate threat. Threat ID not found")
                return action_result.set_status(phantom.APP_ERROR, "Failed to mitigate threat. Threat ID not found")
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Did not get proper response from the server")
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully mitigated threat")

    def _handle_scan_endpoint(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip_hostname = param['ip_hostname']
        try:
            ret_val = self._get_agent_id(ip_hostname, action_result)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Did not get proper response from the server")
        self.save_progress('Agent query: {}'.format(ret_val))
        if ret_val == '0':
            return action_result.set_status(phantom.APP_ERROR, "Endpoint not found")
        elif ret_val == '99':
            return action_result.set_status(phantom.APP_ERROR, "More than one endpoint found")
        else:
            summary = action_result.update_summary({})
            summary['ip_hostname'] = ip_hostname
            summary['agent_id'] = ret_val
            header = self.HEADER
            header["Authorization"] = "APIToken %s" % self.token
            body = {
                "data": {},
                "filter": {
                    "ids": ret_val
                }
            }
            ret_val, response = self._make_rest_call('/web/api/v2.1/agents/actions/initiate-scan', action_result, headers=header, data=json.dumps(body), method='post')
            self.save_progress("Ret_val: {0}".format(ret_val))
            if phantom.is_fail(ret_val):
                self.save_progress("Failed to scan endpoint. Error: {0}".format(action_result.get_message()))
                return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_endpoint_info(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip_hostname = param['ip_hostname']
        try:
            ret_val = self._get_agent_id(ip_hostname, action_result)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Did not get proper response from the server")
        self.save_progress('Agent query: {}'.format(ret_val))
        if ret_val == '0':
            return action_result.set_status(phantom.APP_ERROR, "Endpoint not found")
        elif ret_val == '99':
            return action_result.set_status(phantom.APP_ERROR, "More than one endpoint found")
        else:
            summary = action_result.update_summary({})
            summary['ip_hostname'] = ip_hostname
            summary['agent_id'] = ret_val
            header = self.HEADER
            header["Authorization"] = "APIToken %s" % self.token
            params = {"ids": [ret_val]}
            ret_val, response = self._make_rest_call('/web/api/v2.1/agents', action_result, headers=header, params=params)
            self.save_progress("Ret_val: {0}".format(ret_val))
            if phantom.is_fail(ret_val):
                self.save_progress("Failed to get the endpoint information.  Error: {0}".format(action_result.get_message()))
                return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_threat_info(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        s1_threat_id = param['s1_threat_id']
        summary = action_result.update_summary({})
        summary['s1_threat_id'] = s1_threat_id
        header = self.HEADER
        header["Authorization"] = "APIToken %s" % self.token
        params = {"ids": [s1_threat_id]}
        ret_val, response = self._make_rest_call('/web/api/v2.1/threats', action_result, headers=header, params=params)
        self.save_progress("Ret_val: {0}".format(ret_val))
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_agent_id(self, search_text, action_result):
        header = self.HEADER
        header["Authorization"] = "APIToken %s" % self.token
        params = {"query": search_text}
        ret_val, response = self._make_rest_call('/web/api/v2.1/agents', action_result, headers=header, params=params, method='get')
        if phantom.is_fail(ret_val):
            return str(-1)
        endpoints_found = len(response['data'])
        self.save_progress("Endpoints found: {}".format(str(endpoints_found)))
        action_result.add_data(response)
        if endpoints_found == 0:
            return '0'
        elif endpoints_found > 1:
            return '99'
        else:
            return response['data'][0]['id']

    def _handle_on_poll(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        container_count = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))
        end_time = int(time.time())
        if self.is_poll_now() or self._state.get("first_run", True):
            start_time = end_time - SENTINELONE_24_HOUR_GAP
        else:
            start_time = self._state.get('last_ingestion_time', end_time - SENTINELONE_24_HOUR_GAP)
        self._log.info(('action=on_poll start_time={} end_time={} container_count={}').format(start_time, end_time, container_count))
        response_status, threats_list = self._get_alerts(action_result=action_result, start_time=start_time, end_time=end_time, max_limit=container_count)
        if phantom.is_fail(response_status):
            return action_result.get_status()
        if threats_list:
            self.save_progress('Ingesting data')
        else:
            self.save_progress('No alerts found')
        for threat in threats_list:
            container_id = self._create_container(threat)
            if not container_id:
                continue
            artifacts_creation_status, artifacts_creation_msg = self._create_artifacts(threat=threat, container_id=container_id)
            if phantom.is_fail(artifacts_creation_status):
                self.debug_print(('Error while creating artifacts for container with ID {container_id}. {error_msg}').format(
                    container_id=container_id, error_msg=artifacts_creation_msg))
        self._state['first_run'] = False
        self._state['last_ingestion_time'] = end_time
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_alerts(self, action_result, start_time, end_time, max_limit=None):
        threats_list = []
        self.save_progress('Getting threat data')
        header = self.HEADER
        header["Authorization"] = "APIToken %s" % self.token
        s1_start_time = datetime.fromtimestamp(start_time).strftime('%Y-%m-%dT%H:%M:%S.000000Z')
        s1_end_time = datetime.fromtimestamp(end_time).strftime('%Y-%m-%dT%H:%M:%S.000000Z')
        params = {"createdAt__gte": s1_start_time, "createdAt__lte": s1_end_time, "limit": 1000}
        ret_val, response = self._make_rest_call('/web/api/v2.1/threats', action_result=action_result, headers=header, params=params)
        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)
        try:
            threats_list += response.get('data')
            nextCursor = response.get('pagination', {}).get('nextCursor')
            while nextCursor:
                ret_val, response = self._make_rest_call('/web/api/v2.1/threats', action_result=action_result, headers=header, params=params)
                self.save_progress("Ret_val: {0}".format(ret_val))
                threats_list += response.get('data')
                nextCursor = response.get('pagination', {}).get('nextCursor')
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Did not get proper response from the server"), None
        self.save_progress("Total threats found: {threats}".format(threats=len(threats_list)))
        return (phantom.APP_SUCCESS, threats_list)

    def _create_container(self, threat):
        """ This function is used to create the container in Phantom using threat data.
        :param threat: Data of single threat
        :return: container_id
        """
        container_dict = dict()
        self._log.info(('action=create_container threat={}').format(json.dumps(threat)))
        agent_computer_name = threat.get('agentRealtimeInfo', {}).get('agentComputerName') or "unknown"
        confidence_level = threat.get('threatInfo', {}).get('confidenceLevel')
        s1_threat_id = threat.get('threatInfo', {}).get('threatId')
        threat_name = threat.get('threatInfo', {}).get('threatName')
        severity = "Medium"
        if threat.get('threatInfo', {}).get('confidenceLevel') == 'malicious':
            severity = "High"
        container_name = "{confidence_level} activity on {agent_computer_name} ({threat_name})".format(confidence_level=confidence_level,
            agent_computer_name=agent_computer_name,
            threat_name=threat_name)
        container_dict['name'] = container_name
        container_dict['source_data_identifier'] = s1_threat_id
        container_dict['label'] = "sentinelone"
        container_dict['severity'] = severity
        tags = {'identified_at': threat.get('threatInfo', {}).get('identifiedAt')}
        container_dict['tags'] = [('{}={}').format(x, tags[x]) for x in tags if tags[x] is not None]
        container_creation_status, container_creation_msg, container_id = self.save_container(container=container_dict)
        if phantom.is_fail(container_creation_status):
            self.debug_print(container_creation_msg)
            self.save_progress(('Error while creating container for threat {threat_name}. {error_message}').format(
                threat_name=threat_name, error_message=container_creation_msg))
            return
        else:
            return container_id

    def _create_artifacts(self, threat, container_id):
        """ This function is used to create artifacts in given container using threat data.
        :param threat: Data of single threat
        :param container_id: ID of container in which we have to create the artifacts
        :return: status(success/failure), message
        """
        artifacts_list = []
        self._log.info(('action=create_artifacts threat={} container_id={}').format(json.dumps(threat), container_id))
        agent_computer_name = threat.get('agentRealtimeInfo', {}).get('agentComputerName') or "unknown"
        confidence_level = threat.get('threatInfo', {}).get('confidenceLevel')
        s1_threat_id = threat.get('threatInfo', {}).get('threatId')
        threat_name = threat.get('threatInfo', {}).get('threatName')
        artifact_dict = {}
        container_name = "{confidence_level} activity on {agent_computer_name} ({threat_name})".format(confidence_level=confidence_level,
            agent_computer_name=agent_computer_name,
            threat_name=threat_name)
        artifact_dict['name'] = 'artifact for {}'.format(container_name)
        artifact_dict['source_data_identifier'] = s1_threat_id
        artifact_dict['label'] = "sentinelone"
        artifact_dict['container_id'] = container_id
        cef = threat
        # Add specific 'contains' objects to cef
        cef['sourceHostName'] = threat.get('agentRealtimeInfo', {}).get('agentComputerName')
        cef["s1_threat_id"] = threat.get('threatInfo', {}).get('threatId')
        # TODO: Prevent SHA1 of command line parameters from being presented as a file hash
        if threat.get('threatInfo', {}).get('maliciousProcessArguments') != '':
            cef['fileHashSha1'] = threat.get('threatInfo', {}).get('sha1')
        artifact_dict['cef'] = cef
        artifacts_list.append(artifact_dict)
        create_artifact_status, create_artifact_msg, _ = self.save_artifacts(artifacts_list)
        if phantom.is_fail(create_artifact_status):
            return (phantom.APP_ERROR, create_artifact_msg)
        return (phantom.APP_SUCCESS, 'Artifacts created successfully')

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        self.debug_print('action_id', self.get_action_identifier())
        self._log.info(('action_id={}').format(self.get_action_identifier()))
        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)
        elif action_id == 'block_hash':
            ret_val = self._handle_block_hash(param)
        elif action_id == 'unblock_hash':
            ret_val = self._handle_unblock_hash(param)
        elif action_id == 'quarantine_device':
            ret_val = self._handle_quarantine_device(param)
        elif action_id == 'unquarantine_device':
            ret_val = self._handle_unquarantine_device(param)
        elif action_id == 'mitigate_threat':
            ret_val = self._handle_mitigate_threat(param)
        elif action_id == 'scan_endpoint':
            ret_val = self._handle_scan_endpoint(param)
        elif action_id == 'get_endpoint_info':
            ret_val = self._handle_get_endpoint_info(param)
        elif action_id == 'get_threat_info':
            ret_val = self._handle_get_threat_info(param)
        return ret_val

    def initialize(self):
        self._log.info('action=initialize status=start')
        self._state = self.load_state()
        self._log.info(('action=initialize state={}').format(self._state))
        config = self.get_config()
        self._base_url = config['sentinelone_console_url']
        self.token = config['sentinelone_api_token']
        return phantom.APP_SUCCESS

    def finalize(self):
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
        import getpass
        password = getpass.getpass("Password: ")
    if username and password:
        try:
            login_url = SentineloneConnector._get_phantom_base_url() + '/login'
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
        connector = SentineloneConnector()
        connector.print_progress_message = True
        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    exit(0)


if __name__ == '__main__':
    main()
