# --
# File: fireeyehx_connector.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --
# -----------------------------------------
# Phantom FireEye HX Connector python file
# -----------------------------------------

import json

# import dateutil.parser as parser
# Phantom App imports
import phantom.app as phantom

import requests
import os
# import shutil
import uuid
from zipfile import ZipFile
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class FireeyeHxConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(FireeyeHxConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        # self._base_url = None

    def _flatten_response_data(self, response):
        try:
            response_data = response.get('data', {})
            response.update(response_data)
            del response['data']
        except:
            pass

        return response

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))),
                None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_octet_response(self, r, action_result):

        guid = uuid.uuid4()

        if hasattr(Vault, 'get_vault_tmp_dir'):
            local_dir = Vault.get_vault_tmp_dir() + guid
        else:
            local_dir = '/opt/phantom/vault/tmp/{}'.format(guid)

        self.save_progress("Using temp directory: {0}".format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to create temporary vault folder.", e)

        action_params = self.get_current_param()
        acq_id = action_params.get('acquisition_id', 'no_id')

        zip_file_path = "{0}/{1}.zip".format(local_dir, acq_id)

        # Try to stream the response to a file
        if r.status_code == 200:
            try:
                with open(zip_file_path, 'wb') as f:
                    f.write(r.content)
                    # shutil.copyfileobj(r.raw, f)
            except Exception as e:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Unable to write zip file to disk. Error: {0}".format(str(e))),
                    None)

            try:
                zip_object = ZipFile(zip_file_path)
                zip_object.extractall(pwd=self._zip_password, path=local_dir)
            except Exception as e:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Unable to extract items from zip file. Error: {0}".format(str(e))),
                    None)

            try:
                with open(local_dir + '/metadata.json') as f:
                    metadata = json.load(f)
                target_filename = metadata['req_filename']
                full_target_path = local_dir + '/' + target_filename + '_'

            except Exception as e:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Unable to find target filename. Error: {0}".format(str(e))),
                    None)

            try:
                vault_results = Vault.add_attachment(full_target_path, self.get_container_id(), file_name=target_filename)
                return RetVal(phantom.APP_SUCCESS, vault_results)

            except Exception as e:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Unable to store file in Phantom Vault. Error: {0}".format(str(e))),
                    None)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        if 'octet' in r.headers.get('Content-Type', ''):
            return self._process_octet_response(r, action_result)

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def hx_auth_process_response(self, r, action_result):
        self.save_progress("HX Auth: Process Response")
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process HX Auth Response and return custom auth token
        if r.status_code == 204:
            self.save_progress("HX Auth: Process Response - Token Success")
            token = r.headers.get('x-feapi-token')
            return RetVal(phantom.APP_SUCCESS, token)
        else:
            self.save_progress("HX Auth: Process Response - Token Failed")
            message = "HX Auth Failed, please confirm username and password"
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers, params=None, data=None, method='get'):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        hx_url = config.get("hx_hostname")
        hx_port = config.get("hx_port")
        url = hx_url + ":" + hx_port + endpoint

        if ".zip" in url:
            try:
                r = request_func(
                    url,
                    json=data,
                    headers=headers,
                    verify=config.get('verify_server_cert', False),
                    params=params,
                    stream=True)
            except Exception as e:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))),
                    resp_json)

        else:
            try:
                r = request_func(
                    url,
                    json=data,
                    headers=headers,
                    verify=config.get('verify_server_cert', False),
                    params=params)
            except Exception as e:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))),
                    resp_json)

        return self._process_response(r, action_result)

    def hx_auth_make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method='get'):

        config = self.get_config()

        hx_username = config.get("hx_username")
        hx_password = config.get("hx_password")
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        hx_url = config.get("hx_hostname")
        hx_port = config.get("hx_port")
        url = hx_url + ":" + hx_port + endpoint
        self.save_progress("HX Auth: Execute REST Call")
        try:
            r = request_func(
                url,
                auth=(hx_username, hx_password),
                json=data,
                headers=headers,
                verify=config.get('verify_server_cert', False),
                params=params)
        except Exception as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))),
                resp_json)

        return self.hx_auth_process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Test Connectivity Start")
        # make rest call to custom auth
        hx_uri = "/hx/api/v3/token"

        self.save_progress("Test Connectivity: Preparing API Request")
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed. Error: {0}".format(action_result.get_message()))
            return action_result.get_status()

        self.save_progress("Test Connectivity Auth Token Complete")

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_endpoints(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting Hosts API Call
        limit = param.get('limit')
        search_term = param.get('search')
        params = {}
        if search_term:
            params.update({'search': search_term})
        if limit:
            params.update({'limit': limit})

        hx_uri = "/hx/api/v3/hosts"
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=params, headers=token_header,
                                                 method='get')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        # action_result.add_data({})

        summary = action_result.update_summary({})
        endpoints = response['data']['total']
        summary['Matched Endpoints'] = endpoints

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_start_acquisition(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting Get File API Call
        agent_id = param["agent_id"]
        req_path = param["req_path"]
        req_filename = param["req_filename"]

        comment = ""
        external_id = ""
        req_use_api = ""
        comment = param.get('comment')
        external_id = param.get('external_id')
        req_use_api = param.get('req_use_api', False)

        file_acq_data = {'req_path': req_path, 'req_filename': req_filename, 'comment': comment,
                'external_id': external_id, 'req_use_api': req_use_api}

        hx_uri = "/hx/api/v3/hosts/" + agent_id + "/files"
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header,
                                                 data=file_acq_data, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # flatten out data
        response = self._flatten_response_data(response)

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_acquisitions(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting List of File Acquisitions for All Hosts API Call
        agent_id = param.get("agent_id", None)
        req_filename = param.get("req_filename", None)

        search_data = {}
        if agent_id is not None:
            search_data['host._id'] = agent_id
        if req_filename is not None:
            search_data['search'] = req_filename

        hx_uri = "/hx/api/v3/acqs/files"
        token_header = {
            'x-feapi-token': fe_auth_token,
            'Accept': 'application/json'
        }

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=search_data, headers=token_header)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # flatten out data
        response = self._flatten_response_data(response)

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_acquisition_status(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting Get File Status API Call
        acquisition_id = param["acquisition_id"]

        hx_uri = "/hx/api/v3/acqs/files/" + acquisition_id
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header, method='get')

        # flatten out data
        response = self._flatten_response_data(response)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block
        # Starting Get File Status API Call
        acquisition_id = param["acquisition_id"]

        hx_uri = "/hx/api/v3/acqs/files/" + acquisition_id + ".zip"
        token_header = {'x-feapi-token': fe_auth_token, 'Accept': 'application/octet-stream'}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header, method='get')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        # action_result.add_data({})

        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_triage(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting Get Triage API Call
        agent_id = param["agent_id"]

        # req_timestamp = ""
        # external_id = ""
        # req_timestamp = param.get('req_timestamp')
        # external_id = param.get('external_id')

        triage_acq_data = {}

        hx_uri = "/hx/api/v3/hosts/" + agent_id + "/triages"
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header,
                                                 data=triage_acq_data, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # flatten out data
        response = self._flatten_response_data(response)

        action_result.add_data(response)

        summary = action_result.update_summary({})
        sum_state = response['state']
        sum_id = response['_id']
        summary['State'] = sum_state
        summary['ID'] = sum_id

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_system_info(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting Sys Info API Call
        agent_id = param["agent_id"]

        hx_uri = "/hx/api/v3/hosts/" + agent_id + "/sysinfo"
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header, method='get')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response['data'])

        # action_result.add_data({})

        summary = action_result.update_summary({})
        sum_hostname = response['data']['hostname']
        sum_ip = response['data']['primaryIpAddress']
        summary['Hostname'] = sum_hostname
        summary['Primary IP'] = sum_ip

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_device(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting Contain API Call
        agent_id = param["agent_id"]

        hx_uri = "/hx/api/v3/hosts/" + agent_id + "/containment"
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header,
                                                 method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        # action_result.add_data({})
        summary = action_result.update_summary({})
        sum_message = response['message']
        summary['Message'] = sum_message

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_quarantine_status(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting Contain API Call
        agent_id = param["agent_id"]

        hx_uri = "/hx/api/v3/hosts/" + agent_id + "/containment"
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header, method='get')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response['data'])

        # action_result.add_data({})

        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unquarantine_device(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting Contain API Call
        agent_id = param["agent_id"]

        hx_uri = "/hx/api/v3/hosts/" + agent_id + "/containment"
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header,
                                                 method='delete')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        # action_result.add_data({})

        summary = action_result.update_summary({})
        summary['important_data'] = "value"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_set_quarantine_approved(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting Contain API Call
        agent_id = param["agent_id"]

        hx_uri = "/hx/api/v3/hosts/" + agent_id + "/containment"
        token_header = {'x-feapi-token': fe_auth_token}
        contain_data = {'state': 'contain'}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header,
                                                 data=contain_data, method='patch')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        # action_result.add_data({})

        summary = action_result.update_summary({})
        sum_message = response['message']
        summary['Message'] = sum_message

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_host_sets(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting List of File Acquisitions for All Hosts API Call
        name = param.get("name", None)

        search_data = {
            'limit': 100
        }
        if name is not None:
            search_data['name'] = name

        hx_uri = "/hx/api/v3/host_sets"
        token_header = {
            'x-feapi-token': fe_auth_token,
            'Accept': 'application/json'
        }

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=search_data, headers=token_header)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        for e in response.get('data', {}).get('entries', []):
            action_result.add_data(e)

        # action_result.add_data({})

        # summary = action_result.update_summary({})
        # summary['important_data'] = "value"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_host_set(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Starting HX Auth Token Block

        self.save_progress("Auth Token Starting")
        hx_uri = "/hx/api/v3/token"
        ret_val, response = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress("Auth Token Complete")

        fe_auth_token = response

        # Ending HX Auth Token Block

        # Starting List of File Acquisitions for All Hosts API Call
        host_set_id = param['host_set_id']

        hx_uri = "/hx/api/v3/host_sets/{}/hosts".format(host_set_id)
        token_header = {
            'x-feapi-token': fe_auth_token,
            'Accept': 'application/json'
        }

        search_data = {
            'offset': 0
        }

        HARD_LIMIT = 10000
        stop = False
        while not stop:
            # make rest call
            ret_val, response = self._make_rest_call(hx_uri, action_result, params=search_data, headers=token_header)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            for e in response.get('data', {}).get('entries', []):
                action_result.add_data(e)

            total = response.get('data', {}).get('total', 0)
            offset = response.get('data', {}).get('offset', 0)
            limit = response.get('data', {}).get('limit', 0)
            new_offset = offset + limit

            self.debug_print('Total: {}; New Offset: {}'.format(total, new_offset))

            stop = new_offset >= HARD_LIMIT or new_offset >= total
            search_data['offset'] = new_offset

        # action_result.add_data({})

        # summary = action_result.update_summary({})
        # summary['important_data'] = "value"

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_quarantine_status':
            ret_val = self._handle_get_quarantine_status(param)

        elif action_id == 'get_acquisition_status':
            ret_val = self._handle_get_acquisition_status(param)

        elif action_id == 'set_quarantine_approved':
            ret_val = self._handle_set_quarantine_approved(param)

        elif action_id == 'unquarantine_device':
            ret_val = self._handle_unquarantine_device(param)

        elif action_id == 'list_endpoints':
            ret_val = self._handle_list_endpoints(param)

        elif action_id == 'start_acquisition':
            ret_val = self._handle_start_acquisition(param)

        elif action_id == 'get_file':
            ret_val = self._handle_get_file(param)

        elif action_id == 'get_triage':
            ret_val = self._handle_get_triage(param)

        elif action_id == 'quarantine_device':
            ret_val = self._handle_quarantine_device(param)

        elif action_id == 'get_system_info':
            ret_val = self._handle_get_system_info(param)

        elif action_id == 'list_acquisitions':
            ret_val = self._handle_list_acquisitions(param)

        elif action_id == 'list_host_sets':
            ret_val = self._handle_list_host_sets(param)

        elif action_id == 'get_host_set':
            ret_val = self._handle_get_host_set(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._zip_password = config.get('zip_password', 'unzip-me')
        
        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
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

    if (username is not None and password is None):
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = FireeyeHxConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
