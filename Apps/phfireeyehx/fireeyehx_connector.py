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

# Phantom App imports
import phantom.app as phantom

import requests
import os
import uuid
from zipfile import ZipFile
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault
import phantom.rules as ph_rules
from fireeyehx_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class FireeyeHxConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(FireeyeHxConnector, self).__init__()

        self._state = None
        self._zip_password = None

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.

        :param e: Exception object
        :return: error message
        """
        error_code = ERR_CODE_MSG
        error_msg = ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
        except:
            pass

        try:
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {}".format(error_msg)
            else:
                error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)
        except:
            self.debug_print(PARSE_ERR_MSG)
            error_text = PARSE_ERR_MSG

        return error_text

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        """
        Validate an integer.

        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :param key: input parameter message key
        :allow_zero: whether zero should be considered as valid value or not
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
        """
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, FIREEYEHX_VALID_INT_MSG.format(param=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, FIREEYEHX_VALID_INT_MSG.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, FIREEYEHX_NON_NEG_INT_MSG.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, FIREEYEHX_NON_NEG_NON_ZERO_INT_MSG.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _flatten_response_data(self, response):
        try:
            response_data = response.get('data', {})
            response.update(response_data)
            del response['data']
        except:
            pass

        return response

    def _process_empty_response(self, response, action_result):

        if response.ok:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR,
                "Status Code {}. Empty response and no information in the header.".format(response.status_code)
            ), None
        )

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
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

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(error_msg)),
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
            local_dir = ('{}/{}').format(Vault.get_vault_tmp_dir(), guid)
        else:
            local_dir = '/opt/phantom/vault/tmp/{}'.format(guid)

        self.save_progress("Using temp directory: {0}".format(guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to create temporary vault folder. {}".format(error_msg)), None)

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
                error_msg = self._get_error_message_from_exception(e)
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Unable to write zip file to disk. Error: {0}".format(error_msg)),
                    None)

            try:
                zip_object = ZipFile(zip_file_path)
                zip_object.extractall(pwd=self._zip_password, path=local_dir)
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Unable to extract items from zip file. Error: {0}".format(error_msg)),
                    None)

            try:
                with open("{}/metadata.json".format(local_dir)) as f:
                    metadata = json.load(f)
                target_filename = metadata['req_filename']
                full_target_path = "{}/{}_".format(local_dir, target_filename)

            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Unable to find target filename. Error: {0}".format(error_msg)),
                    None)

            try:
                success, message, vault_id = ph_rules.vault_add(
                    file_location=full_target_path,
                    container=self.get_container_id(),
                    file_name=target_filename
                )
                self.debug_print('vault_add results: success: {}, message: {}, vault_id: {}'.format(
                    success, message, vault_id))
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Unable to store file in Phantom Vault. Error: {0}".format(error_msg)),
                    None)

            if not success:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, "Error: Unable to add the file to vault. {}".format(message)),
                    None
                )

            return RetVal(phantom.APP_SUCCESS, vault_id)

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

        self.save_progress("HX Auth: Process Response - Token Failed")
        message = "HX Auth Failed, please confirm username and password"
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers, params=None, data=None, method='get'):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        hx_url = config.get("hx_hostname").rstrip('/')

        hx_port = config.get("hx_port")
        # Integer validation for 'hx_port' configuration parameter
        ret_val, hx_port = self._validate_integer(action_result, hx_port, "'HX Port' configuration", allow_zero=True)
        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status(), resp_json)

        url = "{}:{}{}".format(hx_url, hx_port, endpoint)

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
                error_msg = self._get_error_message_from_exception(e)
                self.debug_print(self._get_error_message_from_exception(error_msg))
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR,
                        FIREEYEHX_ERR_CONNECTING_TO_SERVER.format(error=error_msg),
                    ),
                    resp_json
                )

        else:
            try:
                r = request_func(
                    url,
                    json=data,
                    headers=headers,
                    verify=config.get('verify_server_cert', False),
                    params=params)
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                self.debug_print(self._get_error_message_from_exception(error_msg))
                return RetVal(
                    action_result.set_status(
                        phantom.APP_ERROR,
                        FIREEYEHX_ERR_CONNECTING_TO_SERVER.format(error=error_msg),
                    ),
                    resp_json
                )

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
        hx_url = config.get("hx_hostname").rstrip('/')

        hx_port = config.get("hx_port")
        # Integer validation for 'hx_port' configuration parameter
        ret_val, hx_port = self._validate_integer(action_result, hx_port, "'HX Port' configuration", allow_zero=True)
        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status(), resp_json)

        url = "{}:{}{}".format(hx_url, hx_port, endpoint)
        self.save_progress("HX Auth: Execute REST Call")
        try:
            r = request_func(
                url,
                auth=(hx_username, hx_password),
                json=data,
                headers=headers,
                verify=config.get('verify_server_cert', False),
                params=params)
        except requests.exceptions.InvalidURL as e:
            self.debug_print(self._get_error_message_from_exception(e))
            return RetVal(action_result.set_status(phantom.APP_ERROR, FIREEYEHX_ERR_INVALID_URL.format(url=url)), resp_json)
        except requests.exceptions.ConnectionError as e:
            self.debug_print(self._get_error_message_from_exception(e))
            return RetVal(action_result.set_status(phantom.APP_ERROR, FIREEYEHX_ERR_CONNECTION_REFUSED.format(url=url)), resp_json)
        except requests.exceptions.InvalidSchema as e:
            self.debug_print(self._get_error_message_from_exception(e))
            return RetVal(action_result.set_status(phantom.APP_ERROR, FIREEYEHX_ERR_INVALID_SCHEMA.format(url=url)), resp_json)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print(self._get_error_message_from_exception(error_msg))
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    FIREEYEHX_ERR_CONNECTING_TO_SERVER.format(error=error_msg),
                ),
                resp_json
            )

        return self.hx_auth_process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Test Connectivity Start")
        # make rest call to custom auth
        hx_uri = "/hx/api/v3/token"

        self.save_progress("Test Connectivity: Preparing API Request")
        ret_val, _ = self.hx_auth_make_rest_call(hx_uri, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
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
        # Integer validation for 'limit' action parameter
        ret_val, limit = self._validate_integer(action_result, limit, "'limit' action")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

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

        summary = action_result.update_summary({})
        endpoints = response.get('data', {}).get('total')
        summary['matched_endpoints'] = endpoints

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

        hx_uri = "/hx/api/v3/hosts/{}/files".format(agent_id)
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
        agent_id = param.get("agent_id")
        req_filename = param.get("req_filename")

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

        hx_uri = "/hx/api/v3/acqs/files/{}".format(acquisition_id)
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header, method='get')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # flatten out data
        response = self._flatten_response_data(response)

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

        hx_uri = "/hx/api/v3/acqs/files/{}.zip".format(acquisition_id)
        token_header = {'x-feapi-token': fe_auth_token, 'Accept': 'application/octet-stream'}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header, method='get')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

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

        # req_timestamp = param.get('req_timestamp')
        # external_id = param.get('external_id')

        triage_acq_data = {}

        hx_uri = "/hx/api/v3/hosts/{}/triages".format(agent_id)
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
        sum_state = response.get('state')
        sum_id = response.get('_id')
        summary['state'] = sum_state
        summary['id'] = sum_id

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

        hx_uri = "/hx/api/v3/hosts/{}/sysinfo".format(agent_id)
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header, method='get')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response.get('data'))

        summary = action_result.update_summary({})
        sum_hostname = response.get('data', {}).get('hostname')
        sum_ip = response.get('data', {}).get('primaryIpAddress')
        summary['hostname'] = sum_hostname
        summary['primary_ip'] = sum_ip

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

        hx_uri = "/hx/api/v3/hosts/{}/containment".format(agent_id)
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header,
                                                 method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        sum_message = response.get('message')
        summary['message'] = sum_message

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

        hx_uri = "/hx/api/v3/hosts/{}/containment".format(agent_id)
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header, method='get')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response.get('data'))

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

        hx_uri = "/hx/api/v3/hosts/{}/containment".format(agent_id)
        token_header = {'x-feapi-token': fe_auth_token}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header,
                                                 method='delete')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

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

        hx_uri = "/hx/api/v3/hosts/{}/containment".format(agent_id)
        token_header = {'x-feapi-token': fe_auth_token}
        contain_data = {'state': 'contain'}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header,
                                                 data=contain_data, method='patch')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        summary = action_result.update_summary({})
        sum_message = response['message']
        summary['message'] = sum_message

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
        name = param.get("name")

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

        for entry in response.get('data', {}).get('entries', []):
            action_result.add_data(entry)

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

            for entry in response.get('data', {}).get('entries', []):
                action_result.add_data(entry)

            total = response.get('data', {}).get('total', 0)
            offset = response.get('data', {}).get('offset', 0)
            limit = response.get('data', {}).get('limit', 0)
            new_offset = offset + limit

            self.debug_print('Total: {}; New Offset: {}'.format(total, new_offset))

            stop = new_offset >= HARD_LIMIT or new_offset >= total
            search_data['offset'] = new_offset

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_alert(self, param):

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

        # Starting Get Alert API Call
        alert_id = param["alert_id"]

        hx_uri = "/hx/api/v3/alerts/{}".format(alert_id)
        token_header = {'x-feapi-token': fe_auth_token, 'Accept': 'application/json'}

        # make rest call
        ret_val, response = self._make_rest_call(hx_uri, action_result, params=None, headers=token_header, method='get')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # flatten out data
        response = self._flatten_response_data(response)

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id: {}".format(self.get_action_identifier()))

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

        elif action_id == 'get_alert':
            ret_val = self._handle_get_alert(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            return self.set_status(phantom.APP_ERROR, FIREEYEHX_STATE_FILE_CORRUPT_ERR)

        # get the asset config
        config = self.get_config()

        self._zip_password = config.get('zip_password', 'unzip-me')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
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
            login_url = BaseConnector._get_phantom_base_url() + "login"
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: {}".format(e))
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
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
