# File: fortigate_connector.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
from fortigate_consts import *

import requests
import json
import sys
import re
import socket
import struct
from bs4 import UnicodeDammit


class FortiGateConnector(BaseConnector):

    def __init__(self):

        # Calling the BaseConnector's init function
        super(FortiGateConnector, self).__init__()
        self._api_username = None
        self._api_password = None
        self._api_vdom = None
        self._device = None
        self._verify_server_cert = False
        self._sess_obj = None

        # Dictionary containing message for errors in response of API call
        self._error_resp_dict = {
            FORTIGATE_REST_RESP_BAD_REQUEST: FORTIGATE_REST_RESP_BAD_REQUEST_MSG,
            FORTIGATE_REST_RESP_NOT_AUTH: FORTIGATE_REST_RESP_NOT_AUTH_MSG,
            FORTIGATE_REST_RESP_FORBIDDEN: FORTIGATE_REST_RESP_FORBIDDEN_MSG,
            FORTIGATE_REST_RESP_NOT_ALLOWED: FORTIGATE_REST_RESP_NOT_ALLOWED_MSG,
            FORTIGATE_REST_RESP_ENTITY_LARGE: FORTIGATE_REST_RESP_ENTITY_LARGE_MSG,
            FORTIGATE_REST_RESP_FAIL_DEPENDENCY: FORTIGATE_REST_RESP_FAIL_DEPENDENCY_MSG,
            FORTIGATE_REST_RESP_INTERNAL_ERROR: FORTIGATE_REST_RESP_INTERNAL_ERROR_MSG
        }

        return

    def initialize(self):

        """
        This is an optional function that can be implemented by the AppConnector derived class. Since the configuration
        dictionary is already validated by the time this function is called, it's a good place to do any extra
        initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        config = self.get_config()

        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        self._api_username = self._handle_py_ver_compat_for_input_str(self._python_version, config[FORTIGATE_JSON_USERNAME])
        self._api_password = config[FORTIGATE_JSON_PASSWORD]
        self._api_vdom = config.get(FORTIGATE_JSON_VDOM, '')
        self._verify_server_cert = config.get(FORTIGATE_JSON_VERIFY_SERVER_CERT, False)
        self.set_validator('ip', self._is_ip)

        self._device = self._handle_py_ver_compat_for_input_str(self._python_version, config[FORTIGATE_JSON_URL])

        # removing single occurence of trailing back-slash or forward-slash
        if self._device.endswith('/'):
            self._device = self._device.strip('/').strip('\\')
        elif self._device.endswith('\\'):
            self._device = self._device.strip('\\').strip('/')

        # removing single occurence of leading back-slash or forward-slash
        if self._device.startswith('/'):
            self._device = self._device.strip('/').strip('\\')
        elif self._device.startswith('\\'):
            self._device = self._device.strip('\\').strip('/')

        self._api_vdom = self._handle_py_ver_compat_for_input_str(self._python_version, self._api_vdom)

        return phantom.APP_SUCCESS

    def _handle_py_ver_compat_for_input_str(self, python_version, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param python_version: Information of the Python version
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """
        try:
            if input_str and python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

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
                    error_code = "Error code unavailable"
                    error_msg = e.args[0]
            else:
                error_code = "Error code unavailable"
                error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."
        except:
            error_code = "Error code unavailable"
            error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(self._python_version, error_msg)
        except TypeError:
            error_msg = "Error occurred while connecting to the Fortigate server. Please check the asset configuration and|or the action parameters."
        except:
            error_msg = "Error message unavailable. Please check the asset configuration and|or action parameters."

        return error_code, error_msg

    def _get_net_size(self, net_mask):

        net_mask = net_mask.split('.')

        binary_str = ''
        for octet in net_mask:
            binary_str += bin(int(octet))[2:].zfill(8)

        return str(len(binary_str.rstrip('0')))

    def _get_net_mask(self, net_size):

        host_bits = 32 - int(net_size)

        net_mask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))

        return net_mask

    def _break_ip_addr(self, ip_addr):

        self.debug_print("Action Identifier: {}, IP Address: {}".format(self.get_action_identifier(), ip_addr))

        ip = None
        net_size = None
        net_mask = None

        if ('/' in ip_addr):
            ip, net_size = ip_addr.split('/')
            if not net_size:
                net_size = "32"
            net_mask = self._get_net_mask(net_size)
        elif(' ' in ip_addr):
            ip, net_mask = ip_addr.split()
            net_size = self._get_net_size(net_mask)
        else:
            ip = ip_addr
            net_size = "32"
            net_mask = "255.255.255.255"

        self.debug_print("IP: {}, Net Size: {}, Net Mask: {}".format(ip, net_size, net_mask))

        return (ip, net_size, net_mask)

    # Function that checks given address and return True if address is valid ip address or (ip address and subnet)
    def _is_ip(self, ip_addr):

        try:
            ip_addr = self._handle_py_ver_compat_for_input_str(self._python_version, ip_addr)
            ip, net_size, net_mask = self._break_ip_addr(ip_addr.strip())
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            self.debug_print("Validation for ip_addr failed. Error Code:{0}. Error Message:{1}. For valid IP formats, please refer to the action's documentation.".format(
                                error_code, error_msg))
            return False

        # Validate ip address
        if not phantom.is_ip(ip):
            return False

        # Regex to validate the subnet
        reg_exp = re.compile('^((128|192|224|240|248|252|254).0.0.0)|(255.(((0|128|192|224|240|248|252|254).0.0)'
                             '|(255.(((0|128|192|224|240|248|252|254).0)|255.(0|128|192|224|240|248|252|254|255)))))$')

        # Validate subnet
        if net_mask:
            if not reg_exp.match(net_mask):
                return False

        if net_size:
            try:
                net_size = int(net_size)
            except:
                self.debug_print("net_size: {0} invalid int".format(net_size))
                return False

            if (not (0 < net_size <= 32)):
                return False

        return True

    # Function that checks given address and return True if address is ipv6 address
    def _is_ipv6(self, address):

        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:
            return False

        return True

    def _paginator(self, action_result, endpoint, limit=None, params=None):
        """ This function is used to fetch polocies data using pagination.

        :param action_result: object of ActionResult class
        :param endpoint: REST endpoint that needs to appended to the service address
        :param limit: maximum number of results to be fetched
        :param params: request parameters

        :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), total policies
        """

        total_results = list()
        skip = 0

        # Define per page limit
        page_limit = FORTIGATE_PER_PAGE_DEFAULT_LIMIT

        if limit and limit <= page_limit:
            page_limit = limit

        params.update({'count': page_limit})

        while True:
            params.update({"start": skip})

            # Make rest call
            ret_val, response = self._make_rest_call(endpoint, action_result, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            # If resource not found, its a failure
            if response.get('resource_not_available'):
                self.debug_print(FORTIGATE_REST_RESP_RESOURCE_NOT_FOUND_MSG)
                return action_result.set_status(phantom.APP_ERROR, FORTIGATE_REST_RESP_RESOURCE_NOT_FOUND_MSG), None

            # Fetch data from response
            results = response.get("results")
            if results is None:
                return action_result.set_status(phantom.APP_ERROR, "Unknown error occurred. No data found"), None

            total_results.extend(results)

            if limit and len(total_results) >= limit:
                return phantom.APP_SUCCESS, total_results[:limit]

            # Fetched all data and fetched policies list is empty and not None
            if not results:
                self.debug_print("Fetched all data and fetched results list is empty and not None")
                break

            skip += FORTIGATE_PER_PAGE_DEFAULT_LIMIT

        # Return success with total reports
        return phantom.APP_SUCCESS, total_results

    # Function that makes the REST call to the device,
    # generic function that can be called from various action handlers
    def _make_rest_call(self, endpoint, action_result, data=None, method="get", headers=None, params=None):

        host = self._device
        rest_res = None

        # get, post or put, whatever the caller asked us to use,
        # if not specified the default will be 'get'
        try:
            request_func = getattr(self._sess_obj, method)
        except:
            self.debug_print(FORTIGATE_ERR_API_UNSUPPORTED_METHOD.format(method=method))
            # set the action_result status to error, the handler function
            # will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, FORTIGATE_ERR_API_UNSUPPORTED_METHOD,
                                            method=str(method)), rest_res

        try:
            url = "{0}{1}{2}".format(host, FORTIGATE_BASE_URL, endpoint)
            if endpoint == FORTIGATE_LOGIN:
                url = "{0}{1}".format(host, endpoint)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Please check the asset configuration and action parameters. Error Code: {0}. Error Message: {1}".format(
                error_code, error_msg)), None

        # Make the call
        try:
            response = request_func(url, params=params, data=data, verify=self._verify_server_cert, timeout=(15, 27))
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Error Code: {0}. Error Message: {1}"
                                                   .format(error_code, error_msg)), rest_res

        # rest_res[FORTIGATE_STATUS_CODE] = response.status_code
        if response.status_code in self._error_resp_dict.keys():
            self.debug_print(FORTIGATE_ERR_FROM_SERVER.format(status=response.status_code,
                                                              detail=self._error_resp_dict[response.status_code]))
            # set the action_result status to error, the handler function
            # will most probably return as is
            return (action_result.set_status(phantom.APP_ERROR, FORTIGATE_ERR_FROM_SERVER, status=response.status_code,
                                             detail=self._error_resp_dict[response.status_code]), rest_res)

        if response.status_code == FORTIGATE_REST_RESP_RESOURCE_NOT_FOUND:
            return phantom.APP_SUCCESS, {'resource_not_available': True}
            # return action_result.set_status(phantom.APP_ERROR, "Unauthorized error")
            # message = "Status Code: {0}. Data from server:\n{1}\n".format(response.status_code,
            #     response.text)
            # message = message.replace(u'{', '{{').replace(u'}', '}}')
            # return action_result.set_status(phantom.APP_ERROR, message), None

        if response.status_code == FORTIGATE_REST_RESP_SUCCESS:
            content_type = response.headers['content-type']
            if content_type.find('json') != -1:
                try:
                    rest_res = response.json()
                except Exception as e:
                    error_code, error_msg = self._get_error_message_from_exception(e)
                    msg_string = FORTIGATE_ERR_JSON_PARSE.format(raw_text=response.text, error_code=error_code, error_msg=error_msg)
                    # set the action_result status to error, the handler function
                    # will most probably return as is
                    return action_result.set_status(phantom.APP_ERROR, msg_string), rest_res

            return phantom.APP_SUCCESS, rest_res

        # All other response codes from Rest call are failures
        # The HTTP response does not return error message in case of unknown error code
        err = FORTIGATE_ERR_FROM_SERVER.format(status=response.status_code, detail=FORTIGATE_REST_RESP_OTHER_ERROR_MSG)
        self.debug_print(err)

        # set the action_result status to error, the handler function
        # will most probably return as is
        return (action_result.set_status(phantom.APP_ERROR, err), rest_res)

    # To list policies
    def _list_policies(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # fetch vdom
        vdom = self._handle_py_ver_compat_for_input_str(self._python_version, param.get(FORTIGATE_JSON_VDOM, ''))
        if not vdom and self._api_vdom:
            vdom = self._api_vdom

        # fetch limit
        limit = param.get('limit', FORTIGATE_PER_PAGE_DEFAULT_LIMIT)
        try:
            # validation for integer value
            limit = int(limit)
            if limit <= 0:
                return action_result.set_status(phantom.APP_ERROR, FORTIGATE_LIMIT_VALIDATION_MSG)
        except:
            return action_result.set_status(phantom.APP_ERROR, FORTIGATE_LIMIT_VALIDATION_MSG)

        # create summary object
        summary_data = action_result.update_summary({})

        # Initiating login session
        ret_val = self._login(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # create paginator parameters
        param = dict()

        if vdom:
            param.update({"vdom": vdom})

        # get list of policies
        ret_val, policies = self._paginator(action_result, FORTIGATE_LIST_POLICIES, limit=limit, params=param)

        # Something went wrong
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for policy in policies:
            action_result.add_data(policy)

        # Adding each policy data to action_result
        summary_data['total_policies'] = len(policies)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _test_connectivity(self, param):

        """
        Called when the user depresses the test connectivity button on the Phantom UI.
        Use a basic query to determine if the device IP/hostname, username and password is correct
        """

        action_result = ActionResult()
        self.save_progress(FORTIGATE_TEST_CONNECTIVITY_MSG)
        self.save_progress("Configured URL: {}".format(self._device))

        ret_val = self._login(action_result)

        if phantom.is_fail(ret_val):
            # self.save_progress("Test Connectivity Failed")
            self.save_progress(action_result.get_message())
            # return action_result.get_status()

            # If SSL is enabled and URL configuration has IP address
            if self._verify_server_cert and (phantom.is_ip(self._device) or self._is_ipv6(self._device)):
                # The failure could be due to IP provided in URL instead of hostname
                self.save_progress(FORTIGATE_TEST_WARN_MSG)

            self.set_status(phantom.APP_ERROR, FORTIGATE_TEST_CONN_FAIL)
            return action_result.get_status()

        self.save_progress(FORTIGATE_TEST_ENDPOINT_MSG)

        # Querying endpoint to check connection to device
        status, _ = self._make_rest_call(FORTIGATE_BLOCKED_IPS, action_result)

        if phantom.is_fail(status):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, FORTIGATE_TEST_CONN_FAIL)
            return action_result.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, FORTIGATE_TEST_CONN_SUCC)
        return action_result.get_status()

    # Block IP address
    def _block_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Initiating login session
        ret_val = self._login(action_result)

        # Something went wrong
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # To get parameters
        try:
            ip_addr_obj_name, policy_name, address_create_params, block_params, vdom = self._get_params(param)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_SUCCESS, "Unable to create request parameters. Error Code:{0}. Error Message:{1}".format(error_code, error_msg))

        # Check if address exist
        addr_status, addr_availability = self._is_address_available(ip_addr_obj_name, vdom, action_result)

        if phantom.is_fail(addr_status):
            return action_result.get_status()

        # Check if address does not exist
        if not addr_availability:
            param = dict()
            if vdom:
                param.update({"vdom": vdom})
            else:
                param = None

            # Create Address Entry Phantom Addr {ip}
            add_addr_status, _ = self._make_rest_call(FORTIGATE_ADD_ADDRESS, action_result,
                                                                      data=json.dumps(address_create_params), method="post", params=param)
            # Something went wrong
            if phantom.is_fail(add_addr_status):
                return action_result.set_status(phantom.APP_ERROR, "Unable to create Address object. {0}".format(action_result.get_message()))

        # To get policy id from policy name
        ret_val, policy_id = self._get_policy_id(policy_name, vdom, action_result)

        # Something went wrong
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        dstaddr_status, address_blocked = self._is_address_blocked(ip_addr_obj_name, policy_id, vdom, action_result)

        if phantom.is_fail(dstaddr_status):
            return action_result.get_status()

        # If address already blocked
        if address_blocked:
            return action_result.set_status(phantom.APP_SUCCESS, FORTIGATE_IP_ALREADY_BLOCKED)

        param = dict()
        if vdom:
            param.update({"vdom": vdom})
        else:
            param = None

        # Block the address
        # Add the address entry to policy's destination
        status, response = self._make_rest_call(FORTIGATE_BLOCK_IP.format(policy_id=policy_id),
                                                action_result, data=json.dumps(block_params), method="post", params=param)

        if phantom.is_fail(status):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, FORTIGATE_IP_BLOCKED)

    # Unblock IP address
    def _unblock_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Initiating login session
        ret_val = self._login(action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # To get parameters
        try:
            ip_addr_obj_name, policy_name, _, _, vdom = self._get_params(param)
        except Exception as e:
            error_code, error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_SUCCESS, "Unable to create request parameters. Error Code:{0}. Error Message:{1}".format(error_code, error_msg))

        # To get policy id from policy name
        ret_val, policy_id = self._get_policy_id(policy_name, vdom, action_result)

        # Something went wrong
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Check if address exist
        addr_status, addr_availability = self._is_address_available(ip_addr_obj_name, vdom, action_result)

        if phantom.is_fail(addr_status):
            return action_result.get_status()

        # Check if address does not exist
        if not addr_availability:
            self.debug_print(FORTIGATE_ADDRESS_NOT_AVAILABLE)
            return action_result.set_status(phantom.APP_ERROR, FORTIGATE_ADDRESS_NOT_AVAILABLE)

        param = dict()
        if vdom:
            param.update({"vdom": vdom})
        else:
            param = None

        # Check if address entry is configured in destination of policy
        dstaddr_status, dstaddr_resp = self._make_rest_call(FORTIGATE_GET_BLOCKED_IP.format(policy_id=policy_id, ip=ip_addr_obj_name), action_result, params=param)

        if phantom.is_fail(dstaddr_status):
            return action_result.get_status()

        # If resource not available, indicates that address entry is
        # not configured in policy as destination
        if dstaddr_resp.get('resource_not_available'):
            self.debug_print(FORTIGATE_IP_ALREADY_UNBLOCKED)
            return action_result.set_status(phantom.APP_SUCCESS, FORTIGATE_IP_ALREADY_UNBLOCKED)

        param = dict()
        if vdom:
            param.update({"vdom": vdom})
        else:
            param = None

        # Unblock an IP
        status, _ = self._make_rest_call(FORTIGATE_GET_BLOCKED_IP.format(policy_id=policy_id, ip=ip_addr_obj_name), action_result, method="delete", params=param)

        if phantom.is_fail(status):
            return action_result.get_status()

        # Blocked Successfully
        return action_result.set_status(phantom.APP_SUCCESS, FORTIGATE_IP_UNBLOCKED)

    # Function used to Logging to FortiGate Device
    def _login(self, action_result):

        credential_data = {
            "username": self._api_username,
            "secretkey": self._api_password
        }

        # Initializing session object which would be used for subsequent API calls
        self._sess_obj = requests.session()
        status, response = self._make_rest_call(FORTIGATE_LOGIN, action_result, data=credential_data, method="post")

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        # updating the CSRFTOKEN for authentication
        try:
            self._sess_obj.headers.update({'X-CSRFTOKEN': self._sess_obj.cookies['ccsrftoken'][1:-1]})
        except:
            return action_result.set_status(phantom.APP_ERROR, FORTIGATE_X_CSRFTOKEN_ERROR)

        return phantom.APP_SUCCESS

    # Function used to logout from FortiGate Device
    # Called from finalize method at the end of each action
    def _logout(self):

        # Only initializing action_result for rest calls, not adding it to BaseConnector
        action_result = ActionResult()

        credential_data = {
            "username": self._api_username,
            "secretkey": self._api_password
        }

        status, response = self._make_rest_call(FORTIGATE_LOGOUT, action_result, data=credential_data, method="post")

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    # To get input parameters
    def _get_params(self, param):

        # Mandatory input parameter
        ip_addr = self._handle_py_ver_compat_for_input_str(self._python_version, param[FORTIGATE_JSON_IP])
        policy = self._handle_py_ver_compat_for_input_str(self._python_version, param[FORTIGATE_JSON_POLICY])

        vdom = self._handle_py_ver_compat_for_input_str(self._python_version, param.get(FORTIGATE_JSON_VDOM, ''))

        if not vdom and self._api_vdom:
            vdom = self._api_vdom

        # Here the handling of exception is not required because the custom validator method
        # _is_ip already validates the IP action parameters for all the actions calling this method.
        ip, net_size, net_mask = self._break_ip_addr(ip_addr.strip())

        ip_addr_obj_name = "Phantom Addr {0}_{1}".format(ip, net_size)

        address_create_params = {
            FORTIGATE_JSON_NAME: ip_addr_obj_name,
            FORTIGATE_JSON_TYPE: FORTIGATE_JSON_IP_MASK,
            FORTIGATE_JSON_SUBNET: "{0} {1}".format(ip, net_mask)
        }

        block_params = {
            FORTIGATE_JSON_NAME: ip_addr_obj_name
        }

        return ip_addr_obj_name, policy, address_create_params, block_params, vdom

    # Get the list of matching policies
    # Check if multiple policy exist or no policy available
    # If unique policy exist, fetch the policy id
    def _get_policy_id(self, policy_name, vdom, action_result):

        policies = None
        policy_id = None

        param = dict()
        param.update({
            "key": "name",
            "pattern": policy_name
        })

        if vdom:
            param.update({"vdom": vdom})

        # Get the list of policies available in device
        ret_code, json_resp = self._make_rest_call(FORTIGATE_GET_POLICY, action_result, params=param)

        # Something went wrong
        if phantom.is_fail(ret_code):
            return action_result.get_status(), policy_id

        # If resource not available its a failure
        if json_resp.get('resource_not_available'):
            return action_result.set_status(phantom.APP_ERROR, FORTIGATE_REST_RESP_RESOURCE_NOT_FOUND_MSG), policy_id

        # Get the list of policies
        policies = json_resp.get("results", [])

        # If result is blank or more than one policies exist with same name then return error
        if len(policies) != 1:
            self.debug_print(FORTIGATE_INVALID_POLICIES.format(vdom=vdom))
            return action_result.set_status(phantom.APP_ERROR, FORTIGATE_INVALID_POLICIES.format(vdom=vdom)), policy_id

        policy = policies[0]

        policy_id = policy.get('policyid')
        if not policy_id:
            return action_result.set_status(phantom.APP_ERROR, "Unable to find policy ID for given policy name under virtual domain {}".format(vdom)), None

        # Check if policy does not have action deny, return error
        # Sure that only one policy exist
        if policy.get("action") != "deny":
            self.debug_print(FORTIGATE_INVALID_POLICY_DENY)
            return action_result.set_status(phantom.APP_ERROR, FORTIGATE_INVALID_POLICY_DENY), None

        # If policy action is deny, store policy id
        return phantom.APP_SUCCESS, policy_id

    # To check if address exists or not
    def _is_address_available(self, ip_addr_obj_name, vdom, action_result):

        param = dict()
        param.update({
            "key": "name",
            "pattern": ip_addr_obj_name
        })

        if vdom:
            param.update({"vdom": vdom})

        # Rest call to get the list of Addresses with name Phantom Addr {ip}
        ret_code, json_resp = self._make_rest_call(FORTIGATE_GET_ADDRESSES.format(ip=ip_addr_obj_name), action_result, params=param)
        if phantom.is_fail(ret_code):
            return action_result.get_status(), None

        # Check is address is not available
        if json_resp.get('resource_not_available'):
            return phantom.APP_SUCCESS, False
        # Address Object is available
        return phantom.APP_SUCCESS, True

    # To check if address already blocked
    def _is_address_blocked(self, ip_addr_obj_name, policy_id, vdom, action_result):

        address_blocked = None

        param = dict()
        if vdom:
            param.update({"vdom": vdom})
        else:
            param = None

        ret_code, json_resp = self._make_rest_call(FORTIGATE_GET_BLOCKED_IP.format(policy_id=policy_id, ip=ip_addr_obj_name), action_result, params=param)

        # Something went wrong
        if phantom.is_fail(ret_code):
            return action_result.get_status(), address_blocked

        # Check if resource not available, its an failure scenario
        if json_resp.get('resource_not_available'):
            if self.get_action_identifier() == 'unblock_ip':
                self.debug_print(FORTIGATE_REST_RESP_RESOURCE_NOT_FOUND_MSG)
                return action_result.set_status(phantom.APP_ERROR, FORTIGATE_REST_RESP_RESOURCE_NOT_FOUND_MSG), address_blocked

            # For block ip, if resource not available indicates that address is not blocked
            address_blocked = False
            return phantom.APP_SUCCESS, address_blocked

        # Check if address entry is available in policy destination address
        if not json_resp.get('results'):
            # Address not configured as destination address
            address_blocked = False
            return phantom.APP_SUCCESS, address_blocked

        # if results exist, indicates that address is already configured in destination addresss
        address_blocked = True
        return phantom.APP_SUCCESS, address_blocked

    def handle_action(self, param):
        """
        This function implements the main functionality of the AppConnector. It gets called for every param dictionary
        element in the parameters array. In it's simplest form it gets the current action identifier and then calls a
        member function of it's own to handle the action. This function is expected to create the results of the action
        run that get added to the connector run. The return value of this function is mostly ignored by the
        BaseConnector. Instead it will just loop over the next param element in the parameters array and call
        handle_action again.

        We create a case structure in Python to allow for any number of actions to be easily added.
        """

        # Supported actions by app
        supported_actions = {
            'test_asset_connectivity': self._test_connectivity,
            'block_ip': self._block_ip,
            'unblock_ip': self._unblock_ip,
            'list_policies': self._list_policies
        }

        action = self.get_action_identifier()

        try:
            run_action = supported_actions[action]
        except:
            raise ValueError('action %r is not supported' % action)

        return run_action(param)

    def finalize(self):

        """
        This function gets called once all the param dictionary elements are looped over and no more handle_action calls
        are left to be made. It gives the AppConnector a chance to loop through all the results that were accumulated by
        multiple handle_action function calls and create any summary if required. Another usage is cleanup, disconnect
        from remote devices etc.
        """
        return self._logout()


if __name__ == '__main__':
    import pudb

    pudb.set_trace()
    if len(sys.argv) < 2:
        print('No test json specified as input')
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = FortiGateConnector()
        connector.print_progress_message = True
        connector._handle_action(json.dumps(in_json), None)
    exit(0)
