# File: awsiam_connector.py
# Copyright (c) 2018-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import json
import hmac
import hashlib
import datetime
import collections
from collections import OrderedDict
import requests
import xmltodict
from bs4 import BeautifulSoup
from awsiam_consts import *

try:
    from urllib import urlencode, unquote
except ImportError:
    from urllib.parse import urlencode, unquote

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AwsIamConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AwsIamConnector, self).__init__()

        self._state = None
        self._access_key = None
        self._secret_key = None
        self._response_metadata_dict = None

    @staticmethod
    def _process_empty_response(response, action_result):
        """ This function is used to process empty response.

        :param response: Response data
        :param action_result: Object of ActionResult
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

    @staticmethod
    def _process_xml_response(response, action_result):
        """ This function is used to process XML response.

        :param response: Response data
        :param action_result: Object of ActionResult
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a xml parse
        try:
            text = (xmltodict.parse(response.text.encode('utf-8')))
        except Exception as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR,
                                         "Unable to parse XML response. Error: {0}".format(str(e))), None)

        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, text)

        # At this point, it is the error response
        error_type = text[AWSIAM_JSON_ERROR_RESPONSE][AWSIAM_JSON_ERROR][AWSIAM_JSON_ERROR_TYPE]
        error_code = text[AWSIAM_JSON_ERROR_RESPONSE][AWSIAM_JSON_ERROR][AWSIAM_JSON_ERROR_CODE]
        error_message = text[AWSIAM_JSON_ERROR_RESPONSE][AWSIAM_JSON_ERROR][AWSIAM_JSON_ERROR_MESSAGE]

        error = 'ErrorType: {}\nErrorCode: {}\nErrorMessage: {}'.\
            format(error_type, error_code, error_message.encode('UTF-8'))
        # Process the error returned in the XML
        try:
            message = "Error from server. Status Code: {0} Data from server: {1}".\
                    format(response.status_code, error)
        except Exception:
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                response.status_code, text)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), text)

    @staticmethod
    def _process_html_response(response, action_result):
        """ This function is used to process html response.

        :param response: Response data
        :param action_result: Object of ActionResult
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text.encode('utf-8').encode('utf-8')
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = 'Error while connecting to a server'

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    @staticmethod
    def _process_json_response(response, action_result):
        """ This function is used to process json response.

        :param response: Response data
        :param action_result: Object of ActionResult
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(str(e))), None)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".\
            format(response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process html response.

       :param response: Response data
       :param action_result: Object of ActionResult
       :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
       """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        # Process an xml response
        if 'xml' in response.headers.get('Content-Type', ''):
            return self._process_xml_response(response, action_result)

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
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".\
            format(response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    @staticmethod
    def _aws_sign(key, data):
        """ This function is used to generate cryptographic hash of the provided data.

        :param key: Secret key shared between two communicating endpoints
        :param data: Initial message content that needs to be authenticated
        :return: Cryptographic hash of the actual data combined with the shared secret key
        """

        return hmac.new(key, data.encode('utf-8'), hashlib.sha256).digest()

    def _get_signature_key(self, date_stamp, region_name, service_name):
        """ This function is used to get signature key using AWS Signature Version 4.

        :param date_stamp: Current date time
        :param region_name: Region name where requests are called
        :param service_name: Service name whose requests are called
        return: Signature key generated using AWS Signature Version 4
        """
        k_date = self._aws_sign(('{}{}'.format(AWSIAM_SIGNATURE_V4, self._secret_key)).encode('utf-8'), date_stamp)
        k_region = self._aws_sign(k_date, region_name)
        k_service = self._aws_sign(k_region, service_name)
        k_signing = self._aws_sign(k_service, AWSIAM_SIGNATURE_V4_REQUEST)
        return k_signing

    def _get_headers(self, current_time, params):
        """ This function is used to get headers for requests to be signed using AWS Signature Version 4.

        :param current_time: Current timestamp at time of making request
        :param params: Request URL params
        return: Headers generated by following AWS IAM Signature Version 4 authentication for making request call
        """

        amzdate = current_time.strftime('%Y%m%dT%H%M%SZ')
        datestamp = current_time.strftime('%Y%m%d')

        # 1. Create a canonical request

        # a) Create the canonical headers and signed headers. Header names
        # must be trimmed and lowercase, and sorted in code point order from
        # low to high. Note that there is a trailing \n.
        canonical_headers = 'host:{}\nx-amz-date:{}\n'.format(AWSIAM_HOST, amzdate)

        # b) Create payload hash (hash of the request body content). For GET
        # requests, the payload is an empty string ("").
        payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()

        # c) Combine elements to create canonical request
        canonical_request = '{}\n/\n{}\n{}\n{}\n{}'.\
                            format('GET', params, canonical_headers, AWSIAM_SIGNED_HEADERS, payload_hash)

        # 2. Create the string_to_sign
        # Match the algorithm to the hashing algorithm, either SHA-1 or SHA-256 (recommended)
        credential_scope = '{}/{}/{}/{}'.format(datestamp, AWSIAM_REGION, AWSIAM_SERVICE, AWSIAM_SIGNATURE_V4_REQUEST)
        string_to_sign = '{}\n{}\n{}\n{}'.format(AWSIAM_REQUESTS_SIGNING_ALGO, amzdate, credential_scope,
                                                 hashlib.sha256(canonical_request.encode('utf-8')).hexdigest())

        # 3. Calculate the signature
        # a) Create the signing key using the function defined above.
        signing_key = self._get_signature_key(datestamp, AWSIAM_REGION, AWSIAM_SERVICE)

        # b) Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        authorization_header = '{} Credential={}/{}, SignedHeaders={}, Signature={}'.\
            format(AWSIAM_REQUESTS_SIGNING_ALGO, self._access_key, credential_scope, AWSIAM_SIGNED_HEADERS, signature)

        headers = dict()
        headers[AWSIAM_JSON_AMZ_DATE] = amzdate
        headers[AWSIAM_JSON_AUTHORIZATION] = authorization_header
        return headers

    def _make_rest_call(self, action_result, params=None, data=None, method='get', timeout=None):
        """ This function is used to make the REST call.

        :param action_result: Object of ActionResult class
        :param params: Request parameters
        :param data: Request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param timeout: Timeout of request
        :return: Status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            self._access_key = self._access_key
            self._secret_key = self._secret_key
        except:
            self.debug_print(AWSIAM_CONFIG_PARAMS_ENCODING_ERROR_MSG)
            return RetVal(action_result.set_status(phantom.APP_ERROR, AWSIAM_CONFIG_PARAMS_ENCODING_ERROR_MSG),
                          resp_json)

        if params is None:
            params = OrderedDict()
        params[AWSIAM_JSON_VERSION] = AWSIAM_API_VERSION

        # Sort the params based on the keys in alphabetical order because of Signature Signing Process of AWS IAM
        params = collections.OrderedDict(sorted(params.items()))

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            request_response = request_func(AWSIAM_SERVER_URL, data=data, params=params, timeout=timeout,
                                            headers=self._get_headers(current_time=datetime.datetime.utcnow(),
                                                                      params=urlencode(params)))
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".
                                                   format(str(e))), resp_json)

        return self._process_response(request_response, action_result)

    def _handle_test_connectivity(self, param):
        """ This function is used to handle the test connectivity action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(AWSIAM_CONNECTING_ENDPOINT_MSG)

        params = dict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_TEST_CONNECTIVITY_ENDPOINT

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params,
                                                 timeout=AWSIAM_TIME_OUT)

        if phantom.is_fail(ret_val):
            self.save_progress(AWSIAM_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(AWSIAM_TEST_CONNECTIVITY_PASSED_MSG)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_disable_user(self, param):
        """ This function is used to disable the login profile and access keys of user.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        response_dict = dict()
        username = param[AWSIAM_PARAM_USERNAME]
        disable_access_keys = param.get(AWSIAM_PARAM_DISABLE_ACCESS_KEYS, True)

        # 1. Disable user
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_DISABLE_USER_ENDPOINT
        params[AWSIAM_JSON_USERNAME] = username

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            # a) If Login Profile does not exist, then,
            # 404 error is thrown and it needs to be handled for delete user action
            if not AWSIAM_USER_LOGIN_PROFILE_ALREADY_DELETED_MSG.format(username=username).lower() in \
                   action_result.get_message().lower():
                return action_result.get_status()

            resp_dict = dict()
            resp_dict[AWSIAM_JSON_REQUEST_ID] = response[AWSIAM_JSON_ERROR_RESPONSE][AWSIAM_JSON_REQUEST_ID]
            response_dict.update(resp_dict)
        else:
            response_dict.update(response[AWSIAM_JSON_DELETE_LOGIN_PROFILE_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        # 2. Inactivate the access keys of user based on boolean parameter 'disable_access_keys' provided
        # a) List all user access keys
        if disable_access_keys:
            params = OrderedDict()
            params[AWSIAM_JSON_ACTION] = AWSIAM_LIST_ACCESS_KEYS_ENDPOINT
            params[AWSIAM_JSON_USERNAME] = username

            access_keys_dict = self._get_list_items(action_result, params, AWSIAM_JSON_ACCESS_KEYS)

            if access_keys_dict is None:
                return action_result.get_status()

            list_access_keys = access_keys_dict[AWSIAM_JSON_LIST_RESPONSE]

            for access_key in list_access_keys:
                # b) Inactivate every access key
                params = OrderedDict()
                params[AWSIAM_JSON_ACCESS_KEY_ID] = access_key[AWSIAM_JSON_ACCESS_KEY_ID].encode('utf-8')
                params[AWSIAM_JSON_ACTION] = AWSIAM_UPDATE_ACCESS_KEYS_ENDPOINT
                params[AWSIAM_JSON_STATUS] = AWSIAM_JSON_INACTIVE
                params[AWSIAM_JSON_USERNAME] = username

                # make rest call
                ret_val, response = self._make_rest_call(action_result=action_result, params=params)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                response_dict.update(response[AWSIAM_JSON_UPDATE_ACCESS_KEY_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        action_result.add_data(response_dict)

        return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_USER_DISABLED_MSG.format(username=username))

    def _handle_enable_user(self, param):
        """ This function is used to enable the login profile and access keys of user.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param[AWSIAM_PARAM_USERNAME]
        password = param[AWSIAM_PARAM_PASSWORD]
        enable_access_keys = param.get(AWSIAM_PARAM_ENABLE_ACCESS_KEYS, True)
        response_dict = dict()

        # 1. Enable user
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_ENABLE_USER_ENDPOINT
        params[AWSIAM_JSON_PASSWORD] = password
        params[AWSIAM_JSON_USERNAME] = username

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            # a) If Login Profile already exist, then,
            # 404 error is thrown and it needs to be handled for delete user action
            if not AWSIAM_USER_LOGIN_PROFILE_ALREADY_EXISTS_MSG.format(username=username).lower() in \
                   action_result.get_message().lower():
                return action_result.get_status()

            resp_dict = dict()
            resp_dict[AWSIAM_JSON_REQUEST_ID] = response[AWSIAM_JSON_ERROR_RESPONSE][AWSIAM_JSON_REQUEST_ID]
            response_dict.update(resp_dict)
        else:
            response_dict = response[AWSIAM_JSON_CREATE_LOGIN_PROFILE_RESPONSE]
            response_dict = response_dict[AWSIAM_JSON_CREATE_LOGIN_PROFILE_RESULT][AWSIAM_JSON_LOGIN_PROFILE]
            response_dict.update(response[AWSIAM_JSON_CREATE_LOGIN_PROFILE_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        # 2. Activate the access keys of user based on boolean parameter 'enable_access_keys' provided
        # a) List all user access keys
        if enable_access_keys:
            params = OrderedDict()
            params[AWSIAM_JSON_ACTION] = AWSIAM_LIST_ACCESS_KEYS_ENDPOINT
            params[AWSIAM_JSON_USERNAME] = username

            access_keys_dict = self._get_list_items(action_result, params, AWSIAM_JSON_ACCESS_KEYS)

            if access_keys_dict is None:
                return action_result.get_status()

            list_access_keys = access_keys_dict[AWSIAM_JSON_LIST_RESPONSE]

            for access_key in list_access_keys:
                # b) Activate every access key
                params = OrderedDict()
                params[AWSIAM_JSON_ACCESS_KEY_ID] = access_key[AWSIAM_JSON_ACCESS_KEY_ID].encode('utf-8')
                params[AWSIAM_JSON_ACTION] = AWSIAM_UPDATE_ACCESS_KEYS_ENDPOINT
                params[AWSIAM_JSON_STATUS] = AWSIAM_JSON_ACTIVE
                params[AWSIAM_JSON_USERNAME] = username

                # make rest call
                ret_val, response = self._make_rest_call(action_result=action_result, params=params)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                response_dict.update(response[AWSIAM_JSON_UPDATE_ACCESS_KEY_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        action_result.add_data(response_dict)

        return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_USER_ENABLED_MSG.format(username=username))

    def _handle_assign_policy(self, param):
        """ This function is used to assign the policy to specified user.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param[AWSIAM_PARAM_USERNAME]
        policy_arn = param[AWSIAM_PARAM_POLICY_ARN]

        # 1. Assign policy to user
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_ATTACH_USER_POLICY_ENDPOINT
        params[AWSIAM_JSON_POLICY_ARN] = policy_arn
        params[AWSIAM_JSON_USERNAME] = username

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response[AWSIAM_JSON_ATTACH_USER_POLICY_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_ATTACH_USER_POLICY_MSG.
                                        format(policy_arn=policy_arn, username=username))

    def _handle_remove_policy(self, param):
        """ This function is used to remove the policy from specified user.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param[AWSIAM_PARAM_USERNAME]
        policy_arn = param[AWSIAM_PARAM_POLICY_ARN]

        # 1. Remove policy from user
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_DETACH_USER_POLICY_ENDPOINT
        params[AWSIAM_JSON_POLICY_ARN] = policy_arn
        params[AWSIAM_JSON_USERNAME] = username

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response[AWSIAM_JSON_DETACH_USER_POLICY_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_DETACH_USER_POLICY_MSG.
                                        format(policy_arn=policy_arn, username=username))

    def _handle_detach_policy(self, param):
        """ This function is used to detach the policy from specified role

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        role_name = param[AWSIAM_PARAM_ROLE_NAME]
        policy_arn = param[AWSIAM_PARAM_POLICY_ARN]

        # Check if role already exists or not
        role_exist = self._if_role_exist(action_result, role_name)
        if role_exist is None:
            return action_result.get_status()

        # Check if the role does not exist, the throw error
        if not role_exist:
            return action_result.set_status(phantom.APP_ERROR, AWSIAM_ROLE_DOES_NOT_EXIST_MSG.
                                            format(role_name=role_name, policy_status=AWSIAM_JSON_DETACHED))

        # 1. Detach Policy from role
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_DETACH_ROLE_POLICY_ENDPOINT
        params[AWSIAM_JSON_POLICY_ARN] = policy_arn
        params[AWSIAM_JSON_ROLE_NAME] = role_name

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response[AWSIAM_JSON_DETACH_ROLE_POLICY_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_DETACH_ROLE_POLICY_MSG.
                                        format(policy_arn=policy_arn, role_name=role_name))

    def _handle_attach_policy(self, param):
        """ This function is used to attach the policy to specified role.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        role_name = param[AWSIAM_PARAM_ROLE_NAME]
        policy_arn = param[AWSIAM_PARAM_POLICY_ARN]

        # Check if role already exists or not
        role_exist = self._if_role_exist(action_result, role_name)
        if role_exist is None:
            return action_result.get_status()

        # Check if the role does not exist, the throw error
        if not role_exist:
            return action_result.set_status(phantom.APP_ERROR, AWSIAM_ROLE_DOES_NOT_EXIST_MSG.
                                            format(role_name=role_name, policy_status=AWSIAM_JSON_ATTACHED))

        # 1. Attach policy to role
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_ATTACH_ROLE_POLICY_ENDPOINT
        params[AWSIAM_JSON_POLICY_ARN] = policy_arn
        params[AWSIAM_JSON_ROLE_NAME] = role_name

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response[AWSIAM_JSON_ATTACH_ROLE_POLICY_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_ATTACH_ROLE_POLICY_MSG.
                                        format(policy_arn=policy_arn, role_name=role_name))

    def _handle_remove_role(self, param):
        """ This function is used to remove the managed role from AWS account.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        role_name = param[AWSIAM_PARAM_ROLE_NAME]

        # Check if role already exists or not
        role_exist = self._if_role_exist(action_result, role_name)
        if role_exist is None:
            return action_result.get_status()

        # Check if the role already exist with the same name, no need to remove role
        if not role_exist:
            return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_NO_NEED_TO_REMOVE_ROLE_MSG.
                                            format(role_name=role_name))

        # 1. Delete all attached instance profiles with the role
        # a) List all attached instance profiles with the role
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_GET_ROLE_INSTANCE_PROFILES_ENDPOINT
        params[AWSIAM_JSON_ROLE_NAME] = role_name

        instance_profiles_dict = self._get_list_items(action_result, params, AWSIAM_JSON_INSTANCE_PROFILES)

        if instance_profiles_dict is None:
            return action_result.get_status()

        list_instance_profiles = instance_profiles_dict[AWSIAM_JSON_LIST_RESPONSE]

        for instance_profile in list_instance_profiles:
            # b) Remove role from instance profile
            params = OrderedDict()
            params[AWSIAM_JSON_ACTION] = AWSIAM_DETACH_ROLE_INSTANCE_PROFILE_ENDPOINT
            params[AWSIAM_JSON_INSTANCE_PROFILE_NAME] = instance_profile[AWSIAM_JSON_INSTANCE_PROFILE_NAME].\
                encode('utf-8')
            params[AWSIAM_JSON_ROLE_NAME] = role_name

            # make rest call
            ret_val, response = self._make_rest_call(action_result=action_result, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            # c) Delete the instance profiles also to maintain consistency with the role to role instance profile
            params = OrderedDict()
            params[AWSIAM_JSON_ACTION] = AWSIAM_DELETE_INSTANCE_PROFILE_ENDPOINT
            params[AWSIAM_JSON_INSTANCE_PROFILE_NAME] = instance_profile[AWSIAM_JSON_INSTANCE_PROFILE_NAME].\
                encode('utf-8')

            # make rest call
            ret_val, response = self._make_rest_call(action_result=action_result, params=params)

            if phantom.is_fail(ret_val):
                self.save_progress(AWSIAM_ACTION_FAILED_MESSAGE.format(action_name=self.get_action_identifier()))
                return action_result.get_status()

        # 2. Delete all attached policies with the role
        # a) List all attached policies with the role
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_GET_ROLE_POLICIES_ENDPOINT
        params[AWSIAM_JSON_ROLE_NAME] = role_name

        policies_dict = self._get_list_items(action_result, params, AWSIAM_JSON_ROLE_POLICIES)

        if policies_dict is None:
            return action_result.get_status()

        list_policies = policies_dict[AWSIAM_JSON_LIST_RESPONSE]

        for policy in list_policies:
            # b) Remove user from every policy
            params = OrderedDict()
            params[AWSIAM_JSON_ACTION] = AWSIAM_DETACH_ROLE_POLICY_ENDPOINT
            params[AWSIAM_JSON_POLICY_ARN] = policy[AWSIAM_JSON_POLICY_ARN].encode('utf-8')
            params[AWSIAM_JSON_ROLE_NAME] = role_name

            # make rest call
            ret_val, response = self._make_rest_call(action_result=action_result, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        # 3. Delete role
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_DELETE_ROLE_ENDPOINT
        params[AWSIAM_JSON_ROLE_NAME] = role_name

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response[AWSIAM_JSON_DELETE_ROLE_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_ROLE_DELETED_MSG.format(role_name=role_name))

    def _if_role_exist(self, action_result, role_name):
        """ This function is used to check if given role exist in AWS account.

        :param action_result: Object of ActionResult class
        :param role_name: AWS IAM role name to verify for its existence in AWS account
        :return: True if role exists and False otherwise
        """

        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_GET_ROLE_ENDPOINT
        params[AWSIAM_JSON_ROLE_NAME] = role_name

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            # a) If role already exist, then,
            # 404 error is thrown and it needs to be handled for delete user action
            if AWSIAM_ROLE_DOES_NOT_EXISTS_MSG.format(role_name=role_name).lower() in \
                    action_result.get_message().lower():
                return False

            return None

        # Return True for role already exists if we are successfully able to fetch the given role
        return True

    def _if_role_instance_profile_exist(self, action_result, role_name):
        """ This function is used to check if given instance profile exists in AWS account.

        :param action_result: Object of ActionResult
        :param role_name: AWS IAM role name to verify for its existence in AWS account
        :return: True if role instance profile exists and False otherwise
        """

        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_GET_ROLE_INSTANCE_PROFILE_ENDPOINT
        params[AWSIAM_JSON_INSTANCE_PROFILE_NAME] = role_name

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            # a) If role already exist, then,
            # 404 error is thrown and it needs to be handled for delete user action
            if AWSIAM_ROLE_INSTANCE_PROFILE_DOES_NOT_EXISTS_MSG.format(instance_profile_name=role_name).lower() in \
                    action_result.get_message().lower():
                return False

            return None

        # Return True for role already exists if we are successfully able to fetch the given role
        return True

    def _handle_add_role(self, param):
        """ This function is used to add the role to AWS account.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        role_name = param[AWSIAM_PARAM_ROLE_NAME]
        role_policy_doc = param[AWSIAM_PARAM_ROLE_POLICY_DOC]
        role_path = param.get(AWSIAM_PARAM_ROLE_PATH, '/').replace('\\', '/')

        # Remove unwanted spaces from json string of role policy document
        try:
            role_policy_doc_dict = json.loads(role_policy_doc)
            role_policy_doc = json.dumps(role_policy_doc_dict, separators=(",", ":"))
        except:
            self.debug_print(AWSIAM_POLICY_DOC_TRIMMING_ERROR_MSG)
            return action_result.set_status(phantom.APP_ERROR, AWSIAM_POLICY_DOC_TRIMMING_ERROR_MSG)

        # Check if role or role instance profile already exists or not
        role_exist = self._if_role_exist(action_result, role_name)
        if role_exist is None:
            return action_result.get_status()

        role_instance_profile_exist = self._if_role_instance_profile_exist(action_result, role_name)
        if role_instance_profile_exist is None:
            return action_result.get_status()

        # Check if the role or role instance profile already exist with the same name, then fail the action
        if role_exist and role_instance_profile_exist:
            return action_result.set_status(phantom.APP_ERROR, AWSIAM_ROLE_AND_PROFILE_ALREADY_EXISTS_MSG.
                                            format(role_name=role_name))
        elif role_exist:
            return action_result.set_status(phantom.APP_ERROR, AWSIAM_ROLE_ALREADY_EXISTS_MSG.
                                            format(role_name=role_name))
        elif role_instance_profile_exist:
            return action_result.set_status(phantom.APP_ERROR, AWSIAM_ROLE_INSTANCE_PROFILE_ALREADY_EXISTS_MSG.
                                            format(role_name=role_name))

        # Check if role_path is given in correct format
        if not role_path == '/' and (not role_path.startswith('/') or not role_path.endswith('/')):
            return action_result.set_status(phantom.APP_ERROR, AWSIAM_INVALID_ROLE_PATH_MSG)

        # 1. Add a container instance profile for role creation in AWS IAM account
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_ADD_ROLE_INSTANCE_PROFILE_ENDPOINT
        params[AWSIAM_JSON_INSTANCE_PROFILE_NAME] = role_name
        params[AWSIAM_JSON_PATH] = role_path

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # 2. Add role to AWS account
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_ADD_ROLE_ENDPOINT
        params[AWSIAM_JSON_ASSUME_POLICY_DOCUMENT] = role_policy_doc
        params[AWSIAM_JSON_ROLE_PATH] = role_path
        params[AWSIAM_JSON_ROLE_NAME] = role_name

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        response_dict = response[AWSIAM_JSON_CREATE_ROLE_RESPONSE][AWSIAM_JSON_CREATE_ROLE_RESULT][AWSIAM_JSON_ROLE]
        response_dict[AWSIAM_JSON_ASSUME_POLICY_DOCUMENT] = unquote(response_dict[AWSIAM_JSON_ASSUME_POLICY_DOCUMENT])

        # 3. Attach role with created container instance profile in step 1
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_ATTACH_ROLE_INSTANCE_PROFILE_ENDPOINT
        params[AWSIAM_JSON_INSTANCE_PROFILE_NAME] = role_name
        params[AWSIAM_JSON_ROLE_NAME] = role_name

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        response_dict.update(response[AWSIAM_JSON_ADD_ROLE_INSTANCE_PROFILE_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])
        action_result.add_data(response_dict)

        return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_ADD_ROLE_MSG.format(role_name=role_name))

    def _handle_delete_user(self, param):
        """ This function is used to delete the user and all associations with login profile, polices, roles, groups,
        and access keys for the same user.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param[AWSIAM_PARAM_USERNAME]

        # 1. Delete login profile of the user
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_DISABLE_USER_ENDPOINT
        params[AWSIAM_JSON_USERNAME] = username

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            # a) If Login Profile does not exist, then,
            # 404 error is thrown and it needs to be handled for delete user action
            if not AWSIAM_USER_LOGIN_PROFILE_ALREADY_DELETED_MSG.format(username=username).lower() in \
                   action_result.get_message().lower():
                return action_result.get_status()

        # 2. Delete all attached policies of user
        # a) List all user policies
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_GET_USER_POLICIES_ENDPOINT
        params[AWSIAM_JSON_USERNAME] = username

        policies_dict = self._get_list_items(action_result, params, AWSIAM_JSON_POLICIES)

        if policies_dict is None:
            return action_result.get_status()

        list_policies = policies_dict[AWSIAM_JSON_LIST_RESPONSE]

        for policy in list_policies:
            # b) Remove user from every policy
            params = OrderedDict()
            params[AWSIAM_JSON_ACTION] = AWSIAM_DETACH_USER_POLICY_ENDPOINT
            params[AWSIAM_JSON_POLICY_ARN] = policy[AWSIAM_JSON_POLICY_ARN].encode('utf-8')
            params[AWSIAM_JSON_USERNAME] = username

            # make rest call
            ret_val, response = self._make_rest_call(action_result=action_result, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        # 3. Remove user from all groups
        # a) List all user groups
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_GET_USER_GROUPS_ENDPOINT
        params[AWSIAM_JSON_USERNAME] = username

        groups_dict = self._get_list_items(action_result, params, AWSIAM_JSON_GROUPS)

        if groups_dict is None:
            return action_result.get_status()

        list_groups = groups_dict[AWSIAM_JSON_LIST_RESPONSE]

        for group in list_groups:
            # b) Remove user from every group
            params = OrderedDict()
            params[AWSIAM_JSON_ACTION] = AWSIAM_REMOVE_USER_FROM_GROUP_ENDPOINT
            params[AWSIAM_JSON_GROUP_NAME] = group[AWSIAM_JSON_GROUP_NAME].encode('utf-8')
            params[AWSIAM_JSON_USERNAME] = username

            # make rest call
            ret_val, response = self._make_rest_call(action_result=action_result, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        # 4. Remove user access keys
        # a) List all user access keys
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_LIST_ACCESS_KEYS_ENDPOINT
        params[AWSIAM_JSON_USERNAME] = username

        access_keys_dict = self._get_list_items(action_result, params, AWSIAM_JSON_ACCESS_KEYS)

        if access_keys_dict is None:
            return action_result.get_status()

        list_access_keys = access_keys_dict[AWSIAM_JSON_LIST_RESPONSE]

        for access_key in list_access_keys:
            # b) Remove user from every group
            params = OrderedDict()
            params[AWSIAM_JSON_ACCESS_KEY_ID] = access_key[AWSIAM_JSON_ACCESS_KEY_ID].encode('utf-8')
            params[AWSIAM_JSON_ACTION] = AWSIAM_DELETE_ACCESS_KEYS_ENDPOINT
            params[AWSIAM_JSON_USERNAME] = username

            # make rest call
            ret_val, response = self._make_rest_call(action_result=action_result, params=params)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

        # 5. Delete user
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_DELETE_USER_ENDPOINT
        params[AWSIAM_JSON_USERNAME] = username

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response[AWSIAM_JSON_DELETE_USER_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_USER_DELETED_MSG.format(username=username))

    def _handle_remove_user(self, param):
        """ This function is used to remove user from the specified group.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param[AWSIAM_PARAM_USERNAME]
        group_name = param[AWSIAM_PARAM_GROUP_NAME]

        # 1. Remove user from group
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_REMOVE_USER_FROM_GROUP_ENDPOINT
        params[AWSIAM_JSON_GROUP_NAME] = group_name
        params[AWSIAM_JSON_USERNAME] = username

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response[AWSIAM_JSON_REMOVE_USER_FROM_GROUP_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_USER_REMOVED_FROM_GROUP_MSG.
                                        format(username=username, group_name=group_name))

    def _handle_add_user(self, param):
        """ This function is used to add user to the specified group.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param[AWSIAM_PARAM_USERNAME]
        group_name = param[AWSIAM_PARAM_GROUP_NAME]

        # 1. Add user to group
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_ADD_USER_TO_GROUP_ENDPOINT
        params[AWSIAM_JSON_GROUP_NAME] = group_name
        params[AWSIAM_JSON_USERNAME] = username

        # make rest call
        ret_val, response = self._make_rest_call(action_result=action_result, params=params)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response[AWSIAM_JSON_ADD_USER_TO_GROUP_RESPONSE][AWSIAM_JSON_RESPONSE_METADATA])

        return action_result.set_status(phantom.APP_SUCCESS, AWSIAM_USER_ADDED_TO_GROUP_MSG.
                                        format(username=username, group_name=group_name))

    def _handle_get_user(self, param):
        """ This function is used to fetch entire details for user groups and attached policies to the user.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        username = param[AWSIAM_PARAM_USERNAME]
        user_details = dict()

        # 1. Fetch entire details for user groups and attached policies
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_GET_USER_GROUPS_ENDPOINT
        params[AWSIAM_JSON_USERNAME] = username

        groups_dict = self._get_list_items(action_result, params, AWSIAM_JSON_GROUPS)

        if groups_dict is None:
            return action_result.get_status()

        list_groups = groups_dict[AWSIAM_JSON_LIST_RESPONSE]

        for group in list_groups:
            group[AWSIAM_JSON_REQUEST_ID] = groups_dict[AWSIAM_JSON_REQUEST_ID]

        user_details[AWSIAM_JSON_GROUPS] = list_groups
        no_of_groups = len(list_groups)

        # 2. Fetch user policies
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_GET_USER_POLICIES_ENDPOINT
        params[AWSIAM_JSON_USERNAME] = username

        policies_dict = self._get_list_items(action_result, params, AWSIAM_JSON_POLICIES)

        if policies_dict is None:
            return action_result.get_status()

        list_policies = policies_dict[AWSIAM_JSON_LIST_RESPONSE]

        for policy in list_policies:
            policy[AWSIAM_JSON_REQUEST_ID] = policies_dict[AWSIAM_JSON_REQUEST_ID]

        user_details[AWSIAM_JSON_POLICIES] = list_policies
        no_of_policies = len(list_policies)

        # Add response data to action_result
        action_result.add_data(user_details)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total_groups'] = no_of_groups
        summary['total_policies'] = no_of_policies

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_groups(self, param):
        """ This function is used to fetch groups of an AWS account

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        group_path = param.get(AWSIAM_PARAM_GROUP_PATH, '/')

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if group_path and not group_path == '/' and (not group_path.startswith('/') or not group_path.endswith('/')):
            return action_result.set_status(phantom.APP_ERROR, AWSIAM_INVALID_GROUP_PATH_MSG)

        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_LIST_GROUPS_ENDPOINT
        params[AWSIAM_JSON_USER_PATH_PREFIX] = group_path

        # Fetch list of groups of AWS account
        groups_dict = self._get_list_items(action_result, params, AWSIAM_JSON_PATHS_GROUPS)

        if groups_dict is None:
            return action_result.get_status()

        for group in groups_dict[AWSIAM_JSON_LIST_RESPONSE]:
            group[AWSIAM_JSON_REQUEST_ID] = groups_dict[AWSIAM_JSON_REQUEST_ID]
            action_result.add_data(group)

        summary = action_result.update_summary({})
        summary['total_groups'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_users(self, param):
        """ This function is used to fetch users of an AWS account based on user_path and group_name.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        params = OrderedDict()
        user_path = param.get(AWSIAM_PARAM_USER_PATH)
        if user_path:
            user_path = user_path.replace('\\', '/')
        group_name = param.get(AWSIAM_PARAM_GROUP_NAME)
        endpoint_flag = AWSIAM_JSON_USERS

        if user_path and not group_name:
            params[AWSIAM_JSON_ACTION] = AWSIAM_LIST_USERS_ENDPOINT
            params[AWSIAM_JSON_USER_PATH_PREFIX] = user_path
        elif group_name:
            params[AWSIAM_JSON_ACTION] = AWSIAM_LIST_USERS_OF_GROUP_ENDPOINT
            params[AWSIAM_JSON_GROUP_NAME] = group_name
            endpoint_flag = AWSIAM_JSON_GROUP_USERS
        elif not user_path and not group_name:
            params[AWSIAM_JSON_ACTION] = AWSIAM_LIST_USERS_ENDPOINT
            params[AWSIAM_JSON_USER_PATH_PREFIX] = '/'

        if user_path and not user_path == '/' and (not user_path.startswith('/') or not user_path.endswith('/')):
            return action_result.set_status(phantom.APP_ERROR, AWSIAM_INVALID_USER_PATH_MSG)

        # 1. Fetch users of an AWS account
        users_dict = self._get_list_items(action_result, params, endpoint_flag)

        if users_dict is None:
            return action_result.get_status()

        # Add the roles data in action_result
        if group_name and user_path:
            for user in users_dict[AWSIAM_JSON_LIST_RESPONSE]:
                if user_path.lower() == user[AWSIAM_JSON_PATH].encode('utf-8').lower():
                    user[AWSIAM_JSON_REQUEST_ID] = users_dict[AWSIAM_JSON_REQUEST_ID]
                    action_result.add_data(user)
        else:
            for user in users_dict[AWSIAM_JSON_LIST_RESPONSE]:
                user[AWSIAM_JSON_REQUEST_ID] = users_dict[AWSIAM_JSON_REQUEST_ID]
                action_result.add_data(user)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total_users'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_roles(self, param):
        """ This function is used to fetch roles of an AWS account.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # 1. Fetch roles of an AWS account
        params = OrderedDict()
        params[AWSIAM_JSON_ACTION] = AWSIAM_LIST_ROLES_ENDPOINT

        roles_dict = self._get_list_items(action_result, params, AWSIAM_JSON_ROLES)

        if roles_dict is None:
            return action_result.get_status()

        # Add the roles data in action_result
        for role in roles_dict[AWSIAM_JSON_LIST_RESPONSE]:
            role[AWSIAM_JSON_REQUEST_ID] = roles_dict[AWSIAM_JSON_REQUEST_ID]
            role[AWSIAM_JSON_ASSUME_POLICY_DOCUMENT] = unquote(role[AWSIAM_JSON_ASSUME_POLICY_DOCUMENT])
            action_result.add_data(role)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total_roles'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_list_items(self, action_result=None, params=None, key=None):
        """ This function is used to fetch paginated response list of items based on provided parameters.

        :param action_result: Object of ActionResult
        :param params: Dictionary of input parameters
        :return: Dictionary of List of items retrieved from paginated response and request ID of request made
        """

        list_items = []

        # 1. Pagination method for getting list of response items
        while True:
            # Remove 'Version' key because for next pagination call, it gets added again in _make_rest_call
            params.pop(AWSIAM_JSON_VERSION, None)

            # make rest call
            ret_val, response = self._make_rest_call(action_result=action_result, params=params)

            if phantom.is_fail(ret_val):
                return None

            json_resp_part_0 = (self._response_metadata_dict[key])[0]
            json_resp_part_1 = (self._response_metadata_dict[key])[1]
            json_resp_part_2 = (self._response_metadata_dict[key])[2]

            pagination_key = response[json_resp_part_0][json_resp_part_1][AWSIAM_JSON_IS_TRUNCATED].encode('utf-8')
            if pagination_key == 'true':
                is_pagination_required = True
            else:
                is_pagination_required = False

            if response[json_resp_part_0][json_resp_part_1][json_resp_part_2]:
                items = response[json_resp_part_0][json_resp_part_1][json_resp_part_2][AWSIAM_JSON_MEMBER]
            else:
                items = []
            request_id = response[json_resp_part_0][AWSIAM_JSON_RESPONSE_METADATA][AWSIAM_JSON_REQUEST_ID]

            if items:
                if isinstance(items, dict):
                    list_items.append(items)
                    break
                elif isinstance(items, list):
                    list_items.extend(items)

            if is_pagination_required:
                params[AWSIAM_JSON_MARKER] = response[json_resp_part_0][json_resp_part_1][AWSIAM_JSON_MARKER]\
                    .encode('utf-8')
            else:
                break

        # Return a dictionary consisting of list of items retrieved and request ID of last request made
        response_dict = dict()
        response_dict[AWSIAM_JSON_LIST_RESPONSE] = list_items
        response_dict[AWSIAM_JSON_REQUEST_ID] = request_id

        return response_dict

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status(success/failure)
        """

        self.debug_print("action_id", self.get_action_identifier())

        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'get_user': self._handle_get_user,
            'list_roles': self._handle_list_roles,
            'list_users': self._handle_list_users,
            'list_groups': self._handle_list_groups,
            'add_user': self._handle_add_user,
            'remove_user': self._handle_remove_user,
            'delete_user': self._handle_delete_user,
            'disable_user': self._handle_disable_user,
            'enable_user': self._handle_enable_user,
            'add_role': self._handle_add_role,
            'remove_role': self._handle_remove_role,
            'attach_policy': self._handle_attach_policy,
            'detach_policy': self._handle_detach_policy,
            'assign_policy': self._handle_assign_policy,
            'remove_policy': self._handle_remove_policy
        }

        action = self.get_action_identifier()

        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    @staticmethod
    def _get_response_metadata_dict():
        response_dict = dict()

        response_dict[AWSIAM_JSON_GROUPS] = [AWSIAM_JSON_LIST_GROUPS_FOR_USER_RESPONSE,
                                             AWSIAM_JSON_LIST_GROUPS_FOR_USER_RESULT, AWSIAM_JSON_GROUPS]
        response_dict[AWSIAM_JSON_POLICIES] = [AWSIAM_JSON_LIST_POLICIES_FOR_USER_RESPONSE,
                                               AWSIAM_JSON_LIST_POLICIES_FOR_USER_RESULT, AWSIAM_JSON_POLICIES]
        response_dict[AWSIAM_JSON_ROLES] = [AWSIAM_JSON_LIST_ROLES_RESPONSE,
                                            AWSIAM_JSON_LIST_ROLES_RESULT, AWSIAM_JSON_ROLES]
        response_dict[AWSIAM_JSON_USERS] = [AWSIAM_JSON_LIST_USERS_RESPONSE,
                                            AWSIAM_JSON_LIST_USERS_RESULT, AWSIAM_JSON_USERS]
        response_dict[AWSIAM_JSON_GROUP_USERS] = [AWSIAM_JSON_GET_GROUP_RESPONSE,
                                                  AWSIAM_JSON_GET_GROUP_RESULT, AWSIAM_JSON_USERS]
        response_dict[AWSIAM_JSON_ACCESS_KEYS] = [AWSIAM_JSON_LIST_ACCESS_KEYS_RESPONSE,
                                                  AWSIAM_JSON_LIST_ACCESS_KEYS_RESULT, AWSIAM_JSON_ACCESS_KEYS]
        response_dict[AWSIAM_JSON_INSTANCE_PROFILES] = [AWSIAM_JSON_LIST_INSTANCE_PROFILES_RESPONSE,
                                                        AWSIAM_JSON_LIST_INSTANCE_PROFILES_RESULT,
                                                        AWSIAM_JSON_INSTANCE_PROFILES]
        response_dict[AWSIAM_JSON_ROLE_POLICIES] = [AWSIAM_JSON_LIST_ROLE_POLICIES_RESPONSE,
                                                    AWSIAM_JSON_LIST_ROLE_POLICIES_RESULT, AWSIAM_JSON_POLICIES]
        response_dict[AWSIAM_JSON_PATHS_GROUPS] = [AWSIAM_JSON_LIST_GROUPS_RESPONSE,
                                                   AWSIAM_JSON_LIST_GROUPS_RESULT, AWSIAM_JSON_GROUPS]

        return response_dict

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS.
        """

        self._state = self.load_state()
        config = self.get_config()

        self._access_key = config[AWSIAM_ACCESS_KEY]
        self._secret_key = config[AWSIAM_SECRET_KEY]
        self._response_metadata_dict = self._get_response_metadata_dict()

        return phantom.APP_SUCCESS

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """

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

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: {0}".format(str(e)))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AwsIamConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
