# File: fortigate_consts.py
#
# Copyright (c) 2016-2020 Splunk Inc.
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
FORTIGATE_BASE_URL = "/api/v2"
FORTIGATE_LOGIN = "/logincheck"
FORTIGATE_LOGOUT = "/logout"
FORTIGATE_ADD_ADDRESS = "/cmdb/firewall/address"
FORTIGATE_GET_ADDRESSES = "/cmdb/firewall/address/{ip}"
FORTIGATE_GET_POLICY = "/cmdb/firewall/policy"
FORTIGATE_BLOCK_IP = "/cmdb/firewall/policy/{policy_id}/dstaddr"
FORTIGATE_GET_BLOCKED_IP = "/cmdb/firewall/policy/{policy_id}/dstaddr/{ip}"
FORTIGATE_BLOCKED_IPS = "/monitor/user/banned/select/"
FORTIGATE_LIST_POLICIES = "/cmdb/firewall/policy/"
FORTIGATE_JSON_USERNAME = "username"
FORTIGATE_JSON_PASSWORD = "password"
FORTIGATE_JSON_URL = "url"
FORTIGATE_JSON_VDOM = "vdom"
FORTIGATE_JSON_VERIFY_SERVER_CERT = "verify_server_cert"
FORTIGATE_JSON_IP = "ip"
FORTIGATE_JSON_POLICY = "policy"
FORTIGATE_JSON_NAME = 'name'
FORTIGATE_JSON_TYPE = 'type'
FORTIGATE_JSON_IP_MASK = 'ipmask'
FORTIGATE_JSON_SUBNET = 'subnet'
FORTIGATE_PER_PAGE_DEFAULT_LIMIT = 100
FORTIGATE_TEST_CONNECTIVITY_MSG = "Logging to device"
FORTIGATE_TEST_CONN_FAIL = "Connectivity test failed"
FORTIGATE_TEST_CONN_SUCC = "Connectivity test succeeded"
FORTIGATE_TEST_ENDPOINT_MSG = 'Querying an endpoint to validate credentials'
FORTIGATE_REST_RESP_BAD_REQUEST = 400
FORTIGATE_REST_RESP_BAD_REQUEST_MSG = "Request cannot be processed by the API"
FORTIGATE_REST_RESP_NOT_AUTH = 401
FORTIGATE_REST_RESP_NOT_AUTH_MSG = "Request without successful login session"
FORTIGATE_REST_RESP_FORBIDDEN = 403
FORTIGATE_REST_RESP_FORBIDDEN_MSG = 'Request is missing CSRF token or administrator is missing access ' \
                                    'profile permissions'
FORTIGATE_REST_RESP_RESOURCE_NOT_FOUND = 404
FORTIGATE_REST_RESP_RESOURCE_NOT_FOUND_MSG = "Resource not available"
FORTIGATE_REST_RESP_NOT_ALLOWED = 405
FORTIGATE_REST_RESP_NOT_ALLOWED_MSG = 'Specified HTTP method is not allowed for this resource'
FORTIGATE_REST_RESP_ENTITY_LARGE = 413
FORTIGATE_REST_RESP_ENTITY_LARGE_MSG = 'Request cannot be processed due to large entity'
FORTIGATE_REST_RESP_FAIL_DEPENDENCY = 424
FORTIGATE_REST_RESP_FAIL_DEPENDENCY_MSG = 'Fail dependency can be duplicate resource, missing required ' \
                                          'parameter, missing required attribute, invalid attribute value'
FORTIGATE_REST_RESP_INTERNAL_ERROR = 500
FORTIGATE_REST_RESP_INTERNAL_ERROR_MSG = 'Internal error when processing the request'
FORTIGATE_REST_RESP_SUCCESS = 200
FORTIGATE_ERR_API_UNSUPPORTED_METHOD = "Unsupported method"
FORTIGATE_ERR_SERVER_CONNECTION = "Connection failed"
FORTIGATE_ERR_FROM_SERVER = 'API failed. Status code: {status}. Detail: {detail}'
FORTIGATE_ERR_JSON_PARSE = 'Unable to parse the fields parameter into a dictionary. Response text - {raw_text}. Error Code: {error_code}. Error Message: {error_msg}'
FORTIGATE_REST_RESP_OTHER_ERROR_MSG = "Unknown error"
FORTIGATE_IP_BLOCKED = 'IP blocked successfully'
FORTIGATE_IP_UNBLOCKED = 'IP unblocked successfully'
FORTIGATE_TEST_WARN_MSG = 'The failure could be due to IP provided in URL instead of hostname'
FORTIGATE_INVALID_POLICIES = 'Policy probably does not exist under virtual domain {vdom}.'
FORTIGATE_LIMIT_VALIDATION_MSG = "Please provide non-zero positive integer value in the limit parameter"
FORTIGATE_INVALID_POLICY_DENY = 'Invalid policy. Action of policy is not deny'
FORTIGATE_ADDRESS_NOT_AVAILABLE = 'Address does not exist'
FORTIGATE_IP_ALREADY_UNBLOCKED = 'IP is already unblocked'
FORTIGATE_IP_ALREADY_BLOCKED = 'IP is already blocked'
FORTIGATE_X_CSRFTOKEN_ERROR = "Error occurred while fetching X-CSRFTOKEN from session object. Please check the provided credentials in the asset configuration parameters"
