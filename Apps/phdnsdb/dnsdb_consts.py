# File: dnsdb_consts.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

DNSDB_JSON_RTYPE_IP = 'A'
DNSDB_JSON_API_KEY = 'api_key'
DNSDB_JSON_DOMAIN = 'domain'
DNSDB_JSON_ZONE = 'zone'
DNSDB_JSON_TYPE = 'type'
DNSDB_JSON_NETWORK_PREFIX = 'network_prefix'
DNSDB_JSON_LIMIT = 'limit'
DNSDB_JSON_RECORD_SEEN_BEFORE = 'record_seen_before'
DNSDB_JSON_RECORD_SEEN_AFTER = 'record_seen_after'
DNSDB_JSON_IP = 'ip'
DNSDB_JSON_RESPONSE = 'json_response'
DNSDB_BASE_URL = 'https://api.dnsdb.info/lookup'
DNSDB_ENDPOINT_DOMAIN = '/rrset/name/{domain}'
DNSDB_ENDPOINT_DOMAIN_TYPE = '/rrset/name/{domain}/{type}'
DNSDB_ENDPOINT_DOMAIN_TYPE_ZONE = '/rrset/name/{domain}/{type}/{zone}'
DNSDB_ENDPOINT_IP = '/rdata/ip/{ip}'
DNSDB_ENDPOINT_IP_PREFIX = '/rdata/ip/{ip},{prefix}'
DNSDB_ERR_API_UNSUPPORTED_METHOD = 'Unsupported method : {method}'
DNSDB_ERR_INVALID_TIME_FORMAT = 'Invalid time format : {time}'
DNSDB_ERR_INVALID_LIMIT = 'Invalid response length limit : {limit}'
DNSDB_ERR_INVALID_NETWORK_PREFIX = 'Invalid network prefix : {prefix}'
DNSDB_TEST_CONN_INITIATION = 'Testing connectivity'
DNSDB_TEST_CONN_DOMAIN = 'www.phantomcyber.com'
DNSDB_TEST_CONN_FAIL = 'Connectivity test failed'
DNSDB_TEST_CONN_SUCC = 'Connectivity test succeeded'
DNSDB_TEST_CONNECTIVITY_MSG = 'Querying a domain to check API key with DNSDB'
DNSDB_REST_RESP_SUCCESS = 200
DNSDB_REST_RESP_SUCCESS_MSG = 'Request Successful'
DNSDB_REST_RESP_RESOURCE_INCORRECT = 400
DNSDB_REST_RESP_RESOURCE_INCORRECT_MSG = 'Invalid input. The resource is in '\
                                         'an incorrect format'
DNSDB_REST_RESP_ACCESS_DENIED = 403
DNSDB_REST_RESP_ACCESS_DENIED_MSG = 'The API key is invalid'
DNSDB_REST_RESP_RESOURCE_NOT_FOUND = 404
DNSDB_REST_RESP_RESOURCE_NOT_FOUND_MSG = 'Resource not found'
DNSDB_REST_RESP_LIC_EXCEED = 429
DNSDB_REST_RESP_LIC_EXCEED_MSG = 'The license count usage for the given '\
                                 'period has been exceeded.'
DNSDB_REST_RESP_OVERLOADED = 503
DNSDB_REST_RESP_OVERLOADED_MSG = 'Server is overloaded. Retry your call '\
                                 'after the time period displayed.'
DNSDB_ERR_JSON_PARSE = 'Unable to parse the fields parameter into a '\
                       'dictionary. , Response text - {raw_text}'
DNSDB_ERR_FROM_SERVER = 'API failed, Status code: {status}, Detail: {detail}'
DNSDB_ERR_SERVER_CONNECTION = 'Connection failed'
DNSDB_REST_RESP_OTHER_ERROR_MSG = 'Error occurred'
DNSDB_DATA_NOT_AVAILABLE_MSG = 'Data not available'
