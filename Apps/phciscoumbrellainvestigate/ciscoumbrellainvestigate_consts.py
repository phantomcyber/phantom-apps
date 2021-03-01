# File: ciscoumbrellainvestigate_consts.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#


INVESTIGATE_JSON_DOMAIN = "domain"
INVESTIGATE_JSON_IP = "ip"
INVESTIGATE_JSON_APITOKEN = "access_token"
INVESTIGATE_JSON_STATUS_DESC = "status_desc"
INVESTIGATE_JSON_DOMAIN_STATUS = "domain_status"
INVESTIGATE_JSON_IP_STATUS = "ip_status"
INVESTIGATE_JSON_TOTAL_BLOCKED_DOMAINS = "total_blocked_domains"
INVESTIGATE_REG_ORG = "organization"
INVESTIGATE_REG_CITY = "city"
INVESTIGATE_REG_COUNTRY = "country"
INVESTIGATE_JSON_CATEGORIES = "category"
INVESTIGATE_JSON_CATEGORY_INFO = "category_info"
INVESTIGATE_JSON_CO_OCCUR = "co_occurances"
INVESTIGATE_JSON_RELATIVE_LINKS = "relative_links"
INVESTIGATE_JSON_TOTAL_OCO_OCCUR = "total_co_occurances"
INVESTIGATE_JSON_TOTAL_RELATIVE_LINKS = "total_relative_links"
INVESTIGATE_JSON_SECURITY_INFO = "security_info"
INVESTIGATE_JSON_TAG_INFO = "tag_info"
INVESTIGATE_JSON_TOTAL_TAG_INFO = "total_tag_info"
INVESTIGATE_JSON_FEATURES = "features"
INVESTIGATE_JSON_RISK_SCORE = "riskScore"

INVESTIGATE_ERR_CONNECTIVITY_TEST = "Test Connectivity Failed"
INVESTIGATE_SUCC_CONNECTIVITY_TEST = "Test Connectivity Passed"
INVESTIGATE_ERR_SERVER_CONNECTION = "Connection failed"
INVESTIGATE_ERR_FROM_SERVER = "API failed, Status code: {status}, Message from server: {message}"
INVESTIGATE_MSG_GET_DOMAIN_TEST = "Querying a single domain to check credentials"

INVESTIGATE_USING_BASE_URL = "Using url: {base_url}"

INVESTIGATE_REST_API_URL = "https://investigate.api.umbrella.com"
STATUS_DESC = {
        '0': 'NO STATUS',
        '1': 'NON MALICIOUS',
        '-1': 'MALICIOUS'}
