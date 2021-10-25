# File: ciscoumbrellainvestigate_consts.py
#
# Copyright (c) 2021 Splunk Inc.
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
INVESTIGATE_JSON_INDICATORS = "indicators"
INVESTIGATE_JSON_RISK_SCORE = "risk_score"

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
