# File: passivetotal_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Configurations and action parameters
PASSIVETOTAL_JSON_DOMAIN = "domain"
PASSIVETOTAL_JSON_IP = "ip"
PASSIVETOTAL_JSON_KEY = "key"
PASSIVETOTAL_JSON_SECRET = "secret"
PASSIVETOTAL_JSON_CLASSIFICATION = "classification"
PASSIVETOTAL_JSON_EVER_COMPROMISED = "ever_compromised"
PASSIVETOTAL_JSON_DYNAMIC = "dynamic"
PASSIVETOTAL_JSON_WATCHING = "watching"
PASSIVETOTAL_JSON_DYNAMIC_DOMAIN = "dynamic_domain"
PASSIVETOTAL_JSON_BEING_WATCHED = "being_watched"
PASSIVETOTAL_JSON_METADATA = "metadata"
PASSIVETOTAL_JSON_PASSIVE = "passive"
PASSIVETOTAL_JSON_SINKHOLE = "sinkhole"
PASSIVETOTAL_JSON_SUBDOMAINS = "subdomains"
PASSIVETOTAL_JSON_TAGS = "tags"
PASSIVETOTAL_JSON_UNIQUE = "unique"
PASSIVETOTAL_JSON_SSL_CERTIFICATES = "ssl_certificates"
PASSIVETOTAL_JSON_AS_NAME = "as_name"
PASSIVETOTAL_JSON_COUTRY = "country"
PASSIVETOTAL_JSON_FIRST_SEEN = "first_seen"
PASSIVETOTAL_JSON_LAST_SEEN = "last_seen"
PASSIVETOTAL_JSON_TOTAL_UNIQUE_DOMAINS = "total_unique_domains"
PASSIVETOTAL_JSON_FROM = "from"
PASSIVETOTAL_JSON_TO = "to"

# Error and success messages
PASSIVETOTAL_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
PASSIVETOTAL_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
PASSIVETOTAL_ERR_SERVER_CONNECTION = "Connection failed"
PASSIVETOTAL_ERR_FROM_SERVER = "API failed, Status code: {status}, Message: {message}"
PASSIVETOTAL_MSG_GET_DOMAIN_TEST = "Querying a single domain to check credentials"

PASSIVETOTAL_USING_BASE_URL = "Using url: {base_url}"

# Rest API URL
PASSIVETOTAL_REST_API_URL = "https://api.passivetotal.org/v2"

# Consts for _get_error_message_from_exception
PASSIVETOTAL_ERR_CODE_UNAVAILABLE = "Error code unavailable"
PASSIVETOTAL_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or the action parameters."
PASSIVETOTAL_UNICODE_DAMMIT_TYPE_ERR_MSG = "Error occurred while connecting to the PassiveTotal server. Please check the asset configuration and|or the action parameters."

# API quota exceed messages
QUOTA_EXCEEDED_MSG = "quota has been exceeded"
QUOTA_EXCEEDED_MSG_API = "quota exceeded for operation search_api"
