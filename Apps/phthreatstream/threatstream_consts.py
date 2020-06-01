# File: threatstream_consts.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

DEFAULT_MAX_RESULTS = 1000
THREATSTREAM_JSON_USERNAME = "username"
THREATSTREAM_JSON_API_KEY = "api_key"
THREATSTREAM_JSON_HASH = "hash"
THREATSTREAM_JSON_DOMAIN = "domain"
THREATSTREAM_JSON_IP = "ip"
THREATSTREAM_JSON_URL = "url"
THREATSTREAM_JSON_EMAIL = "email"
THREATSTREAM_JSON_TAGS = "tags"
THREATSTREAM_JSON_SOURCE_USER_ID = "source_user_id"

ENDPOINT_INTELLIGENCE = "/v2/intelligence"
ENDPOINT_PDNS = "/v1/pdns/{ioc_type}/{ioc_value}/"
ENDPOINT_INISGHT = "/v1/inteldetails/insights/"
ENDPOINT_REFERENCE = "/v1/inteldetails/references/{ioc_value}/"
ENDPOINT_CONFIDENCE = "/v1/inteldetails/confidence_trend/"
ENDPOINT_WHOIS = "/v1/inteldetails/whois/{ioc_value}/"
ENDPOINT_INCIDENT = "/v1/incident/"
ENDPOINT_VULNERABILITY = "/v1/vulnerability/"
ENDPOINT_SINGLE_VULNERABILITY = "/v1/vulnerability/{vul_id}/"
ENDPOINT_INCIDENT_WITH_VALUE = "/v1/incident/associated_with_intelligence/"
ENDPOINT_SINGLE_INCIDENT = "/v1/incident/{inc_id}/"
ENDPOINT_IMPORT_IOC = "/v1/intelligence/"
ENDPOINT_TAG_IOC = "/v1/intelligence/{indicator_id}/tag/"
ENDPOINT_FILE_DETONATION = "/v1/submit/new/"
ENDPOINT_URL_DETONATION = "/v1/submit/new/"
ENDPOINT_GET_REPORT = '/v1/submit/{report_id}/report/'
ENDPOINT_ASSOCIATE_INTELLIGENCE = '/v1/incident/{incident}/intelligence/bulk_add/'

THREATSTREAM_ERR_INVALID_TYPE = "Invalid IOC Type"
THREATSTREAM_ERR_INVALID_VALUE = "Invalid IOC Value. Don't include the http:// or any paths"
THREATSTREAM_ERR_FETCH_REPLY = "Unable to fetch the whois response. Error from the server: {error}"
THREATSTREAM_ERR_PARSE_REPLY = "Unable to parse whois response. Error from the server: {error}"
THREATSTREAM_SUCCESS_WHOIS_MESSAGE = "Successfully retrieved whois info"
THREATSTREAM_ERR_INVALID_PARAM = "Please provide non-zero positive integer in {param}"

WHOIS_NO_DATA = "No Whois Data Available"
THREARSTREAM_INVALID_TIMEOUT = "Please provide non-zero positive integer in timeout_minutes"
THREARSTREAM_INVALID_CONFIDENCE = "Please provide positive integer in range of 0-100 in confidence parameter"
