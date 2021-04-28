# File: deepsight_consts.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

DEEPSIGHT_BASE_URL = "https://deepsightapi.accenture.com/v1/"
DEEPSIGHT_ERR_API_UNSUPPORTED_METHOD = 'Unsupported method {method}'
DEEPSIGHT_ERR_SERVER_CONNECTION = 'Connection failed'
DEEPSIGHT_TEST_CONNECTIVITY_PASS = 'Connectivity test succeeded'
DEEPSIGHT_TEST_CONNECTIVITY_FAIL = 'Connectivity test failed'
DEEPSIGHT_ERR_JSON_PARSE = 'Unable to parse the fields parameter into a ' \
                           'dictionary. Response text: {raw_text}'
DEEPSIGHT_ERR_FROM_SERVER = 'API failed, Status code: {status}, ' \
                            'Detail: {detail}'
DEEPSIGHT_REPORT_FILE_TYPE = 'pdf'
DEEPSIGHT_SUCC_FILE_ADD_TO_VAULT = 'Successfully added file to Vault'
DEEPSIGHT_MSG_DOWNLOADING_REPORT = 'Downloading report'
DEEPSIGHT_ENDPOINT_USAGE_LIMIT = '/application/usage_limit_status'
DEEPSIGHT_ENDPOINT_DOMAINS = '/domains/{domain}'
DEEPSIGHT_ENDPOINT_FILEHASH = '/files/{hash}'
DEEPSIGHT_ENDPOINT_URL = '/urls/{url}'
DEEPSIGHT_ENDPOINT_IP = '/ips/{ip}'
DEEPSIGHT_ENDPOINT_MATI_FILE = '/mati/files?q={hash}'
DEEPSIGHT_ENDPOINT_MATI_EMAIL = '/mati/emails?q={email}'
DEEPSIGHT_ENDPOINT_MATI_REPORT = '/mati/reports/{mati_id}'
DEEPSIGHT_ENDPOINT_MATI_REPORT_SUMMARY = '/mati/reports/{mati_id}/summary'
DEEPSIGHT_ENDPOINT_MATI_REPORT_PDF = '/mati/reports/{mati_id}/report'
DEEPSIGHT_ENDPOINT_MATI_REPORT_LIST = '/mati/reports'
DEEPSIGHT_JSON_API_KEY = 'api_key'
DEEPSIGHT_JSON_DOMAIN = 'domain'
DEEPSIGHT_JSON_FILE = 'file'
DEEPSIGHT_JSON_URL = 'url'
DEEPSIGHT_JSON_IP = 'ip'
DEEPSIGHT_JSON_EMAIL = 'email'
DEEPSIGHT_JSON_MATI_ID = 'mati_id'
DEEPSIGHT_JSON_DOWNLOAD_REPORT = 'download_report'
DEEPSIGHT_JSON_RESPONSE = "json_response"
DEEPSIGHT_JSON_RESOURCE_NOT_FOUND = 'resource_not_found'
DEEPSIGHT_JSON_REPORT_DATA = "report_data"
DEEPSIGHT_JSON_REPORT_FILE_NAME = "report_file_name"
DEEPSIGHT_JSON_REPORT_SUMMARY_DATA = "report_summary_data"
DEEPSIGHT_JSON_CONTAINER_ID = "container_id"
DEEPSIGHT_JSON_FIRST_INGEST_COUNT = "max_reports_first_ingestion"
DEEPSIGHT_JSON_LAST_REPORT_ID = "last_report_id"
DEEPSIGHT_REST_RESP_SUCCESS = 200
DEEPSIGHT_REST_RESP_SUCCESS_MSG = 'Request successful'
DEEPSIGHT_REST_RESP_RESOURCE_INCORRECT = 400
DEEPSIGHT_REST_RESP_RESOURCE_INCORRECT_MSG = 'Invalid input. The resource is' \
                                             ' in an incorrect format'
DEEPSIGHT_REST_RESP_ACCESS_DENIED = 403
DEEPSIGHT_REST_RESP_ACCESS_DENIED_MSG = 'Access denied. The API key was ' \
                                        'successfully authenticated, but the' \
                                        ' license does not permit access to ' \
                                        'the requested resource'
DEEPSIGHT_REST_RESP_RESOURCE_NOT_FOUND = 404
DEEPSIGHT_REST_RESP_RESOURCE_NOT_FOUND_MSG = 'Data not available'
DEEPSIGHT_REST_RESP_LIC_EXCEED = 429
DEEPSIGHT_REST_RESP_LIC_EXCEED_MSG = 'The license count usage for the ' \
                                     'given period has been exceeded.'
DEEPSIGHT_REST_RESP_OVERLOADED = 503
DEEPSIGHT_REST_RESP_OVERLOADED_MSG = 'Server is overloaded. ' \
                                     'Retry after sometime'
DEEPSIGHT_REST_RESP_OTHER_ERROR_MSG = "Error returned"
DEEPSIGHT_REST_RESP_INCORRECT_FORMAT = "JSON Response has incorrect format." \
                                       "Response : {json}," \
                                       "Expected Format :{format}"
DEEPSIGHT_TEST_ENDPOINT = "Querying an endpoint to check API key for DeepSight"
DEEPSIGHT_CONTAINER_ERROR = "Error while creating container for report id {report}"
DEEPSIGHT_ARTIFACTS_DESC = "Artifact created by DeepSight app"
DEEPSIGHT_ARTIFACTS_ERROR = "Error while creating artifact"
DEEPSIGHT_DEFAULT_POLL_NOW_CONTAINER_COUNT = 2
DEEPSIGHT_DEFAULT_POLL_NOW_ARTIFACT_COUNT = 2
DEEPSIGHT_DEFAULT_FIRST_INGEST_COUNT = 5
DEEPSIGHT_DOWNLOAD_PDF_CONFIG = "download_report"
DEEPSIGHT_INGEST_CONTAINER_ID = "Source id {container} has been provided. "\
                                "Matching reports would be ingested"
DEEPSIGHT_INGEST_LATEST_REPORT_ID = "Ingesting data for reports latest than report id {report}"
DEEPSIGHT_REPORT_ERROR = "Error while getting report detail for {report}. Error Message: {message}"
DEEPSIGHT_REPORT_PDF_ERROR = "Error while downloading report pdf for {report}. Error Message: {message}"
DEEPSIGHT_REPORT_PDF_UNAVAILABLE = "The report pdf is unavailable"
DEEPSIGHT_REPORT_PDF_ALREADY_AVAILABLE = "The report pdf is already available in vault"
