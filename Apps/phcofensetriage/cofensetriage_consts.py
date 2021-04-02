# File: cofensetriage_consts.py
# Copyright (c) 2020-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
CONNECTION_TEST_ENDPOINT = '/api/public/v1/status'
REPORTER_LOOKUP_ENDPOINT = '/api/public/v1/reporters'
INTEGRATION_SEARCH_ENDPOINT = '/api/public/v1/integration_search'
THREAT_INDICATORS_ENDPOINT = '/api/public/v1/triage_threat_indicators'
PROCESSED_REPORTS_ENDPOINT = '/api/public/v1/processed_reports?fields[]=subject&fields[]=category_id'
#
PHANTOM_VAULT_DIR = '/opt/phantom/vault/tmp/'
#
MAX_PER_PAGE = 50
DEFAULT_MAX_DOWNLOADED_RESULTS = 150

# By default, client applications can make 25 requests to Cofense Triage within
# a five-minute interval using the Cofense Triage API.
#
# This constant is used as a default value when the Cofense Triage API does not
# explicitly respond with the X-RateLimit-Remaining header.
DEFAULT_COFENSE_TRIAGE_RATE_LIMIT = 25
PAGE_KEY = '"page" action parameter'
PER_PAGE_KEY = '"per_page" action parameter'
MAX_RESULTS_KEY = '"max_results" action parameter'
MATCH_PRIORITY_KEY = '"match_priority" action parameter'
REPORTER_ID_KEY = '"reporter_id" action parameter'
REPORT_ID_KEY = '"report_id" action parameter'
ATTACHMENT_ID_KEY = '"attachment_id" action parameter'
ERROR_CODE_MSG = 'Error code unavailable'
ERROR_MSG_UNAVAILABLE = 'Error message unavailable. Please check the asset configuration and|or action parameters'
PARSE_ERR_MSG = 'Unable to parse the error message. Please check the asset configuration and|or action parameters'

#
ENDPOINT_TYPE_VALUES = {
    '/reports': ['all', 'reports', 'all reports'],
    '/inbox_reports': ['inbox', 'inbox reports', 'uncategorized', 'uncategorized reports', 'uncategorized inbox reports'],
    '/processed_reports': ['processed', 'processed reports', 'categorized', 'categorized reports', 'categorized processed reports'],
}
#
CATEGORY_ID_VALUES = {
    '_none_': ['all'],
    '5': ['5', 'id:5', 'id: 5', 'id:5 phishing simulation', 'phishing', 'phishing simulation', 'lowest'],
    '1': ['1', 'id:1', 'id: 1', 'id:1 non malicious', 'non malicious', 'not malicious'],
    '2': ['2', 'id:2', 'id: 2', 'id:2 spam', 'spam'],
    '3': ['3', 'id:3', 'id: 3', 'id:3 crimeware', 'crimeware'],
    '4': ['4', 'id:4', 'id: 4', 'id:4 advanced threats', 'advanced threats', 'threats', 'highest'],
}
#
DOWNLOAD_METHOD_VALUES = {
    'artifact': ['artifact', 'cef'],
    'vault': ['vault', 'vault file', 'vaulted', 'vaulted file', 'file'],
}
#
RUN_QUERY_METHOD_VALUES = {
    'url': ['url', 'requesturl', 'website', 'web'],
    'sha256': ['sha256', 'sha256sum'],
    'md5': ['md5', 'md5sum'],
}
#
CATEGORY_ID_TO_SEVERITY = {
    'High': ['4'],
    'Medium': ['3'],
    'Low': ['1', '2', '5'],
}
#
DATE_SORT_DIRECTION = {
    'latest first': ['latest first', 'latest', 'newest', 'newest first'],
    'oldest first': ['oldest first', 'oldest'],
}
#
THREAT_TYPE_VALUES = {
    '_none_': ['all'],
    'Subject': ['subject'],
    'Sender': ['sender'],
    'Domain': ['domain'],
    'URL': ['url'],
    'MD5': ['md5'],
    'SHA256': ['sha256'],
}
#
THREAT_LEVEL_VALUES = {
    '_none_': ['all'],
    'Malicious': ['malicious'],
    'Suspicious': ['suspicious'],
    'Benign': ['benign'],
}
#
THREAT_LEVEL_TO_SEVERITY = {
    'High': ['malicious'],
    'Medium': ['suspicious'],
    'Low': ['benign'],
}
#
INGESTION_METHOD_VALUES = {
    'threat': ['threat indicator', 'threat indicators', 'threat', 'indicator', 'indicators'],
    'reports': ['report', 'reports'],
}
