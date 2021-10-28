# File: gsgmail_consts.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

GSGMAIL_ERR_CODE_UNAVAILABLE = 'Error code unavailable'
GSGMAIL_ERR_MESSAGE_UNAVAILABLE = 'Error message unavailable. Please check the asset configuration and|or action parameters'
GSGMAIL_UNICODE_DAMMIT_TYPE_ERROR_MESSAGE = 'Error occurred while connecting to the GMAIL server. Please check the asset configuration and|or the action parameters'
GSGMAIL_SERVICE_KEY_FAILURE = 'Unable to load the credentials from the key JSON'
GSGMAIL_CREDENTIALS_FAILURE = 'Failed to create delegated credentials'
GSGMAIL_EMAIL_FETCH_FAILURE = 'Failed to get email details'
GSGMAIL_USERS_FETCH_FAILURE = 'Failed to get users'
GSGMAIL_INVALID_INTEGER_ERR_MSG = 'Please provide a valid {msg} integer value in the "{param}"'

GSGMAIL_AUTH_GMAIL_READ = 'https://www.googleapis.com/auth/gmail.readonly'
GSGMAIL_AUTH_GMAIL_ADMIN_DIR = 'https://www.googleapis.com/auth/admin.directory.user'
GSGMAIL_DELETE_EMAIL = 'https://mail.google.com/'

GSMAIL_DEFAULT_FIRST_RUN_MAX_EMAIL = 1000
GSMAIL_DEFAULT_MAX_CONTAINER = 100
GSMAIL_MAX_RESULT = 10000
GSMAIL_OLDEST_INGEST_MANNER = 'oldest first'
GSMAIL_LATEST_INGEST_MANNER = 'latest first'

FAILED_CREATE_SERVICE = "Failed to create service object for API: {0}-{1}. {2} {3}"
GSMAIL_USER_VALID_MESSAGE = "Please make sure the user '{0}' is valid and the service account has the proper scopes enabled."
GSMAIL_POLL_NOW_PROGRESS = "Will be ingesting all possible artifacts (ignoring max artifacts value) for POLL NOW"
GSMAIL_FIRST_INGES_DELETED = "First time Ingestion detected."

# process mail constants

PROC_EMAIL_JSON_FILES = "files"
PROC_EMAIL_JSON_BODIES = "bodies"
PROC_EMAIL_JSON_DATE = "date"
PROC_EMAIL_JSON_FROM = "from"
PROC_EMAIL_JSON_SUBJECT = "subject"
PROC_EMAIL_JSON_TO = "to"
PROC_EMAIL_JSON_START_TIME = "start_time"
PROC_EMAIL_JSON_EXTRACT_ATTACHMENTS = "extract_attachments"
PROC_EMAIL_JSON_EXTRACT_EMAIL_ATTACHMENTS = "download_eml_attachments"
PROC_EMAIL_JSON_EXTRACT_URLS = "extract_urls"
PROC_EMAIL_JSON_EXTRACT_IPS = "extract_ips"
PROC_EMAIL_JSON_EXTRACT_DOMAINS = "extract_domains"
PROC_EMAIL_JSON_EXTRACT_HASHES = "extract_hashes"
PROC_EMAIL_JSON_IPS = "ips"
PROC_EMAIL_JSON_HASHES = "hashes"
PROC_EMAIL_JSON_URLS = "urls"
PROC_EMAIL_JSON_DOMAINS = "domains"
PROC_EMAIL_JSON_MSG_ID = "message_id"
PROC_EMAIL_JSON_EMAIL_HEADERS = "email_headers"
PROC_EMAIL_CONTENT_TYPE_MESSAGE = "message/rfc822"
PROC_EMAIL_PARSED = "Email Parsed"
PROC_EMAIL_PROCESSED = "Email Processed"

PROC_EMAIL_MAPPED_HASH_VAL = "Mapped hash values"

PROC_EMAIL_SAVE_CONTAINER = "save_container returns, value: {0}, reason: {1}, id: {2}"
PROC_EMAIL_FAILED_CONTAINER = "Failed to add Container for id: {0}, error msg: {1}"
PROC_EMAIL_SAVE_CONTAINER_FAILED = "save_container did not return a container_id"
PROC_EMAIL_SAVE_CONT_PASSED = "save_artifact returns, value: {0}, reason: {1}, id: {2}"
PROC_EMAIL_FAILED_VAULT_CONT_DATA = "Failed to get vault item metadata"
PROC_EMAIL_FAILED_VAULT_ADD_FILE = "Failed to add file to Vault: {0}"


URI_REGEX = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
EMAIL_REGEX = r"\b[A-Z0-9._%+-]+@+[A-Z0-9.-]+\.[A-Z]{2,}\b"
EMAIL_REGEX2 = r'".*"@[A-Z0-9.-]+\.[A-Z]{2,}\b'
HASH_REGEX = r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b"
IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
IPV6_REGEX = r'\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))'
IPV6_REGEX += r'|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*'
