# File: smtp_consts.py
#
# Copyright (c) 2014-2021 Splunk Inc.
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
SMTP_SUCC_SMTP_CONNECTED_TO_SERVER = "Connected to server"
SMTP_SUCC_SMTP_EMAIL_SENT = "Email sent"
SMTP_ERR_SMTP_CONNECT_TO_SERVER = "Connection to server failed"
SMTP_ERR_SMTP_SEND_EMAIL = "Email send failed"
SMTP_SUCC_CONNECTIVITY_TEST = "Test Connectivity Passed"
SMTP_ERR_CONNECTIVITY_TEST = "Test Connectivity Failed"

SMTP_PROG_UNABLE_TO_ATTACH_FILE = "Unable to attach file {}"
SMTP_MSG_SKIP_AUTH_NO_USERNAME_PASSWORD = "Skipping authentication, since Username or Password not configured"
SMTP_ERR_PARSE_HEADERS = 'Unable to parse headers as a dictionary: {}'
SMTP_UNICODE_ERROR_MSG = "Error occurred while associating the email content in the email message object. If you are dealing with the Unicode characters, \
please mark the asset configuration parameter 'Enable Unicode support' as true, if not done already and try again."
SMTP_JSON_ATTACHMENTS = "attachments"
SMTP_JSON_BODY = "body"
SMTP_JSON_HEADERS = "headers"
SMTP_JSON_FROM = "from"
SMTP_JSON_PORT = "port"
SMTP_JSON_SUBJECT = "subject"
SMTP_JSON_TO = "to"
SMTP_JSON_CC = "cc"
SMTP_JSON_BCC = "bcc"
SMTP_JSON_USE_SSL = "use_ssl"
SMTP_JSON_TOTAL_SCANS = "total_scans"
SMTP_JSON_TOTAL_POSITIVES = "total_positives"
SMTP_JSON_TOTAL_GUESTS = "total_guests"
SMTP_JSON_TOTAL_GUESTS_RUNNING = "total_guests_running"
SMTP_JSON_SSL_CONFIG = "ssl_config"
SSL_CONFIG_NONE = "None"
SSL_CONFIG_SSL = "SSL"
SSL_CONFIG_STARTTLS = "StartTLS"
SMTP_ENCODING = "encoding"
SMTP_ALLOW_SMTPUTF8 = "allow_smtputf8"

SMTP_SENDING_TEST_MAIL = "Sending test mail"
SMTP_DONE = "Done..."

SMTP_ERR_SSL_CONFIG_SSL = "Possible misconfiguration. The current SSL configuration value requires the server to speak SSL from the beginning of the connection."
SMTP_ERR_STARTTLS_CONFIG = "Possible misconfiguration. The current SSL configuration value requires the server to support the startTLS command issued after a connection is made."
SMTP_ERR_SMTPUTF8_CONFIG = "Unable to encode the Unicode characters. Possible misconfiguration. \
Either the server does not support SMTPUT8 or the 'Enable SMTPUTF8 support' asset configuration parameter is set to False"
SMTP_ERR_TO_FROM_UNAVAILABLE = "Error: Failed to send the email. The {} is unavailable. Please check the action parameters"

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_UNAVAILABLE = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the server. Please check the asset configuration and|or the action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
