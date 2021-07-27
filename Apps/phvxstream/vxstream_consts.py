# File: vxstream_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

PAYLOAD_SECURITY_API_KEY = 'api_key'
PAYLOAD_SECURITY_API_SECRET = 'api_secret'
PAYLOAD_SECURITY_WEBSERVICE_BASE_URL = 'base_url'
PAYLOAD_SECURITY_VERIFY_SERVER_CERT = 'verify_server_cert'

PAYLOAD_SECURITY_MSG_QUERYING = 'Querying Falcon Sandbox'
PAYLOAD_SECURITY_MSG_SUBMITTING_FILE = 'Submitting file/url to Falcon Sandbox'
PAYLOAD_SECURITY_MSG_CHECKED_STATE = 'Actual state is \'{}\'. Last check: {}. Done already {} attempts of foreseen {}. The next attempt will be done after {} seconds.'
PAYLOAD_SECURITY_MSG_DETONATION_QUERYING_REPORT = 'Querying Falcon Sandbox to get the report'
# When new verdict name will be added, remember about adding it to output in config json file
PAYLOAD_SECURITY_SAMPLE_VERDICT_NAMES = ['no specific threat', 'whitelisted', 'no verdict', 'suspicious', 'malicious', 'unknown']

PAYLOAD_SECURITY_DETONATION_QUEUE_TIME_INTERVAL_SECONDS = 60
PAYLOAD_SECURITY_DETONATION_QUEUE_NUMBER_OF_ATTEMPTS = 1440
PAYLOAD_SECURITY_DETONATION_PROGRESS_TIME_INTERVAL_SECONDS = 30
PAYLOAD_SECURITY_DETONATION_PROGRESS_NUMBER_OF_ATTEMPTS = 30

PAYLOAD_SECURITY_SAMPLE_STATE_IN_QUEUE = 'IN_QUEUE'
PAYLOAD_SECURITY_SAMPLE_STATE_IN_PROGRESS = 'IN_PROGRESS'
PAYLOAD_SECURITY_SAMPLE_STATE_SUCCESS = 'SUCCESS'
PAYLOAD_SECURITY_SAMPLE_STATE_ERROR = 'ERROR'
