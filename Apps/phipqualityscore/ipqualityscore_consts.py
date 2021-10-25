# File: ipqualityscore_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

IPQUALITYSCORE_DOMAIN = 'https://ipqualityscore.com'

IPQUALITYSCORE_API_TEST = 'https://ipqualityscore.com/api/json/ip/{apikey}/8.8.8.8'
IPQUALITYSCORE_API_URL_CHECKER = 'https://ipqualityscore.com/api/json/url/{apikey}/{url}'
IPQUALITYSCORE_API_IP_REPUTATION = 'https://ipqualityscore.com/api/json/ip/{apikey}/{ip}'
IPQUALITYSCORE_API_EMAIL_VALIDATION = 'https://ipqualityscore.com/api/json/email/{apikey}/{email}'

IPQUALITYSCORE_APP_KEY = 'app_key'
IPQUALITYSCORE_MSG_QUERY_URL = 'Querying URL: {query_url}'
IPQUALITYSCORE_MSG_CONNECTING = 'Polling IPQualityScore site ...'
IPQUALITYSCORE_SERVICE_SUCC_MSG = 'IPQualityScore Service successfully executed.'
IPQUALITYSCORE_SUCC_CONNECTIVITY_TEST = 'Test Connectivity passed'
IPQUALITYSCORE_ERR_CONNECTIVITY_TEST = 'Test Connectivity failed'
IPQUALITYSCORE_MSG_GOT_RESP = 'Got response from IPQualityScore'
IPQUALITYSCORE_NO_RESPONSE = 'Server did not return a response \
                         for the object queried'
IPQUALITYSCORE_SERVER_CONNECTION_ERR = 'Server connection error'
IPQUALITYSCORE_MSG_CHECK_CONNECTIVITY = 'Please check your network connectivity'
IPQUALITYSCORE_SERVER_RETURNED_ERR_CODE = 'Server returned error code: {code}'
IPQUALITYSCORE_ERR_MSG_OBJECT_QUERIED = "IPQualityScore response didn't \
                                    send expected response"
IPQUALITYSCORE_SERVER_ERR_RATE_LIMIT = 'Query is being rate limited. \
                                     Server returned 509'

ACTION_ID_URL_CHECKER = 'check_url'
ACTION_ID_IP_REPUTATION = 'ip_reputation'
ACTION_ID_EMAIL_VALIDATION = 'email_validation'

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Constants relating to '_validate_integer'
VALID_INTEGER_MSG = "Please provide a valid integer value in the {}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value in the {}"
TIMEOUT_KEY = "'timeout' action parameter"
STRICTNESS_KEY = "'strictness' action parameter"
ABUSE_STRICTNESS_KEY = "'abuse_strictness' action parameter"
TRANSACTION_STRICTNESS_KEY = "'transaction_strictness' action parameter"
