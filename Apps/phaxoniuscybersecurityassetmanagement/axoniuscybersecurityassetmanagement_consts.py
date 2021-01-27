# File: axoniuscybersecurityassetmanagement_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


API_KEY = "api_key"
API_SECRET = "api_secret"
URL_KEY = "url"
PROXY_URL_KEY = "proxy_url"
SQ_NAME_KEY = "sq_name"
MAX_ROWS_KEY = "max_rows"
HOSTNAME_KEY = "hostname"
IP_KEY = "ip"
MAC_KEY = "mac"
MAIL_KEY = "mail"
USERNAME_KEY = "username"

# Maximum number of assets to allow user to fetch
MAX_ROWS = 25

# Fields to remove from each asset if found
SKIPS = ["specific_data.data.image"]

# Fields to try and convert to date time if they have these words in them
FIELDS_TIME = ["seen", "fetch", "time", "date"]

# exception handling
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Integer validation constants
VALID_INTEGER_MSG = "Please provide a valid integer value for the parameter {key}"
NON_NEGATIVE_INTEGER_MSG = "Please provide a valid non-negative integer value for the parameter {key}"
