DG_CONFIG_SERVER_URL = 'server_url'
DG_CONFIG_API_KEY = 'api_key'
DG_ON_POLL = '/1.0/rest/1.0/export_profiles'
DG_COMPONENT_LIST = '/1.0/remediation/lists'
DG_WATCHLIST = '/rest/1.0/watchlists'
DG_PARAM_LIST_FILES = 'get-files'
DG_PARAM_IP = 'ip'
DG_HEADER_URL = {'Content-Type': 'application/x-www-form-urlencoded', }
DG_HEADER_JSON = {'Content-Type': 'application/json'}
DG_CLIENT_HEADER = {'Authorization': '', 'Accept': 'application/json'}
DG_PARAM_START_TIME = 'start_time'
DG_PARAM_END_TIME = 'end_time'
DG_QUERY_PARAM = 'srcip eq {srcip} or dstip eq {dstip}'
DG_INVALID_START_TIME = "Parameter 'start_time' failed validation"
DG_INVALID_END_TIME = "Parameter 'end_time' failed validation"
DG_INVALID_TIME_RANGE = ("Invalid time range. 'end_time'"
                         "should be greater than 'start_time'")
DG_INVALID_TIME = 'Invalid time. Time cannot be negative'
DG_VALID_TIME = 'TIme validation successful'
DG_CONNECTIVITY_PASS_MSG = 'Test Connectivity Passed'
DG_CONNECTIVITY_FAIL_MSG = 'Test Connectivity Failed'
DG_CONNECTION_MSG = 'Querying endpoint to verify the credentials provided'
DG_ERROR_CONNECTING_SERVER = 'Error while connecting to server'
DG_JSON_FILE = 'file'
DG_JSON_PROFILE = 'profile'
DG_TEST_CONNECTIVITY_LIMIT = 1
DG_24_HOUR_GAP = 86400
DG_INITIAL_SKIP_VALUE = 0
DG_UPDATE_SKIP_VALUE = 5000
DG_DEFAULT_LIMIT = 50
DG_LIST_NAME = 'list_name'

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Digital Guardian ARC Server. Please check the asset configuration and|or the action parameters"
