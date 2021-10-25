# File: digitalguardianarc_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

DG_HEADER_URL = {'Content-Type': 'application/x-www-form-urlencoded', }
DG_CLIENT_HEADER = {'Authorization': '', 'Accept': 'application/json'}

# Constants relating to '_get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Digital Guardian ARC Server. Please check the asset configuration and|or the action parameters"
