# File: symantecmanagementcenter_consts.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
# Constants relating to '_get_error_message_from_exception'

ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Symantec Management Center Server. Please check the asset configuration and|or the action parameters"

# Constant relating to '_handle_remove_content' and '_handle_add_content'
CONTENT_TYPES = ['LOCAL_CATEGORY_DB', 'URL_LIST', 'IP_LIST']
