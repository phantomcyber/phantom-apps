# File: taniumrest_consts.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

SESSION_URL = "/api/v2/session/login"
TANIUMREST_GET_SAVED_QUESTIONS = "/api/v2/saved_questions"
TANIUMREST_GET_QUESTIONS = "/api/v2/questions"
TANIUMREST_GET_QUESTION_RESULTS = "/api/v2/result_data/question/{question_id}"
TANIUMREST_PARSE_QUESTION = "/api/v2/parse_question"
TANIUMREST_EXECUTE_ACTION = "/api/v2/saved_actions"
TANIUMREST_GET_ACTION_GROUP = "/api/v2/action_groups/by-name/{action_group}"
TANIUMREST_GET_GROUP = "/api/v2/groups/by-name/{group_name}"
TANIUMREST_GET_PACKAGE = "/api/v2/packages/by-name/{package}"
TANIUMREST_GET_SAVED_QUESTION = "/api/v2/saved_questions/by-name/{saved_question}"
TANIUMREST_GET_SENSOR_BY_NAME = "/api/v2/sensors/by-name/{sensor_name}"
TANIUMREST_GET_SAVED_QUESTION_RESULT = "/api/v2/result_data/saved_question/{saved_question_id}"
WAIT_SECONDS = 5
TANIUMREST_RESULTS_UNAVAILABLE = ["[current results unavailable]", "[current result unavailable]", "[results currently unavailable]"]

# Constants relating to 'get_error_message_from_exception'
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Tanium Server. Please check the asset configuration and|or action parameters"

# Constants relating to 'validate_integer'
INVALID_INT_ERR_MSG = "Please provide a valid integer value in the {}"
INVALID_NON_NEG_INT_ERR_MSG = "Please provide a valid non-negative integer value in the {}"
INVALID_NON_NEG_NON_ZERO_ERR_MSG = "PLease provide a valid non-zero non-negative integer value in the {}"
EXPIRE_SECONDS_KEY = "'expire_seconds' action parameter"
DISTRIBUTE_SECONDS_KEY = "'distribute_seconds' action parameter"
ISSUE_SECONDS_KEY = "'issue_seconds' action parameter"
TIMEOUT_SECONDS_KEY = "'timeout_seconds' action parameter"
RETURN_WHEN_N_RESULTS_AVAILABLE_KEY = "'return_when_n_results_available' action parameter"
WAIT_FOR_N_RESULTS_AVAILABLE_KEY = "'wait_for_n_results_available' action parameter"
RESULTS_PERCENTAGE_KEY = "'Consider question results complete at' configuration parameter"
QUESTION_ID_KEY = "'question_id' action parameter"
