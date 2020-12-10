# File: taniumrest_consts.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
SESSION_URL = "/api/v2/session/login"
TANIUMREST_GET_SAVED_QUESTIONS = "/api/v2/saved_questions"
TANIUMREST_GET_QUESTIONS = "/api/v2/questions"
TANIUMREST_PARSE_QUESTION = "/api/v2/parse_question"
TANIUMREST_EXECUTE_ACTION = "/api/v2/saved_actions"
TANIUMREST_GET_ACTION_GROUP = "/api/v2/action_groups/by-name/{action_group}"
TANIUMREST_GET_PACKAGE = "/api/v2/packages/by-name/{package}"
TANIUMREST_GET_SAVED_QUESTION = "/api/v2/saved_questions/by-name/{saved_question}"
TANIUMREST_GET_SENSOR_BY_NAME = "/api/v2/sensors/by-name/{sensor_name}"
TANIUMREST_GET_SAVED_QUESTION_RESULT = "/api/v2/result_data/saved_question/{saved_question_id}"
TANIUMREST_ERR_INVALID_PARAM = "Please provide non-zero positive integer in {param}"
WAIT_SECONDS = 5
