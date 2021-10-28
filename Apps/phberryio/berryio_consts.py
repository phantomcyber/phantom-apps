# --
# File: berryio_consts.py
#
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
#
# --

ERR_CONNECTIVITY_TEST = "Connectivity test failed"
SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
ERR_SERVER_CONNECTION = "Connection failed"
ERR_FROM_SERVER = "API failed, Status code: {status}, Detail: {detail}"
ERR_API_UNSUPPORTED_METHOD = "Unsupported method"

BERRYIO_BASE_URL = "http://localhost:80"
USING_BASE_URL = "Using url: {base_url}/{api_uri}/{endpoint}"
BERRYIO_BASE_API = "/api_command/"
BERRYIO_FAIL_ERROR = "ERROR:"
# input invalid and no results dont yet apply to berryio but were left for future
BERRYIO_INPUT_INVALID = "error input invalid"
BERRYIO_NO_RESULTS = "No results found"
# MSG_MAX_POLLS_REACHED = "Reached max polling attempts."

BERRYIO_VERSION = "/version/"
BERRYIO_GPIO_STATUS = "/gpio_status/"
BERRYIO_SET_MODE = "/gpio_set_mode/"
BERRYIO_SET_VALUE = "/gpio_set_value/"

MAX_TIMEOUT_DEF = 3
SLEEP_SECS = 15
