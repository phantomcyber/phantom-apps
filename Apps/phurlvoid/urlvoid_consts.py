# --
# File: urlvoid_connector.py
#
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

BASE_URL = "http://api.urlvoid.com"

URLVOID_JSON_IDENTIFIER = "identifier"
URLVOID_JSON_APIKEY = "api_key"
URLVOID_JSON_DOMAIN = "domain"
URLVOID_JSON_POSITIVES = "positives"

URLVOID_JSON_CACHE_UPDATE_TIME = "cache_update_time"
URLVOID_JSON_CACHE_EXP_DAYS = "update_days"

URLVOID_HOST_ENDPOINT = "/host/{domain}/"
URLVOID_ERR_SERVER_CONNECTION = "Error connecting to server"
URLVOID_ERR_FROM_SERVER = "Error from server. Status Code: {status}, Details: {detail}"
URLVOID_ERR_UNABLE_TO_PARSE_REPLY = "Unable to parse reply from server"
URLVOID_ERR_PARSE_INPUT = "Unable to parse input data"
