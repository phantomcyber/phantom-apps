# File: ipcontrol_consts.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

IPCONTROL_ENDPOINT_LOGIN = '/login'
IPCONTROL_ENDPOINT = '/inc-rest/api/v1'
IPCONTROL_ENDPOINT_GET_CHILD_BLOCK = '/Exports/initExportChildBlock'
IPCONTROL_ENDPOINT_GET_HOSTNAME = '/Gets/getDeviceByIPAddr?ipAddress='
IPCONTROL_ENDPOINT_GET_BLOCK_TYPE = '/Exports/initExportChildBlock'
IPCONTROL_ENDPOINT_GET_IP_ADDRESS = '/Gets/getDeviceByHostname?hostname='

IPCONTROL_SUCC_TEST_CONNECTIVITY = 'Test Connectivity Passed'
IPCONTROL_ERR_TEST_CONNECTIVITY = 'Test Connectivity Failed'
IPCONTROL_ERR_NO_DATA_FOUND = 'No data found for parameter'
