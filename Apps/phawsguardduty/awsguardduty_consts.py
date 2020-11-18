# File: awsguardduty_consts.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

AWSGUARDDUTY_MAX_PER_PAGE_LIMIT = 50
AWSGUARDDUTY_POLL_NOW_DAYS = 30
AWSGUARDDUTY_INVALID_LIMIT = 'Please provide non-zero positive integer in {param_name}'
AWSGUARDDUTY_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
AWSGUARDDUTY_SEVERITY_MAP = {
            'Low': '2',
            'Medium': '5',
            'High': '8'
        }
AWSGUARDDUTY_SEVERITY_REVERSE_MAP = {
            2: 'Low',
            5: 'Medium',
            8: 'High'
        }
