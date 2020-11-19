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
AWSGUARDDUTY_JSON_REGION = "region"
AWSGUARDDUTY_REGION_DICT = {
        "US East (N. Virginia)": "us-east-1",
        "US East (Ohio)": "us-east-2",
        "US West (N. California)": "us-west-1",
        "US West (Oregon)": "us-west-2",
        "Asia Pacific (Mumbai)": "ap-south-1",
        "Asia Pacific (Seoul)": "ap-northeast-2",
        "Asia Pacific (Singapore)": "ap-southeast-1",
        "Asia Pacific (Sydney)": "ap-southeast-2",
        "Asia Pacific (Tokyo)": "ap-northeast-1",
        "Canada (Central)": "ca-central-1",
        "EU (Frankfurt)": "eu-central-1",
        "EU (Ireland)": "eu-west-1",
        "EU (London)": "eu-west-2",
        "EU (Paris)": "	eu-west-3",
        "South America (Sao Paulo)": "sa-east-1"
    }
