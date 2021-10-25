# File: awswaf_consts.py
#
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
AWSWAF_ACCESS_KEY = 'access_key_id'
AWSWAF_SECRET_KEY = 'access_key_secret'
AWSWAF_REGION = 'region'
AWSWAF_DEFAULT_LIMIT = 100
AWSWAF_INSUFFICIENT_PARAM = 'Insufficient parameters. Please provide either ip_set_name or ip_set_id'
AWSWAF_ERR_TOKEN = 'Error in connection while getting the token'
AWSWAF_ERR_CREATE_IPSET = 'Error in connection while creating a new IP set'
AWSWAF_INVALID_INPUT = 'The given input ip_set_id/ip_set_name is not valid'
AWSWAF_IMPROPER_FORMAT = 'Please enter IP in a proper format which includes the mask of the IP (e.g. 126.0.0.0/24)'
AWSWAF_INVALID_IP = 'Please provide a valid IPV4 or IPV6'
AWSWAF_INVALID_LIMIT = 'Please provide non-zero positive integer in limit'
AWSWAF_TEST_CONNECTIVITY_FAILED = 'Test Connectivity Failed'
AWSWAF_TEST_CONNECTIVITY_PASSED = 'Test Connectivity Passed'
AWSWAF_REGION_DICT = {
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
        "China (Beijing)": "cn-north-1",
        "China (Ningxia)": "cn-northwest-1",
        "EU (Frankfurt)": "eu-central-1",
        "EU (Ireland)": "eu-west-1",
        "EU (London)": "eu-west-2",
        "EU (Paris)": "	eu-west-3",
        "EU (Stockholm)": "eu-north-1",
        "South America (Sao Paulo)": "sa-east-1",
        "AWS GovCloud (US-East)": "us-gov-east-1",
        "AWS GovCloud (US)": "us-gov-west-1"
    }
