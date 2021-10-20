# File: awswafv2_consts.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

AWSWAF_VERSION_V2 = 'wafv2'
AWSWAF_ACCESS_KEY = 'access_key_id'
AWSWAF_SECRET_KEY = 'access_key_secret'
AWSWAF_REGION = 'region'
AWSWAF_SCOPE = 'scope'
AWSWAF_SCOPE_CLOUDFRONT = 'CLOUDFRONT'
AWSWAF_ADD_IP = 'add_ip'
AWSWAF_DELETE_IP = 'delete_ip'
AWSWAF_DEFAULT_LIMIT = 100
AWSWAF_INSUFFICIENT_PARAM = 'Insufficient parameters. Please provide either ip_set_name or ip_set_id'
AWSWAF_ERR_TOKEN = 'Error in connection while getting the token'
AWSWAF_ERR_CREATE_IPSET = 'Error in connection while creating a new IP set'
AWSWAF_ERR_GET_IPSET = 'Error in connection while getting an IP set'
AWSWAF_ERR_UPDATE_IPSET = 'Error in connection while updating an IP set'
AWSWAF_ERR_LIST_WEBACLS = "Error while connecting list_web_acls api"
AWSWAF_ERR_LIST_IPSET = "Error while connecting list_ip_sets api"
AWSWAF_ERR_IP_NOT_FOUND = "IP could not be found in the given ip set. Please provide valid input parameters"
AWSWAF_INVALID_INPUT = 'The given input ip_set_id/ip_set_name is not valid. Please provide valid input parameters'
AWSWAF_INVALID_IP = 'Please enter IP in a proper format which includes the mask of the IP (e.g. 126.0.0.0/24 or ' \
                         '1111:0000:0000:0000:0000:0000:0000:0115/128)'
AWSWAF_INVALID_LIMIT = 'Please provide a non-zero positive integer in limit'
AWSWAF_TEST_CONNECTIVITY_FAILED = 'Test Connectivity Failed'
AWSWAF_TEST_CONNECTIVITY_PASSED = 'Test Connectivity Passed'
AWSWAF_ADD_IP_SUCCESS = 'IP(s) added successfully'
AWSWAF_ADD_IP_FAILED = 'IP could not be added'
AWSWAF_DELETE_IP_FAILED = 'IP could not be deleted'
AWSWAF_DELETE_IP_SUCCESS = 'IP(s) deleted successfully'
AWSWAF_DELETE_IPSET_FAILED = 'IP Set could not be deleted'
AWSWAF_DELETE_IPSET_SUCCESS = 'IP Set deleted successfully'
AWSWAF_BAD_ASSET_CFG_ERR_MSG = "Please provide access keys or select assume role check box in asset configuration"
AWSWAF_INFO_CHECK_CREDENTIALS = "Querying AWS to check credentials"
AWSWAF_INFO_SCOPE = "To work with CloudFront scope, you must specify the Region US East (N. Virginia)"
AWSWAF_INFO_ACTION = "In action handler for: {0}"
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
