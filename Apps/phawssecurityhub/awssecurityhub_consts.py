# File: awssecurityhub_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

AWSSECURITYHUB_EQUALS_CONSTS = 'EQUALS'
AWSSECURITYHUB_MAX_PER_PAGE_LIMIT = 100
AWSSECURITYHUB_SQS_MESSAGE_LIMIT = 10

AWSSECURITYHUB_REGION_DICT = {
        "US East (Ohio)": "us-east-2",
        "US East (N. Virginia)": "us-east-1",
        "US West (N. California)": "us-west-1",
        "US West (Oregon)": "us-west-2",
        "Canada (Central)": "ca-central-1",
        "Asia Pacific (Mumbai)": "ap-south-1",
        "Asia Pacific (Tokyo)": "ap-northeast-1",
        "Asia Pacific (Seoul)": "ap-northeast-2",
        "Asia Pacific (Singapore)": "ap-southeast-1",
        "Asia Pacific (Sydney)": "ap-southeast-2",
        "China (Ningxia)": "cn-northwest-1",
        "EU (Frankfurt)": "eu-central-1",
        "EU (Ireland)": "eu-west-1",
        "EU (London)": "eu-west-2",
        "EU (Paris)": "eu-west-3",
        "South America (Sao Paulo)": "sa-east-1"
    }

AWSSECURITYHUB_FINDING_CEF_TYPES = {
        "Id": ["aws security hub findings id", "aws arn"],
        "ProductArn": ["aws arn"],
        "GeneratorId": ["aws arn"],
        "ProductFields.aws/securityhub/FindingId": ["aws arn"],
        "ProductFields.action/networkConnectionAction/localPortDetails/port": ["port"],
        "ProductFields.action/networkConnectionAction/remotePortDetails/port": ["port"],
        "ProductFields.action/networkConnectionAction/remoteIpDetails/ipAddressV4": ["ip"]
    }

AWSSECURITYHUB_RESOURCE_CEF_TYPES = {
        "Id": ["aws arn"],
        "InstanceId": ["aws ec2 instance id"],
        "Details.AwsEc2Instance.IpV4Addresses": ["ip"]
    }

# constants relating to error messages
AWSSECURITYHUB_ERR_FETCHING_PYTHON_VERSION_MSG = "Error occurred while fetching the Phantom server's Python major version"
AWSSECURITYHUB_PY_2TO3_ERR_MSG = "Error occurred while handling python 2to3 compatibility for the input string"

# constants relating to 'get_error_message_from_exception'
AWSSECURITYHUB_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
AWSSECURITYHUB_ERR_CODE_UNAVAILABLE = "Error code unavailable"
AWSSECURITYHUB_PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# constants relating to 'validate_integer'
AWSSECURITYHUB_VALID_INT_MSG = "Please provide a valid integer value in the {param}"
AWSSECURITYHUB_NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in {param}"
AWSSECURITYHUB_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the {param}"
AWSSECURITYHUB_LIMIT_KEY = "'limit' action parameter"
AWSSECURITYHUB_POLL_NOW_DAYS_KEY = "'poll_now_days' configuration parameter"
AWSSECURITYHUB_SCHEDULED_POLL_DAYS_KEY = "'scheduled_poll_days' configuration parameter"
