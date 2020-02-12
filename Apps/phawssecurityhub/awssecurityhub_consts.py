# File: awssecurityhub_consts.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

AWSSECURITYHUB_EQUALS_CONSTS = 'EQUALS'
AWSSECURITYHUB_MAX_PER_PAGE_LIMIT = 100
AWSSECURITYHUB_SQS_MESSAGE_LIMIT = 10
AWSSECURITYHUB_INVALID_INTEGER = 'Please provide non-zero positive integer in {parameter}'
AWSSECURITYHUB_INVALID_DAYS = 'Error occurred while getting value of {parameter} config parameter. It should be a valid positive non-zero integer. Error is: {error}'

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
        "South Americia (Sao Paulo)": "sa-east-1"
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
