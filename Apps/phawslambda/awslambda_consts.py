# File: awslambda_consts.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
# Define your constants here

LAMBDA_JSON_ACCESS_KEY = "access_key"
LAMBDA_JSON_SECRET_KEY = "secret_key"
LAMBDA_JSON_REGION = "region"

LAMBDA_REGION_DICT = {
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

LAMBDA_BAD_ASSET_CONFIG_MSG = "Please provide access keys or select assume role check box in asset configuration"
EC2_ROLE_CREDENTIALS_FAILURE_MSG = "Failed to get EC2 role credentials"
