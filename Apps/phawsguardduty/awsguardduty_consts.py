# File: awsguardduty_consts.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

AWSGUARDDUTY_MAX_PER_PAGE_LIMIT = 50
AWSGUARDDUTY_POLL_NOW_DAYS = 30
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
        "US East(N. Virginia) us-east-1": "us-east-1",
        "US East(Ohio) us-east-2": "us-east-2",
        "US West(N. California) us-west-1": "us-west-1",
        "US West(Oregon) us-west-2": "us-west-2",
        "Africa(Cape Town) af-south-1": "af-south-1",
        "Asia Pacific(Hong Kong) ap-east-1": "ap-east-1",
        "Asia Pacific(Mumbai) ap-south-1": "ap-south-1",
        "Asia Pacific(Seoul) ap-northeast-2": "ap-northeast-2",
        "Asia Pacific(Singapore) ap-southeast-1": "ap-southeast-1",
        "Asia Pacific(Sydney) ap-southeast-2": "ap-southeast-2",
        "Asia Pacific(Tokyo) ap-northeast-1": "ap-northeast-1",
        "Canada(Central) ca-central-1": "ca-central-1",
        "Europe(Frankfurt) eu-central-1": "eu-central-1",
        "Europe(Ireland) eu-west-1": "eu-west-1",
        "Europe(London) eu-west-2": "eu-west-2",
        "Europe(Milan) eu-south-1": "eu-south-1",
        "Europe(Paris) eu-west-3": "eu-west-3",
        "Europe(Stockholm) eu-north-1": "eu-north-1",
        "Middle East(Bahrain) me-south-1": "me-south-1",
        "South America(Sao Paulo) sa-east-1": "sa-east-1"
    }

# Constants relating to error messages
AWSGUARDDUTY_ERR_FETCHING_PYTHON_VERSION_MSG = "Error occurred while fetching the Phantom server's Python major version"
AWSGUARDDUTY_PY_2TO3_ERR_MSG = "Error occurred while handling python 2to3 compatibility for the input string"
AWSGUARDDUTY_CREATE_CLIENT_ERR_MSG = "Could not create boto3 client"
AWSGUARDDUTY_TEST_CONN_FAILED_MSG = "Test Connectivity Failed"
AWSGUARDDUTY_TEST_CONN_PASSED_MSG = "Test Connectivity Passed"
AWSGUARDDUTY_CREATE_CONTAINER_ERR_MSG = "Error occurred while creating container for finding {finding_id}"
AWSGUARDDUTY_CREATE_ARTIFACT_ERR_MSG = "Error while creating artifacts for container with ID {container_id}"
AWSGUARDDUTY_CREATE_ARTIFACT_MSG = "Artifacts created successfully"
AWSGUARDDUTY_INVALID_METHOD_ERR_MSG = "Invalid method: {method}"
AWSGUARDDUTY_PROCESS_RESPONSE_ERR_MSG = "Error occurred while processing response"
AWSGUARDDUTY_BOTO3_CONN_FAILED_MSG = 'Boto3 call to Guardduty failed'
AWSGUARDDUTY_INVALID_FINDING_ID_ERR_MSG = "Please provide a valid input value in the 'finding_id' action parameter"
AWSGUARDDUTY_INVALID_FEEDBACK_ERR_MSG = "Please provide a valid input value in the 'feedback' action parameter"
AWSGUARDDUTY_UPDATE_FINDING_SUCC_MSG = "Successfully updated finding ID(s)"
AWSGUARDDUTY_ARCHIVE_FINDING_SUCC_MSG = "Successfully archived the findings"
AWSGUARDDUTY_UNARCHIVE_FINDING_SUCC_MSG = "Successfully unarchived the findings"
AWSGUARDDUTY_INVALID_SEVERITY_ERR_MSG = "Please provide a valid input value in the 'severity' action parameter"
AWSGUARDDUTY_FINDING_ID_NOT_FOUND_ERR_MSG = "Please provide valid Finding IDs"
AWSGUARDDUTY_FINDING_ID_IN_RECORD_STATE_ERR_MSG = "The provided finding IDs are already in {record_state}"
AWSGUARDDUTY_BAD_ASSET_CONFIG_ERR_MSG = "Please provide access keys or select assume role check box in asset configuration"

# Constants relating to 'get_error_message_from_exception'
AWSGUARDDUTY_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
AWSGUARDDUTY_ERR_CODE_UNAVAILABLE = "Error code unavailable"
AWSGUARDDUTY_UNICODE_DAMMIT_TYPE_ERR_MSG = "Error occurred while connecting to the AWS GuardDuty server. Please check the asset configuration and|or the action parameters."

# Constants relating to 'validate_integer'
AWSGUARDDUTY_VALID_INT_MSG = "Please provide a valid integer value in the {param}"
AWSGUARDDUTY_NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in {param}"
AWSGUARDDUTY_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the {param}"
AWSGUARDDUTY_LIMIT_KEY = "'limit' action parameter"
AWSGUARDDUTY_POLL_NOW_DAYS_KEY = "'poll_now_days' configuration parameter"

# Constants relating to value list
AWSGUARDDUTY_FEEDBACK_LIST = ['USEFUL', 'NOT_USEFUL']
