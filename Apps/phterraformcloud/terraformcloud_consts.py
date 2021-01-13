# File: terraformcloud_consts.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

TERRAFORM_DEFAULT_URL = "https://app.terraform.io"
TERRAFORM_BASE_API_ENDPOINT = "/api/v2"

TERRAFORM_ENDPOINT_WORKSPACES = "/organizations/{organization_name}/workspaces"
TERRAFORM_ENDPOINT_GET_WORKSPACE_BY_ID = "/workspaces/{id}"
TERRAFORM_ENDPOINT_RUNS = "/runs"
TERRAFORM_ENDPOINT_LIST_RUNS = "/workspaces/{id}/runs"
TERRAFORM_ENDPOINT_ACCOUNT_DETAILS = "/account/details"
TERRAFORM_ENDPOINT_APPLIES = "/applies/{id}"
TERRAFORM_ENDPOINT_APPLY_RUN = "/runs/{run_id}/actions/apply"
TERRAFORM_ENDPOINT_PLANS = "/plans/{id}"

# exception handling
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Terraform Cloud Server. Please check the asset configuration and|or the action parameters"

# validate integer
ERR_VALID_INT_MSG = "Please provide a valid integer value in the {}"
ERR_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the {}"
PAGE_NUM_INT_PARAM = "'page_num' action parameter"
PAGE_SIZE_INT_PARAM = "'page_size' action parameter"
