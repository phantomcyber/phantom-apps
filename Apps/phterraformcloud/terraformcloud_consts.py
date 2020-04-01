# File: terraformcloud_consts.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL – Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
 
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