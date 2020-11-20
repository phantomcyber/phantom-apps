# File: hashicorp_vault_consts.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Action Identifier constants
ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'
ACTION_ID_SET_SECRET = 'set_secret'
ACTION_ID_GET_SECRET = 'get_secret'
ACTION_ID_LIST_SECRETS = 'list_secrets'

# Error message handling constants
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
TYPE_ERR_MSG = "Error occurred while connecting to the Hashicorp Vault Server. Please check the asset configuration and|or the action parameters"
