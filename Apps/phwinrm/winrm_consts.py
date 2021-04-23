# File: winrm_consts.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

APPLOCKER_BASE_SCRIPT = """
Import-Module AppLocker
"""

APPLOCKER_GET_POLICIES = 'Get-AppLockerPolicy -{0} {1}'

APPLOCKER_CREATE_POLICY = """
$Policy = Get-ChildItem "{0}" | Get-AppLockerFileInformation | New-AppLockerPolicy -RuleType Path,Hash {1}
foreach($RuleCollection in $Policy.RuleCollections)
{{
    foreach($Rule in $RuleCollection)
    {{
        $Rule.Description = 'Created by Phantom'
    }}
}}
Set-AppLockerPolicy -PolicyObject $Policy {2} -Merge
"""

# You can't actually create a blocking rule, so we need to edit that field in our created policy
APPLOCKER_CREATE_POLICY_DENY = """
$Policy = Get-ChildItem "{0}" | Get-AppLockerFileInformation | New-AppLockerPolicy -RuleType Path,Hash {1}
foreach($RuleCollection in $Policy.RuleCollections)
{{
    foreach($Rule in $RuleCollection)
    {{
        $Rule.Description = 'Created by Phantom'
        $Rule.Action = 'Deny'
    }}
}}
Set-AppLockerPolicy -PolicyObject $Policy {2} -Merge
"""

APPLOCKER_DELETE_POLICY = """
$tomatch_id = "{0}"
$Policy = {1}
$Passed = $False
foreach($RuleCollection in $Policy.RuleCollections)
{{
    foreach($Rule in $RuleCollection)
    {{
        if ($Rule.Id.Value -eq $tomatch_id)
        {{
            $RuleCollection.Delete($Rule.Id)
            $Passed = $True
            break
        }}
    }}
}}
if ($Passed -eq $False)
{{
    throw "No AppLocker Policy with specified ID was found"
}}
Set-AppLockerPolicy -PolicyObject $Policy {2}
"""

SEND_FILE_START = """
$f = @"
{b64string_chunk}
"@

$fp = "{file_path}"

$f {action} $fp
"""

SEND_FILE_END = """
$d = Get-Content $fp
[IO.File]::WriteAllBytes($fp, [Convert]::FromBase64String($d))
"""

GET_FILE = """
$d = "{}"
[Convert]::ToBase64String([IO.File]::ReadAllBytes($d))
"""

WINRM_UNICODE_ERR_MESSAGE = "Invalid unicode detected"

# Constants relating to '_validate_integer'
WINRM_ERR_INVALID_INT = 'Please provide a valid {msg} integer value in the "{param}"'
WINRM_ERR_PARTITION = "Failed to fetch system volume, Please check the asset configuration and|or \"ip hostname\" parameter"
WINRM_ERR_INVALID_VAULT_ID = "Could not retrieve vault file"

# Constants relating to '_get_error_message_from_exception'
WINRM_ERR_CODE_MSG = "Error code unavailable"
WINRM_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
WINRM_PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"
WINRM_TYPE_ERR_MSG = "Error occurred while connecting to the Winrm Server. Please check the asset configuration and|or the action parameters"

# Constants relating to value_list check
DIRECTION_VALUE_LIST = ["in", "out"]
DIR_VALUE_LIST = ["in", "out"]
ACTION_VALUE_LIST = ["allow", "block", "bypass"]
LOCATION_VALUE_LIST = ["local", "domain", "effective"]
DENY_ALLOW_VALUE_LIST = ["deny", "allow"]
VALUE_LIST_VALIDATION_MSG = "Please provide valid input from {} in '{}' action parameter"
