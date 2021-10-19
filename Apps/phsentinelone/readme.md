[comment]: # " File: readme.md"
[comment]: # "    Copyright (c) SentinelOne, 2018-2021"
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
This version of the SentinelOne app is compatible with Phantom **4.9.39220+**

## Playbook Backward Compatibility

The below-mentioned actions have been modified. Hence, it is requested to the end-user to update
their existing playbooks by re-inserting \| modifying \| deleting \| creating the corresponding
action blocks or by providing appropriate values to these action parameters to ensure the correct
functioning of the playbooks created on the earlier versions of the app.

-   The existing action parameter 'site_tokens' has been removed from the 'Block Hash', 'Unlock
    Hash', 'Quarantine Device', 'Unquarantine Device', 'Mitigate Threat', and 'Scan Endpoint'
    actions.
-   New actions 'Get Threat Info' and 'On Poll' have been added.
-   Existing actions 'List Endpoints' and 'List Threats' have been removed.
