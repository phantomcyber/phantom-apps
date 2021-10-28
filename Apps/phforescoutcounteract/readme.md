[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2018-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
<div>

This app requires  **CounterACT 8.0** or above with the **eyeExtend Connect Module** installed. When
the eyeExtend Connect Module is installed, Web API and Data Exchange (DEX) modules will be
available. Web API is a read-only module, while DEX is a read and write module.

</div>

<div>

In the case of restricting updates to CounterACT, only supply Web API credentials in the asset
configuration.

</div>

## Playbook Backward Compatibility

-   The existing action parameters have been modified in the actions given below. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting \| modifying
    \| deleting the corresponding action blocks or by providing appropriate values to these action
    parameters to ensure the correct functioning of the playbooks created on the earlier versions of
    the app.

      

    -   get device info - Added two new parameters for this action.

          

        -   The parameters 'host_ip' and 'host_mac' have been added.
