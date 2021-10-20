[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2018-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Playbook Backward Compatibility

-   The below-mentioned action has been added. Hence, it is requested to the end-user to please
    update their existing playbooks by inserting the corresponding action blocks for this action on
    the earlier versions of the app.

      

    -   create task log

-   The existing output data paths have been modified for the 'get observables' action. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting \| modifying
    \| deleting the corresponding action blocks to ensure the correct functioning of the playbooks
    created on the earlier versions of the app.
