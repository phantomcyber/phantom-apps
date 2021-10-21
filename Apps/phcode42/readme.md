[comment]: # ""
[comment]: # "    File: readme.md"
[comment]: # "    Copyright (c) 2018-2021 Splunk Inc."
[comment]: # "    "
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Playbook Backward Compatibility

-   The below-mentioned actions have been added. Hence, it is requested to the end-user to please
    update their existing playbooks by inserting \| modifying \| deleting the corresponding action
    blocks for this action on the earlier versions of the app.

      

    -   get organization info
    -   add departing employee
    -   remove departing employee

-   The existing action parameters have been modified in the actions given below. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting the
    corresponding action blocks or by providing appropriate values to these action parameters to
    ensure the correct functioning of the playbooks created on the earlier versions of the app.

      

    -   run query - The new "max_results" parameter has been added.
    -   hunt file - The new "max_results" parameter has been added.
