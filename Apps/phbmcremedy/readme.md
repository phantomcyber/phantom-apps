[comment]: # ""
[comment]: # "    File: readme.md"
[comment]: # "    Copyright (c) 2017-2021 Splunk Inc."
[comment]: # "    "
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""

Incidents are typically categorized among following types:

-   **User Service Restoration**
    -   Typical ITIL (Information Technology Infrastructure Library) of incident.
-   **User Service Request**
    -   Used to identify incidents that are not related to ITIL definition.
-   **Infrastructure Restoration**
    -   ITIL definition, but more focused on CI (Configuration Item) restoration.
-   **Infrastructure Event**
    -   Used for integration for system management tools.

## Playbook Backward Compatibility

-   A new action parameter has been added in the existing action. Hence, it is requested to the
    end-user to please update their existing playbooks by inserting \| modifying \| deleting the
    corresponding action blocks for this action on the earlier versions of the app.


    -   A 'offset' action parameter has been added in the 'list tickets' action

-   The existing output data paths have been modified for the 'list tickets' action. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting \| modifying
    \| deleting the corresponding action blocks to ensure the correct functioning of the playbooks
    created on the earlier versions of the app.
