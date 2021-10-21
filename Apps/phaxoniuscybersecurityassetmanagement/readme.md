[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Playbook Backward Compatibility

-   A new action parameter has been added in the below existing actions. Hence, it is requested to
    the end-user to please update their existing playbooks by re-inserting \| modifying \| deleting
    the corresponding action blocks.

      

    -   The 'additional_fields' parameter has been added in all the actions mentioned below:

          

        -   devices by hostname
        -   devices by ip
        -   devices by mac
        -   users by mail
        -   users by username

-   The version 2.0.0 of this application is a complete rewrite and is not backward compatible.
    Hence, it is requested to the end-user to please update their existing playbooks by re-inserting
    \| modifying \| deleting the corresponding action blocks to ensure the correct functioning of
    the playbooks created on the earlier versions of the app. If the end-user does not want to
    upgrade their playbooks, they can remain on or downgrade to the old version(v1.0.0).
