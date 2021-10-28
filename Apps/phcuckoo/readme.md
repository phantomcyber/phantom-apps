[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2014-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## SDK and SDK Licensing details for the app

#### pexpect

This app uses the pexpect module, which is licensed under the ISC License (ISCL), Copyright (c) Noah
Spurrier, Thomas Kluyver, Jeff Quast.

#### ptyprocess

This app uses the ptyprocess module, which is licensed under the ISC License (ISCL), Copyright (c)
Thomas Kluyver.

### Getting Web Reports

If you add the base URL to the Cuckoo instance's Web Interface, a link will be generated and added
to the action result which will point to analysis summary for each action.

## Playbook Backward Compatibility

-   The existing action parameter has been modified in the action given below. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting \| modifying
    \| deleting the corresponding action blocks or by providing appropriate values to these action
    parameters to ensure the correct functioning of the playbooks created on the earlier versions of
    the app.

      

    -   Detonate File - The new \[zip_and_encrypt\] parameter has been added providing an option to
        zip and encrypt the file.

-   New action 'submit strings' has been added. Hence, it is requested to the end-user to please
    update their existing playbooks by inserting the corresponding action blocks for this action on
    the earlier versions of the app.
