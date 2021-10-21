[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
**Permissions**

The following is a breakdown of the permission needed for the API user to be able to use the action
in this app. These permissions are controlled in the IAM section of the ETP server. For information
pertaining to setting up the API user refer to the API documentation located at
https://docs.fireeye.com/docs/index.html#ETP.

For any API access, the following entitlements are required:

-   iam.users.browse
-   iam.orgs.self.read

For accessing alerts APIs, the following additional entitlements are required:

-   etp.alerts.read

For accessing trace APIs, the following additional entitlements are required:

-   etp.email_trace.read

For accessing quarantine APIs, the following additional entitlements are required:

-   etp.quarantine.update
-   etp.quarantine.read
-   etp.quarantine.delete

  
  

**Actions**

It is important to know that all the actions in this app take affect on the Fireeye ETP side, with
the exception of *remediating email* . For example, deleting a quarantined email is the action that
deletes the email in the Fireeye ETP quarantined section, not in the Office365. Office365 may have
other actions for quarantined emails from there own security suite

*Remediate Email action*

This action talks to the API for Office365 which will move/delete the email depending on the input
from the user. This action does not have an undo function and if the user selects action_overrite of
delete, this email will be permanently deleted in the Office365 environment and not recoverable. Use
cautiously!
