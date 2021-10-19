[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
This app is used for detonating files and URLs on a Fireeye AX (Malware Analysis) console.

**Permissions**

To submit API requests from a remote system, you need a valid API user account on the appliance
where you will run the Web Services API. Create one of the following API user accounts:

-   api_analyst
-   api_monitor

The following tables show the breakdown of the user access and what actions they can perform.

|                                    |             |             |       |
|------------------------------------|-------------|-------------|-------|
| Permissions                        | api_analyst | api_monitor | admin |
| Read Alerts                        | Yes         | Yes         | Yes   |
| Update Alerts (Central Management) | Yes         | No          | Yes   |
| Read Reports                       | Yes         | Yes         | Yes   |
| Read Stats (Central Management)    | Yes         | No          | Yes   |
| Submit Object                      | Yes         | No          | Yes   |
| Submit URL (other appliances)      | Yes         | No          | Yes   |
