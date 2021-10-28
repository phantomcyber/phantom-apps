[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
The app pulls cloudaudit and access Bitglass log data filtered down to the specified DLP patterns.
It also provides actions for access to Bitglass REST APIs for group and user manipulation. A sample
playbook is included.

## Troubleshooting tips, known issues, and miscellaneous notes

-   After installing the app, please perform the following configuration steps:

      

    -   Create a new asset and save the required settings 'OAuth 2 Authentication Token' and
        'Bitglass API URL' in the 'Asset Settings' tab
    -   In the 'Ingest Settings' tab, select the source (i.e 'events') and enable polling interval
        or another scheduling option, press SAVE
    -   Do 'Asset Settings / TEST CONNECTIVITY' and make sure it passes

-   The Phantom logs are available in /var/log/phantom or ${phantom_home}/var/log/phantom (for a
    non-root installation)

-   The last ingested data with the time and error code (if failed) is available in the app state
    directory /opt/phantom/local_data/app_states/8119e222-818e-42f5-a210-1c7c9d337e81 in
    lastlog-\*.json files

-   Optionally, install the bitglass_dlp_response.tgz playbook sample before creating your playbook
    from scratch

## The actions available with the app roughly fall into 3 groups

<div style="margin-left: 2em">

Phantom standard and Bitglass log event retrieval

-   'test connectivity': Phantom requirement to test the asset settings (API url, authentication
    token, etc.)
-   'on poll': Phantom requirement for automatic data ingestion. Only the 'DLP Pattern for Access'
    and 'DLP Pattern for CloudAudit' matches from the log types 'Access' and 'CloudAudit'
    correspondingly get ingested into Phantom
-   'filter by dlp pattern': Additionally to filtering done according to the asset params 'DLP
    Pattern for Access' and 'DLP Pattern for CloudAudit' (as part of the ingestion), filter the
    ingested Bitglass log events further down as defined by the 'bg_match_expression' action param

User manipulation in response to log events from either Bitglass or other vendors

-   'add user to group': Add the user from the offending log event to a Bitglass group. For Bitglass
    log event source, the user is determined according to the asset params 'DLP Pattern for Access',
    'DLP Pattern for CloudAudit' and the 'bg_match_expression' param of the 'filter by dlp pattern'
    action by chaining this action after 'filter by dlp pattern'
-   'remove user from group': Same but in reverse
-   'deactivate user': A more drastic action in comparison to 'add user to group' above
-   'reactivate user': Same but in reverse

Other available actions covering the rest of the methods in Bitglass REST API, please refer to the
online documentation for reference

-   'create update user'
-   'create update group'
-   'delete group'

</div>

## The following describes creating a simple playbook from scratch for the 'User manipulation' use case described above. The resulting playbook should be similar to the sample bitglass_dlp_response.tgz playbook included with the app package

1.  Go to the 'Playbooks' page and click '+ PLAYBOOK'
2.  Drag the arrow on the 'START' block and click 'Action' in the menu on the left
3.  Choose 'Bitglass', the available actions will be listed
4.  Choose 'filter by dlp pattern'. This action will narrow down the available data (in the form of
    Phantom artifacts already available and the ones to be ingested into the future)
5.  Choose the asset configured earlier. Please note, that the artifacts available on the system
    have been already pre-filtered according to the 'DLP Pattern for Access' and 'DLP Pattern for
    CloudAudit' asset settings
6.  Override the 'bg_match_expression' and 'bg_log_event' params if necessary (keeping the defaults
    values of Malware.\* and artifact:\*.id correspondingly should be good for a start)
7.  Click 'SAVE'. That concludes defining the first action
8.  Pull at the output pin of the first action and click 'Action' to define the next action
9.  Choose 'Bitglass', the available actions will be listed
10. Choose 'add user to risk group'. This action will extract the user name from the artifact data
    corresponding to the log event and call Bitglass REST API to add the offending user to the group
    of risky users
11. Choose the same asset configured earlier
12. Override the 'bg_group_name' param if necessary. This group must have been created previously so
    that it exists
13. For the 'bg_user_name', this value has been extracted by the previous action and is available to
    pick as 'data.\*.userName', use it
14. Click 'SAVE'. That concludes defining the second action
15. Connect the output pin of the second action to the 'END' block
16. Click 'PLAYBOOK SETTINGS' and set 'Operates on' to 'events' and check 'Active'
17. Enter the desired playbook name in the upper left corner
18. Click the 'SAVE' button
19. Enter the description if prompted and click the 'SAVE' button
20. From now on, the playbook will be run automatically whenever new data conforming to the filter
    parameters defined above arrives
21. IMPORTANT! If using the Playbook Debugger or invoking the playbook manually, be sure to change
    the default value of the 'Scope' setting from the default 'new' to 'all'. Skipping this step
    will result in a Phantom error as the input data set will be empty in such a case

## The following table summarizes all the params available

| Param name                   | Found in asset / action | Type             | Value example                                          |
|------------------------------|-------------------------|------------------|--------------------------------------------------------|
| 'DLP Pattern for Access'     | asset                   | regex            | Malware.\*\|PCI.\*                                     |
| 'DLP Pattern for CloudAudit' | asset                   | regex            | ^PCI.\*                                                |
| 'bg_match_expression'        | 'filter by dlp pattern' | regex            | Malware.\*                                             |
| 'bg_log_event'               | 'filter by dlp pattern' | Phantom wildcard | artifact:\*.id                                         |
| 'bg_group_name'              | 'add user to group'     | string           | RiskyUsers                                             |
| 'bg_user_name'               | 'add user to group'     | Phantom wildcard | filter_by_dlp_pattern_1:action_result.data.\*.userName |

All filtering params of the asset and actions described above are Python regular expressions. For
example, Malware.\*\|PCI.\* matches any string containing EITHER the substring of 'Malware' followed
by any number of chars including zero OR, likewise, with the 'PCI' char sequence. Please refer to
the Python regex documentation
