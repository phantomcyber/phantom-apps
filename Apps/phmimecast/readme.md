[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2019-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Playbook Backward Compatibility

-   The newer version of the app updates the action names for blacklist and whitelist actions.
    Hence, it is requested to the end-user to please update their existing playbooks by modifying
    the corresponding action blocks to ensure the correct functioning of the playbooks created on
    the earlier versions of the app. The following actions names have been updated:

      

    -   \[blacklist url\] to \[blocklist url\]
    -   \[unblacklist url\] to \[unblocklist url\]
    -   \[whitelist url\] to \[allowlist url\]
    -   \[unwhitelist url\] to \[unallowlist url\]
    -   \[blacklist sender\] to \[blocklist sender\]
    -   \[whitelist sender\] to \[allowlist sender\]

-   Added new paremeter in the action given below. Hence, it is requested to the end-user to please
    update their existing playbooks by re-inserting \| modifying \| deleting the corresponding
    action blocks or by providing appropriate values to these action parameters to ensure the
    correct functioning of the playbooks created on the earlier versions of the app.
    -   list urls - 'max_results' parameter has been added

## Authorization

Upon installing Mimecast and configuring your asset, you will not have an accessKey or secretKey
(together known as a binding) that is required by Mimecast upon each call to its API.  
When you run the first Mimecast action or test connectivity on the asset, your accessKey and
secretKey will be generated and saved in your instance.  
Every action run will be using the same accessKey and secretKey that was saved to avoid generating
new keys on every request.  
It is important to note that your accessKey and secretKey binding may expire after the period of
time defined in the Authentication Cache TTL setting in the service user's effective Authentication
Profile (accessible through the Mimecast Administration Console under
Services>Applications>Authentication Profiles). It is recommended to set this to "Never Expires" so
you do not have to deal with expired authentication.

## Points to remember while connecting to Mimecast

-   **IP Range Restrictions:** Be sure to enable your Mimecast to accept communication with the IP
    address of your Phantom server(s).
-   **Two Factor Authentication:** Mimecast supports optional two-factor authentication. Two-factor
    authentication should be disabled for the account that is used to handle API communication with
    Phantom.

**Note:** The 'unblocklist url' and 'unallowlist url' actions use the same API endpoint and action
parameter to remove the URL from the blocklist and allowlist. Hence, removing the URL from the
allowlist will automatically remove the URL from the blocklist as well.
