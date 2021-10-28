[comment]: # "File: readme.md"
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Asset configuration

1). Find **Group IB Threat Intelligence and Attribution** app, click **CONFIGURE NEW ASSET** button,
in **Asset Settings** tab enter your credentials and configure necessary collections.

-   **Group-IB API URL** is https://tap.group-ib.com/api/v2/
-   **Username** is the login for the Group-IB TIA portal.
-   **Verify server certificate** - Whether to allow connections without verifying SSL certificates
    validity.
-   **API key** can be manually generated in the portal:  
    The old version of the portal: log in to the TIA -> click on your name in the right upper corner
    -> choose the **Profile** option -> click on the **Go to my setting** button under your name ->
    under the **Change password** button you will see **API KEY generator** . **Do not forget to
    save the API key** .  
    The new version of the portal: log in to the TIA -> click on your name in the right upper corner
    -> choose the **Profile** option -> click on **Security and Access** tab -> click on **Personal
    token** tab -> click on **Generate new token** button -> enter your password, copy token and
    click **Save** button.
-   Every collection has a poll starting date and enable checkbox.

2). If you are using a proxy to connect to the Group IB TIA server, you can specify the appropriate
settings. You need to expand the **Advanced** section on the bottom, find the **Environment**
section and click **+ Variable** . **NAME** must be HTTPS_PROXY, **VALUE** is your proxy server.

3). In the **Ingest settings** tab choose the polling interval you need.

## SDK and SDK Licensing details for the app

#### pytia

This app uses the pytia module, which is licensed under the MIT License (MIT), Copyright (c) 2021
Group-IB.
