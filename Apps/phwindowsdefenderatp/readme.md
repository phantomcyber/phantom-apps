[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2019-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Defender ATP Instance Minimum Version Compatibility

-   With this major version 2.0.0 of the Windows Defender ATP app on Phantom, we declare support for
    (on and above) the cloud 'November-December 2019' GA release for the ATP instances. This app has
    been tested and certified on the mentioned GA release of the Defender ATP and its APIs.

## Playbook Backward Compatibility

-   The existing action parameters have been modified in the actions given below. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting \| modifying
    \| deleting the corresponding action blocks, or by providing appropriate values to these action
    parameters to ensure the correct functioning of the playbooks created on the earlier versions of
    the app.

      

    -   List Devices - The 'IP' option has been removed from the value list of the \[input_type\]
        action parameter in the app version 3.0.0 because there is no specific API currently
        available to support the filtering of devices based on the IP in the Defender ATP.
    -   List Devices - The new \[query\] parameter has been added to support the additional OData V4
        filters.

## Pagination Not Supported

-   Based on the base URL link ( [Microsoft Defender ATP API
    Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-list)
    ), the pagination is not supported by the Defender ATP APIs. Hence, this app does not implement
    the pagination for the below-mentioned actions.

      

    -   List Devices
    -   List Alerts
    -   List Sessions
    -   List Indicators
    -   Get Installed Software
    -   Get Discovered Vulnerabilities
    -   Get File Devices
    -   Get User Devices
    -   Get Domain Devices
    -   Get Missing KBs
    -   Run Query

## Explanation of Asset Configuration Parameters

-   Tenant ID - It is the Directory ID of the Microsoft Azure Active Directory on the Microsoft
    Azure portal.
-   Client ID - It is the Application ID of an application configured in the Microsoft Azure Active
    Directory.
-   Client Secret - It is the secret string used by the application to prove its identity when
    requesting a token. It can be generated for the configured application on the Microsoft Azure
    Active Directory.
-   Non Interactive Auth - It is used to determine the authentication method. If it is checked then
    non interactive auth will be used otherwise interactive auth will be used. Whenever this
    checkbox is toggled then the test connectivity action must be run again.

## Configure SIEM Integration on the Microsoft Defender Security Center

-   ### SIEM Integration Configuration Link

    -   [Configure SIEM
        Integration](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-siem-integration)

-   ### Prerequisites

    -   The user who activates the setting must have permission to create an app in the Azure Active
        Directory (AAD).
    -   During the initial activation, a pop-up screen is displayed for credentials to be entered.
        Make sure that you allow pop-ups for this site.

-   ### Steps

    1.  Login to [Microsoft Defender Security
        Center](https://securitycenter.microsoft.com/dashboard) .
    2.  In the navigation pane, select Settings > APIs (section) > SIEM.
    3.  Select 'Enable SIEM connector' (this activates the SIEM connector access details section
        with pre-populated values and an application is created under your Azure Active Directory
        (AAD) tenant).
    4.  In the 'Choose the SIEM you want to configure and download details to file' section, select
        the 'Generic API' option.
    5.  Copy the individual pre-populated values displayed on the screen or click the 'Save details
        to file' button to download a file that contains all these values (these details are
        required to run the test connectivity action).
    6.  After enabling the SIEM connector on the Microsoft Defender Security Center, the app
        'WindowsDefenderATPSiemConnector' will be created on the Microsoft Azure portal.

## Configure and set up permissions of the app created on the Microsoft Azure portal

1.  Navigate to <https://portal.azure.com> .
2.  Log in with the same user which was used to enable the SIEM integration on Microsoft Defender
    Security Center.
3.  Select the 'Azure Active Directory'.
4.  Select the 'App registrations' menu from the left-side panel.
5.  Select the 'WindowsDefenderATPSiemConnector' app.
6.  Select the 'API Permissions' menu from the left-side panel.
7.  Click on 'Add a permission'.
8.  Under the 'Select an API' section, select 'APIs my organization uses'.
9.  Search for 'WindowsDefenderATP' keyword in the search box and click on the displayed option for
    it.
10. Provide the following Delegated and Application permissions to the app.
    -   **Application Permissions**

          

        -   Alert.ReadWrite.All
        -   File.Read.All
        -   Machine.Isolate
        -   Machine.Offboard
        -   Machine.Read.All
        -   Machine.ReadWrite.All
        -   Machine.RestrictExecution
        -   Machine.Scan
        -   Machine.StopAndQuarantine
        -   User.Read.All
        -   Software.Read.All
        -   URL.Read.All
        -   Ip.Read.All
        -   Ti.ReadWrite.All
        -   AdvancedQuery.Read.All
        -   Vulnerability.Read.All
        -   Score.Read.All
        -   Machine.LiveResponse

    -   **Delegated Permissions**

          

        -   Alert.ReadWrite
        -   File.Read.All
        -   Machine.Isolate
        -   Machine.Offboard
        -   Machine.Read
        -   Machine.ReadWrite
        -   Machine.RestrictExecution
        -   Machine.Scan
        -   Machine.StopAndQuarantine
        -   User.Read.All
        -   Software.Read
        -   URL.Read.All
        -   Ip.Read.All
        -   Ti.ReadWrite
        -   AdvancedQuery.Read
        -   Vulnerability.Read
        -   Score.Read
        -   Machine.LiveResponse
11. 'Grant Admin Consent' for it.
12. Again click on 'Add a permission'.
13. Under the 'Select an API' section, select 'Microsoft APIs'.
14. Click on the 'Microsoft Graph' option.
15. Provide the following Delegated permission to the app.
    -   **Delegated Permission**

          

        -   offline_access

## Configure the Microsoft Defender ATP Phantom app's asset

When creating an asset for the app,

-   Check the checkbox if you want to use Non Interactive authentication mechanism otherwise
    Interactive auth mechanism will be used.

-   Provide the client ID of the app created during the previous step of SIEM Integration in the
    'Client ID' field.

-   Provide the client secret of the app created during the previous step of SIEM Integration in the
    'Client Secret' field. If the client secret is not generated during the SIEM step, follow the
    below steps to generate the new client secret.
    -   Navigate to <https://portal.azure.com> .
    -   Log in with the same user which was used to enable the SIEM integration on Microsoft
        Defender Security Center.
    -   Select the 'Azure Active Directory'.
    -   Select the 'App registrations' menu from the left-side panel.
    -   Select the 'WindowsDefenderATPSiemConnector' app.
    -   Click on the 'Certificates & secrets' menu on the left-side panel.
    -   Click on the 'New client secret' button to open a pop-up window.
    -   Provide the description, select an appropriate option for deciding the client secret
        expiration time, and click on the 'Add' button to open a pop-up window.
    -   Please save this client secret string displayed on the pop-up window to some secure place,
        as it cannot be retrieved after closing the pop-up window.
    -   Provide the newly generated client secret string in the 'Client Secret' field of the asset.

-   Provide the tenant ID of the app created during the previous step of SIEM Integration in the
    'Tenant ID' field. For getting the value of tenant ID, navigate to the 'Azure Active Directory'
    on the Microsoft Azure portal; click on the 'App registrations' menu from the left-side panel;
    click on the earlier created 'WindowsDefenderATPSiemConnector' app. The value displayed in the
    'Directory (tenant) ID' is the required tenant ID.

-   Save the asset with the above values.

-   After saving the asset, a new uneditable field will appear in the 'Asset Settings' tab of the
    configured asset for the ATP app on Phantom. Copy the URL mentioned in the 'POST incoming for
    Windows Defender ATP to this location' field. Add a suffix '/result' to the URL copied in the
    previous step. The resulting URL looks like the one mentioned below.

      

                    https://<phantom_host>/rest/handler/windowsdefenderatp_<appid>/<asset_name>/result
                  

-   Add the URL created in the earlier step into the 'Redirect URIs' section of the 'Authentication'
    menu for the registered app 'WindowsDefenderATPSiemConnector' on the Microsoft Azure portal. For
    the 'Redirect URIs' section, follow the below steps.

      

    1.  Below steps are required only in case of Interactive auth (i.e. If checkbox is unchecked)
    2.  Navigate to the 'Azure Active Directory' on the Microsoft Azure portal.
    3.  Click on the 'App registrations' menu from the left-side panel.
    4.  Click on the earlier created 'WindowsDefenderATPSiemConnector' app.
    5.  Navigate to the 'Authentication' menu of the app on the left-side panel.
    6.  Click on the 'Add a platform' button and select 'Web' from the displayed options.
    7.  Enter the URL created in the earlier section in the 'Redirect URIs' text-box.
    8.  This will display the 'Redirect URIs' under the 'Web' section displayed on the page.

## Interactive Method to run Test Connectivity

-   After setting up the asset and user, click the 'TEST CONNECTIVITY' button. A pop-up window will
    be displayed with appropriate test connectivity logs. It will also display a specific URL on
    that pop-up window.
-   Open this URL in a separate browser tab. This new tab will redirect to the Microsoft login page
    to complete the login process to grant the permissions to the app.
-   Log in using the same Microsoft account that was used to configure the SIEM connector workflow
    and the application on the Microsoft Azure Portal. After logging in, review the requested
    permissions listed and click on the 'Accept' button.
-   This will display a successful message of 'Code received. Please close this window, the action
    will continue to get new token.' on the browser tab.
-   Finally, close the browser tab and come back to the 'Test Connectivity' browser tab. The pop-up
    window should display a 'Test Connectivity Passed' message.

## Non Interactive Method to run Test Connectivity

-   Here make sure that the 'Non Interactive Auth' checkbox is checked in asset configuration.
-   Click on the 'TEST CONNECTIVITY' button, it should run the test connectivity action without any
    user interaction.

## Explanation of Test Connectivity Workflow for Interactive auth and Non Interactive auth

-   This app uses (version 1.0) OAUTH 2.0 authorization code workflow APIs for generating the
    \[access_token\] and \[refresh_token\] pairs if the authentication method is interactive else
    \[access_token\] if authentication method is non interactive is used for all the API calls to
    the Defender ATP instance.

-   Interactive authentication mechanism is a user-context based workflow and the permissions of the
    user also matter along with the API permissions set to define the scope and permissions of the
    generated tokens. For more information visit the link mentioned here for the [OAUTH 2.0 AUTH
    CODE](https://docs.microsoft.com/en-gb/azure/active-directory/azuread-dev/v1-protocols-oauth-code)
    .

-   Non Interactive authentication mechanism is a user-context based workflow and the permissions of
    the user also matter along with the API permissions set to define the scope and permissions of
    the generated token. For more information visit the link mentioned here for the [OAUTH 2.0
    CLIENT
    CREDENTIALS](https://docs.microsoft.com/en-gb/azure/active-directory/azuread-dev/v1-oauth2-client-creds-grant-flow)
    .

-   The step-by-step process for the entire authentication mechanism is explained below.

      

    -   The first step is to get an application created in a specific tenant on the Microsoft Azure
        Active Directory. Generate the \[client_secret\] for the configured application. The
        detailed steps have been mentioned in the earlier section.

    -   Configure the Windows Defender ATP app's asset with appropriate values for \[tenant_id\],
        \[client_id\], and \[client_secret\] configuration parameters.

    -   Run the test connectivity action for Interactive method.

          

        -   Internally, the connectivity creates a URL for hitting the /authorize endpoint for the
            generation of the authorization code and displays it on the connectivity pop-up window.
            The user is requested to hit this URL in a browser new tab and complete the
            authorization request successfully resulting in the generation of an authorization code.
        -   The authorization code generated in the above step is used by the connectivity to make
            the next API call to generate the \[access_token\] and \[refresh_token\] pair. The
            generated authorization code, \[access_token\], and \[refresh_token\] are stored in the
            state file of the app on the Phantom server.
        -   The authorization code can be used only once to generate the pair of \[access_token\]
            and \[refresh_token\]. If the \[access_token\] expires, then the \[refresh_token\] is
            used internally automatically by the application to re-generate the \[access_token\] by
            making the corresponding API call. This entire autonomous workflow will seamlessly work
            until the \[refresh_token\] does not get expired. Once the \[refresh_token\] expires,
            the user will have to run the test connectivity action once again to generate the
            authorization code followed by the generation of an entirely fresh pair of
            \[access_token\] and \[refresh_token\]. The default expiration time for the
            \[access_token\] is 1 hour and that of the \[refresh_token\] is 90 days. For more
            details visit [AD Configurable Token
            Lifetimes](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes)
        -   The successful run of the Test Connectivity ensures that a valid pair of
            \[access_token\] and \[refresh_token\] has been generated and stored in the app's state
            file. These tokens will be used in all the actions' execution flow to authorize their
            API calls to the Defender ATP instance.

    -   Run the test connectivity action for Non Interactive method.

          

        -   Internally, the application authenticates to Azure AD token issuance endpoint and
            requests an \[access_token\] then it will generate the \[access_token\].
        -   The \[access_token\] generated in the above step is used by the test connectivity to
            make the next API call to verify the \[access_token\]. The generated \[access_token\] is
            stored in the state file of the app on the Phantom server.
        -   If the \[access_token\] expires, then application will automatically re-generate the
            \[access_token\] by making the corresponding API call.
        -   The successful run of the Test Connectivity ensures that a valid \[access_token\] has
            been generated and stored in the app's state file. This token will be used in all the
            actions execution flow to authorize their API calls to the Defender ATP instance.

## State file permissions

Please check the permissions for the state file as mentioned below.

#### State file path

-   For Non-NRI instance: /opt/phantom/local_data/app_states/\<appid>/\<asset_id>\_state.json
-   For NRI instance:
    /\<PHANTOM_HOME_DIRECTORY>/local_data/app_states/\<appid>/\<asset_id>\_state.json

#### State file permissions

-   File rights: rw-rw-r-- (664) (The phantom user should have read and write access for the state
    file)
-   File owner: Appropriate phantom user

## Notes

-   \<appid> - The app ID will be available in the Redirect URI which gets populated in the field
    'POST incoming for Windows Defender ATP to this location' when the Defender ATP Phantom app
    asset is configured e.g.
    https://\<phantom_host>/rest/handler/windowsdefenderatp\_\<appid>/\<asset_name>/result
-   \<asset_id> - The asset ID will be available on the created asset's Phantom web URL e.g.
    https://\<phantom_host>/apps/\<app_number>/asset/\<asset_id>/

## get file (live response) action workflow

-   There can be four different cases based on the provided parameters:

      

    -   Case 1:

          

        -   Only event_id is provided - In this case, the rest of the parameters will be ignored and
            the action will try to get the file based on the provided **event_id** . The action can
            get the file only if the status received from the **get_status** action for the given
            event_id is **Succeeded** (How the event_id is generated is mentioned in the next Case).

    -   Case 2:

          

        -   No event_id is provided and other parameters are provided - In this case, **device_id,
            file_path and comment** all the three parameters are required. If the timeout is not
            provided, the default timeout value is considered as 300 seconds. In the given timeout,
            the action will try to get the file and if action takes longer time than the given
            timeout, it will provide an **event_id** and **file_status** . The event_id can be used
            in the **get_status** action to receive the status and once the status is **Succeeded**
            , the same event_id can be used in this action to get the file into the vault (Case 1).

    -   Case 3:

          

        -   Both event_id and other parameters are provided - In this case, the event_id will get
            the higher priority and the action will try to get the file based on the **event_id**
            (Case 1). If the action fails to get the file using event_id, it will look into other
            parameters and it will work in the same way as mentioned in Case 2.

    -   Case 4:

          

        -   No parameters are provided - In this case the action will fail, because either
            **event_id** or **Other parameters (file_path, device_id, and comment)** are required in
            order to get the file.

## run script (live response) action workflow

-   There can be four different cases based on the provided parameters:

      

    -   Case 1:

          

        -   Only event_id is provided - In this case, the rest of the parameters will be ignored and
            the action will try to get the script output based on the provided **event_id** . The
            action can get the script output if the status received from the **get_status** action
            for the given event_id is **Succeeded** (How the event_id is generated is mentioned in
            the next Case.)

    -   Case 2:

          

        -   No event_id provided and other parameters are provided - In this case, **device_id,
            script_name and comment** all the three parameters are required. If the timeout is not
            provided, the default timeout value is considered as 300 seconds. In the given timeout,
            the action will try to execute the script and provide the output and if the action takes
            longer time than the given timeout, it will provide an **event_id** and
            **script_status** . The event_id can be used in the **get_status** action to receive the
            status and once the status is **Succeeded** , the same event_id can be used in this
            action to get the script output (Case 1).

    -   Case 3:

          

        -   Both event_id and other parameters are provided - In this case the event_id will get the
            higher priority and the action will try to get the script output based on the
            **event_id** (Case 1). If the action fails to get the script output using event_id, it
            will look into other parameters and it will work in the same way as mentioned in Case 2.

    -   Case 4:

          

        -   No parameters are provided - In this case the action will fail, because either
            **event_id** or **Other parameters (script_name, device_id, and comment)** are required
            in order to get the script output.

### The app is configured and ready to be used now.
