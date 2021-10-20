[comment]: # " File: readme.md"
[comment]: # "     Copyright (c) 2021 Splunk Inc."
[comment]: # "     Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Authentication

This app supports two types of authentication:

-   Using the Personal Access Token
-   OAuth authentication

### Using the Personal Access Token

To use this method navigate to [developer
site](https://developer.webex.com/docs/api/getting-started) in a browser and log in with your
credentials. Copy the token and paste it into the **Personal Access Token** field in asset
configuration. Click save and run test connectivity.  
  

### OAuth authentication

To enable OAuth and to retrieve Client ID and Client Secret, we need to follow the steps which are
mentioned in the [developer document](https://developer.webex.com/docs/integrations) .

-   **Steps**
    1.  Log in to the [Cisco Webex app page](https://developer.webex.com/my-apps) .
    2.  Click "Create a New App" then "Create an Integration" to start the wizard.
    3.  You'll need to provide some basic information like your integration's name, description, and
        logo.
    4.  After successful registration, you'll be taken to a different screen containing your
        integration's newly created Client ID and Client Secret.
    5.  The Client Secret will only be shown once so please copy and keep it safe!
    6.  Give the required scope which defines the level of access that your integration requires.

  
While creating the asset for this authentication method, provide the Client ID and Client Secret
generated during previous steps in **client_id** and **client_secret** field of asset configuration
and click on Save.  
A new field called **POST incoming for Cisco Webex to this location** will appear in the **Asset
Settings** tab. Take the URL found in this field and place it in the **Redirect URI(s)** field of
your registered app. To this URL, add **/result** at the end. After doing so the URL should look
something like:

https://\<phantom_host>/rest/handler/ciscowebex_34624d1a-f0ae-47d6-a731-8499d5617cf7/\<asset_name>/result

## Method to run Test Connectivity

-   **Using the Personal Access Token**
    -   For the Personal Access Token method of authentication, you just need to click the TEST
        CONNECTIVITY button.
-   **OAuth authentication**
    -   After setting up the asset, click the 'TEST CONNECTIVITY' button. A pop-up window will be
        displayed with appropriate test connectivity logs. It will also display a specific URL on
        that pop-up window.
    -   Open this URL in a separate browser tab. This new tab will redirect to the Cisco Webex login
        page to complete the login process to grant the permissions to the app.
    -   Log in using the same Cisco Webex account that was used to configure the integration and the
        application on the Cisco Webex page.
    -   This will display a successful message of 'Code received. Please close this window, the
        action will continue to get new token.' on the browser tab.
    -   Finally, close the browser tab and come back to the 'Test Connectivity' browser tab. The
        pop-up window should display a 'Test Connectivity Passed' message.

## Explanation of Test Connectivity Workflow for Interactive auth

-   This app uses (version 1.0) OAUTH 2.0 authorization code workflow APIs for generating the
    \[access_token\] and \[refresh_token\] pairs if the authentication method is interactive else
    \[Personal access token\] if the authentication method is non-interactive is used for all the
    API calls to the Cisco Webex instance.

-   An interactive authentication mechanism is a user-context-based workflow and the permissions of
    the user also matter along with the API permissions set to define the scope and permissions of
    the generated tokens. For more information visit the link mentioned here for the [OAUTH 2.0 AUTH
    CODE](https://developer.webex.com/docs/integrations) .

-   The step-by-step process for the entire authentication mechanism is explained below.

      

    -   The first step is to get an application created on the Cisco Webex developer portal.
        Generate the \[client_secret\] for the configured application. The detailed steps have been
        mentioned in the earlier section.

    -   Run the test connectivity action for the Interactive method.

          

        -   Configure the Cisco Webex app's asset with appropriate values for \[client_id\] and
            \[client_secret\] configuration parameters.
        -   Internally, the connectivity creates a URL for hitting the /v1/authorize endpoint for
            the generation of the authorization code and displays it on the connectivity pop-up
            window. The user is requested to hit this URL in a browser new tab and complete the
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
            \[access_token\] and \[refresh_token\].
        -   The successful run of the Test Connectivity ensures that a valid pair of
            \[access_token\] and \[refresh_token\] has been generated and stored in the app's state
            file. These tokens will be used in all the actions' execution flow to authorize their
            API calls to the Cisco Webex instance.

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

### Notes:

-   All the asset configuration parameters are optional, but you need to provide the configuration
    parameters based on the authentication method you want to use. Otherwise, the actions will
    return an error.
-   The Personal Access Token is valid for only 12 hours.
-   If you have provided all the configuration parameters, the priority of the authentication method
    will be Personal Access Token

#### The app is configured and ready to be used now.

### LDAP Ports Requirements (Based on Standard Guidelines of [IANA ORG](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) )

-   Webex(service) TCP(transport protocol)
-   Webex(service) UDP(transport protocol)
