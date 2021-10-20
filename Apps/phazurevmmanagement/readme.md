[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2019-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
-   For an admin user, you can run the test connectivity directly.
-   For a non-admin user, you need to get the admin consent first. This can be done by granting
    admin consent in the Azure portal.

## Authentication

This app requires creating a Microsoft Graph Application. To do so, navigate to
[https://apps.dev.microsoft.com](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
in a browser and log in with a Microsoft account, then select **New registration** .  
  
On the next page, give your application a name and select **Register** .  
  
Once the app is created, three steps need to be taken on the next page:  
  
Under **Certificates and Secrets** , select **New client secret** . Note this key somewhere secure,
as it cannot be retrieved after closing the window.  
  
**For Interactive OAuth**

-   Under **Authentication** select **Add a platform** . In the **Add a platform** window, select
    **Web** . The **Redirect URLs** should be filled right here. It should look something like:

      

    https://\<phantom_host>/rest/handler/microsoftazurecompute_39c7128b-666b-4a16-9d44-afab6a9b825d/\<asset_name>/result

-   Under **API permissions** the following **Delegated Permissions** need to be added:
    -   Group.ReadWrite.All
    -   offline_access
    -   User.ReadWrite.All

**For Non-Interactive OAuth**

-   Under **API permissions** the following **Application Permissions** need to be added:
    -   Group.ReadWrite.All
    -   User.ReadWrite.All
-   On the Azure portal, go to subscriptions and select your subscription.
-   Go to Access control(IAM) section and click on add role assignment.
-   Select **Contributer** in the **Role** field from the drop down and select your application in
    the **Select** field.

After making these changes, click **Save** at the bottom of the screen.

## Configure the Microsoft Azure Compute Phantom app Asset

When creating an asset for the **Microsoft Azure Compute** app, place **Subscription Id** of the app
in the **Subscription ID** field, place **Application Id** of the app created during the previous
step in the **Client ID** field, and place the password generated during the app creation process in
the **Client Secret** field. Then, after filling out the **Tenant ID** field, click **SAVE** .  
  
After saving, a new field will appear in the **Asset Settings** tab. Take the URL found in the
**POST incoming for Microsoft Azure Compute to this location** field and place it in the **Redirect
URLs** field mentioned in a previous step. To this URL, add **/result** . After doing so the URL
should look something like:  
  

https://\<phantom_host>/rest/handler/microsoftazurecompute_39c7128b-666b-4a16-9d44-afab6a9b825d/\<asset_name>/result

  
Once again, click save at the bottom of the screen.

## Method to run test connectivity

After setting up the asset and user, click the **TEST CONNECTIVITY** button. A window should pop up
and display a URL. Navigate to this URL in a separate browser tab. This new tab will redirect to a
Microsoft login page. Log in to a Microsoft account. After logging in, review the requested
permissions listed, then click **Accept** . Finally, close that tab. The test connectivity window
should show a success.  
If the admin consent is required then, the display url will occur twice. The first one will be for
admin access.  
  
The app should now be ready to be used.

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

## Playbook Backward Compatibility

-   A new action has been added. Hence, it is requested to the end-user to please update their
    existing playbooks by inserting the corresponding action blocks for this action on the earlier
    versions of the app.

      

    -   Get Results

-   The parameters have been modified in the below existing action. Hence, it is requested to the
    end-user to please update their existing playbooks by re-inserting \| modifying \| deleting the
    corresponding action blocks on the earlier versions of the app.

      

    -   Run Command - Below parameter have been modified

          

        -   The parameter 'body' has been removed
        -   New parameters 'command_id', 'script', 'script_parameters' have been added
