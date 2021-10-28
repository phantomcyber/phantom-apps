[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2019-2020 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
[comment]: # ""
## Registering the app on Azure portal

This app requires creating an Azure Application. To do so, navigate to <https://portal.azure.com/>
in a browser and log in with a Microsoft account, then follow the steps given below:  

1.  Go to Azure Active Directory → App Registrations and click on **+New Application Registration**
    .
2.  Give a name, select type as **“Web App/API”** and provide a sign-on URL.
3.  After saving the app, open Manifest, change the field **‘oauth2AllowImplicitFlow’** from *false*
    to *true* and Save Manifest.
4.  Go to App Settings → Properties, change **‘Multi-tenanted’** to &quotYES&quot.
5.  Go to App Settings → Required Permissions and click on **+Add** and select **&quotSkype for
    Business Online"**
6.  Add the following Delegated Permissions for your app
    -   Initiate conversations and join meetings
    -   Create Skype Meetings
    -   Read/write Skype user contacts and groups
7.  Go to App Settings → Keys → Password. In the description box, write *‘client_secret’* and
    provide a time duration.
8.  After saving, a key/password would be generated. **Please save it somewhere securely.** This
    would be used as your **client_secret** .

## Phantom Skype Asset

When creating an asset for **Skype for Business** app, place **Application Id/Client Id** of the app
in the **Client ID** field and place the key/password generated in the **Client Secret** field. User
can enter **Tenant** if he chooses, else &quotcommon" would be taken as default. Click **SAVE** .  
  
After saving, a new field will appear in the **Asset Settings** tab. Take the URL found in the
**POST incoming for Skype for Business to this location** field and place it in the **App Settings
-> Reply URLs** field of your registered app. To this URL, add **/result** . After doing so the URL
should look something like:  
  

    https://<phantom_host>/rest/handler/skypeforbusiness_42d0f6b6-c8bb-498c-ae35-a3fc21da8552/<asset_name>/result

  
Once again, click save at the bottom of the screen.

## Method to run test connectivity

  

1.  After setting up the asset and app, click the **TEST CONNECTIVITY** button.
2.  A window should pop up and display a URL.
3.  Navigate to this URL in a separate browser tab.
4.  This new tab will redirect to a Microsoft login page. Log in with a Microsoft account.
5.  After logging in, review the requested permissions listed, then click **Accept.**
6.  **Close that tab after authentication** .  
    -   NOTE:- Users may be required to repeat **Step-3** and **Step-4** multiple times.
7.  The test connectivity window should show a success.

  
The app should now be ready to use.
