[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## SDK and SDK Licensing details for the app

#### cachetools

This app uses the cachetools module, which is licensed under the MIT License (MIT), Copyright (c)
2014-2020 Thomas Kemmer.

#### google-api-python-client

This app uses the google-api-python-client module, which is licensed under the Apache Software
License (Apache 2.0), Copyright (c) Google LLC.

#### google-auth-httplib2

This app uses the google-auth-httplib2 module, which is licensed under the Apache Software License
(Apache 2.0), Copyright (c) Google Cloud Platform.

#### google-auth-oauthlib

This app uses the google-auth-oauthlib module, which is licensed under the Apache Software License
(Apache 2.0), Copyright (c) Google Cloud Platform.

#### google-auth

This app uses the google-auth module, which is licensed under the Apache Software License (Apache
2.0), Copyright (c) Google Cloud Platform.

#### httplib2

This app uses the httplib2 module, which is licensed under the MIT License (MIT), Copyright (c) Joe
Gregorio.

#### oauth2client

This app uses the oauth2client module, which is licensed under the Apache Software License (Apache
2.0), Copyright (c) Google Inc.

#### pyasn1-modules

This app uses the pyasn1-modules module, which is licensed under the BSD License (BSD-2-Clause),
Copyright (c) Ilya Etingof.

#### rsa

This app uses the rsa module, which is licensed under the Apache Software License (ASL 2), Copyright
(c) Sybren A. Stuvel.

#### uritemplate

This app uses the uritemplate module, which is licensed under the OSI Approved, Apache Software
License, BSD License (BSD 3-Clause License or Apache License, Version 2.0), Copyright (c) Ian
Stapleton Cordasco.

### Service Account

This app requires a pre-configured service account to operate. Please follow the procedure outlined
at [this link](https://support.google.com/a/answer/7378726?hl=en) to create a service account.  
The following APIs will need to be enabled:

-   AdminSDK
-   Google People API

At the end of the creation process, the admin console should ask you to save the config as a JSON
file. Copy the contents of the JSON file in the clipboard and paste it as the value of the "Contents
of Service Account JSON file" asset configuration parameter.

### Scopes

Once the service account has been created and APIs enabled, the next step is to configure scopes on
these APIs to allow the App to access them. Every action requires different scopes to operate, these
are listed in the action documentation.  
To enable scopes please complete the following steps:

-   Go to your G Suite domain's [Admin console](http://admin.google.com/) .
-   Select **Security** from the list of controls.
-   Select **API Controls** then select **Manage Domain Wide Delegation** under **Domain Wide
    Delegation**
-   In the **Client Name** field enter the service account's **Client ID** . You can find your
    service account's client ID in the [Service accounts credentials
    page](https://console.developers.google.com/apis/credentials) or the service account JSON file
    (key named **client_id** ).
-   Click **Add new** to add another API client or use an existing client if you have one. Hover
    over the newly created API client then select **Edit** to add the scopes that you wish to grant
    access to the App. For example, to enable all the scopes required by this app enter:
    -   'https://www.googleapis.com/auth/contacts'
    -   'https://www.googleapis.com/auth/contacts.other.readonly'
    -   'https://www.googleapis.com/auth/directory.readonly'
    -   'https://www.googleapis.com/auth/userinfo.profile'
-   Click **Authorize** .
