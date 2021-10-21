[comment]: # ""
[comment]: # "File: readme.md"
[comment]: # "Copyright (c) 2021 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
### SDK and SDK Licensing details for the app

##### PyJWT

This app uses the PyJWT module, which is licensed under the MIT License (MIT), Copyright (c) Jose
Padilla.

## Setting up Trend Micro Apex One

This app requires an API Key to access the Trend Micro Apex One environment. Please refer to the
documentation ["Obtain an Application ID and API
Key"](https://automation.trendmicro.com/apex-central/Guides/Relocate-a-Security-_001) on Apex
Central to learn how to create and access such a key.  

## Phantom Trend Micro Apex One Asset

When creating an asset for **Trend Micro Apex One** app, place the Apex Server URL (eg.
https://myapexenv.manage.trendmicro.com) into the Apex Server URL field. Next, enter the Application
ID and API Key pair into their respective input fields. After saving the asset, run the **Test
Connectivity** action under *Asset Settings* to ensure the asset has been configured correctly.
