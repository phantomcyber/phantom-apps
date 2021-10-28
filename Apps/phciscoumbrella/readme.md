[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
This app implements actions that manage a Cisco Umbrella domain list. Cisco Umbrella allows
third-party implementations like Phantom Enterprise to create and manage a list of domains (i.e.
add, delete) via what it calls 'custom integrations'. The Phantom Cisco Umbrella App requires such
an integration to be pre-configured on Cisco Umbrella. The steps to do this are outlined below:

-   Login to your Cisco dashboard and go to Policies > Policy Components > Integrations and click
    the "Add" button.
-   Set the name of the custom integration to be "Phantom Orchestration Feed"
-   Expand your new custom integration, check "Enable", copy the integration URL and then click
    Save.
-   The integration URL will be of the form:
    **https://s-platform.api.opendns.com/1.0/events?customerKey=bac2bfa7-d134-4b85-a5ed-b1ffec027a91**
    One of the parameters to this URL is the customer key (GUID format). This value will be required
    while configuring the Cisco Umbrella asset on Phantom. The Cisco Umbrella App on Phantom will
    use this customer key while adding, listing, and deleting domains.
-   Go to Policies > Policy Components > Security Settings, click on add, and check the relevant
    security settings. Scroll down and under Integrations select 'Phantom Orchestration Feed'.

At the end of the above steps Cisco Umbrella has been configured to:  

-   Create a 'custom integration' domain list with a *customerKey* for Phantom to use.
-   Use the domains belonging to the 'Phantom Orchestration Feed' to block DNS requests.

The next step is to configure a 'Cisco Umbrella' app's asset on Phantom and specify the 'Cisco
Customer key' and click 'Test Connectivity' to validate the configuration.

More information about 'custom integrations' can be found
[here](https://support.umbrella.com/hc/en-us/articles/231248748) .  
