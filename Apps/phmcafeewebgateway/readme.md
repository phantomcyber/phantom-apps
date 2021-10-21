[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2020 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
#### Setup

In order to set up an asset, you will need to first do the following on McAfee Web Gateway:

1.  [Enable the REST interface (Click HERE to go to McAfee
    documentation)](https://docs.mcafee.com/bundle/web-gateway-9.1.x-product-guide/page/GUID-F559827C-224E-49E8-AA5B-7D389EF39E4A.html)
2.  [Give permission to access (Click HERE to go to McAfee
    documentation)](https://docs.mcafee.com/bundle/web-gateway-9.1.x-product-guide/page/GUID-2D0D4E6C-E96A-4B52-8602-BF322B2AC914.html)

  
*Note: It is important to create a separate account for Splunk> Phantom to use since a user cannot
log in more than once at a time.*

#### Block/Unblock Actions

**block** actions (block url\|ip\|domain) *only* add items to a provided list. It is up to the
McAfee Web Gateway Administrators to manage the rules used for using that list in the correct rule.
**unblock** actions (unblock url\|ip\|domain) *only* remove items from a provided list. It is up to
the McAfee Web Gateway Administrators to manage the rules used for using that list in the correct
rule.
