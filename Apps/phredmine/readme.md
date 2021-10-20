[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Redmine

Redmine is an open-source ticketing system, and the actions performed by these API calls depend to
some extent on the configuration of the Redmine instance.

**The functioning of On Poll**

-   The On Poll action works in 2 steps. In the first step, all the tickets (issues) will be fetched
    in defined time duration. In the second step, all the components (e.g. fields) of the tickets
    (retrieved in the first step) will be fetched. A container will be created for each ticket and
    for each ticket all the components will be created as the respective artifacts.
-   The tickets will be fetched in the oldest first order based on the **updated** time in the On
    Poll action
-   The updated timestamps of the components have been appended to the end of the artifact name to
    maintain a particular component's uniqueness.
-   Users can provide the JSON formatted list of the custom fields' names (to be considered for the
    ingestion) in the asset configuration parameter `      custom_fields     ` .
