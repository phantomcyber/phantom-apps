[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2018-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Pagination

The pagination mechanism has been implemented for the investigative actions mentioned below.

-   list users
-   list user groups
-   list providers
-   list roles

The pagination mechanism has been explained below.

-   Limit Parameter: This input parameter is used to limit the total number of items (a valid
    positive integer) to be fetched in action results.

**Examples**  
Total items in the end system for reference in the below examples are 950 and internally, every page
fetched will have 200 result items. Based on the value of the limit and other parameters combined,
the required items from every page will be fetched and added to the action results output. The
'after' field (for navigating to next pages) used in API calls is handled internally by the
pagination mechanism.

-   **Example 1:** Limit = 50

      

    -   This will fetch the first 50 items

      

-   **Example 2:** Limit = 200

      

    -   This will fetch the first 200 items

      

-   **Example 3:** Limit = 240

      

    -   This will fetch all 200 items from the first page and 40 items from the second page. Hence,
        in total, it will fetch 240 items.

      

-   **Example 4:** Limit = 1000

      

    -   This will fetch all 950 items

      

-   **Example 6:** Limit = None

      

    Here the None is considered as empty parameter value

    -   This will fetch all 950 items
