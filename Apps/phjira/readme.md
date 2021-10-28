[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## JIRA

This app uses the python JIRA module, which is licensed under the BSD License (BSD), Copyright (c)
2001-2021. Python Software Foundation

## oauthlib

This app uses the python oauthlib module, which is licensed under the OSI Approved, BSD License
(BSD), Copyright (c) 2001-2021. Python Software Foundation

## pbr

This app uses the python pbr module, which is licensed under the Apache Software License, Copyright
(c) 2001-2021. Python Software Foundation

## PyJWT

This app uses the python PyJWT module, which is licensed under the MIT License (MIT), Copyright (c)
2001-2021. Python Software Foundation

## requests-oauthlib

This app uses the python requests-oauthlib module, which is licensed under the BSD License (ISC),
Copyright (c) 2001-2021. Python Software Foundation

## requests-toolbelt

This app uses the python requests-toolbelt module, which is licensed under the Apache Software
License (Apache 2.0), Copyright (c) 2001-2021. Python Software Foundation

## JIRA

JIRA is a highly configurable ticketing system, and the actions performed by these API calls are
highly dependent on the process defined in each Jira instance.

If your action fails, you may need to try an alternate method, or sequence, to perform the actions
desired for Jira to process them properly. One helpful debugging tool: simplify your action, instead
of filling out all the fields, attempt to make only one change at a time.

Unfortunately, the JIRA API in most cases returns a generic error message with no valuable
information to assist in debugging.

**Playbook Backward Compatibility**

-   The existing action parameters have been modified in the actions given below. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting the
    corresponding action blocks or by providing appropriate values to these action parameters to
    ensure the correct functioning of the playbooks created on the earlier versions of the app.

      

    -   Add Watcher - The new \[user_account_id\] parameter has been added for the Jira cloud to add
        a watcher into a provided issue.
    -   Remove Watcher - The new \[user_account_id\] parameter has been added for the Jira cloud to
        remove a watcher from a provided issue.
    -   Create Ticket - The new \[assignee_account_id\] parameter has been added for the Jira cloud
        to add the assignee while creating a Jira ticket.
    -   Lookup Users - Added a new action. This action will get a list of User resources that match
        the specified search string.
    -   Add Comment - The new \[internal\] parameter has been added for comment that whether it
        should be internal only or not in Jira Service Desk. This parameter is an optional Boolean
        parameter. If the value is not provided for it, then it will be considered as a 'False'
        value.
    -   Get Attachments - Added a new action. The action will store specific attachments from a
        given Jira ticket inside the vault.

**Authentication steps for JIRA Cloud**

-   Create an API token

      

    -   Log in to [Click here.](https://id.atlassian.com/manage/api-tokens)

    -   Click **Create an API token.**

    -   From the dialog that appears, enter a unique and concise **Label** for your token and click
        **Create** .

    -   Click **Copy to clipboard** , then paste the token to your script, or elsewhere to save.

          
          
        Notes:

    -   For security reasons it isn't possible to view the token after closing the creation dialog;
        if necessary, create a new token.

    -   You should store the token securely, just as for any password.

      

-   Use an API token

      

    -   A primary use case for API tokens is to allow scripts to access REST APIs for Atlassian
        Cloud applications using HTTP basic authentication.
    -   HTTP basic authentication would require a username and API token to access REST APIs for
        Atlassian Cloud applications.

      

**The functioning of On Poll**

-   **NOTE (Consider below points due to a minute's granularity (instead of a second or lesser) for
    querying tickets in the JIRA)**

      

    -   It is highly recommended for configuring a significantly large value (larger than the number
        of existing tickets on the user's instance) in the asset configuration parameter to bring
        the ingested tickets in the Phantom in sync entirely with the JIRA instance in the first run
    -   It is highly recommended for configuring a significantly large value (larger than the
        possible number of tickets that can be updated in 1 minute or any value larger than the
        average number of tickets getting created every unit of time (based on the frequency of
        scheduled or interval polling)) in the asset configuration parameter to avoid the duplicate
        tickets ingestion

      

-   The On Poll action works in 2 steps. In the first step, all the tickets (issues) in a defined
    time duration will be fetched. In the second step, all the components (e.g. fields, comments,
    and attachments) of the tickets (retrieved in the first step) will be fetched. A container will
    be created for each ticket and for each ticket all the components will be created as the
    respective artifacts.

-   The tickets will be fetched in the oldest first order based on the **updated** time in the On
    Poll action

-   The updated timestamps of the components have been appended to the end of the artifact name to
    maintain the uniqueness of a particular component

-   The timezone parameter in the asset configurations defines the timezone used to query the
    tickets from the JIRA instance. If you do not find your exact timezone in the available list in
    the dropdown, please select a timezone having the same time offset from the GMT timezone as
    yours. Below are the details of setting the timezone parameter for on-prem and cloud JIRA
    instances.

      

    1.  On-premise JIRA
        -   The timezone parameter here is the profile timezone of the JIRA instance
        -   For checking the profile timezone, navigate to the JIRA instance; navigate to the
            profile settings; the value of the **Time Zone** parameter is the timezone that has to
            be provided in the Phantom asset configuration
    2.  Cloud JIRA
        -   The timezone parameter here is the system settings timezone of the JIRA instance
        -   For checking the system settings timezone, navigate to the JIRA instance; navigate to
            the option **Jira Settings --> System** in the settings page; the value of the **Default
            user time zone** parameter is the timezone that has to be provided in the Phantom asset
            configuration

-   Users can provide the JSON formatted list of names of the custom fields (to be considered for
    the ingestion) in the asset configuration parameter **custom_fields** e.g. \["Test \\"CF\\" 1",
    "test_cf_2"\]. It's a valid JSON formatted list of strings, so the user should use escape
    sequences whenever needed. Please find the below points for getting exact names for the custom
    fields.

      

    1.  On-premise JIRA
        -   Navigate to the JIRA instance; navigate to the issues settings; navigate to the **Custom
            fields** section under the **Fields** section; in the **Name** column, search for the
            custom field that the user wants to be added in the asset configuration parameter
            **custom_fields**
    2.  Cloud JIRA
        -   The timezone parameter here is the system settings timezone of the JIRA instance
        -   For checking the system settings timezone, navigate to the JIRA instance; navigate to
            the option **Jira Settings --> System** in the settings page; the value of the **Default
            user time zone** parameter is the timezone that has to be provided in the Phantom asset
            configuration

-   If there is any error while fetching the custom fields metadata due to project configuration or
    lack of permissions, then, the custom fields will be ignored and the ingestion based on the
    system fields of the tickets (issues) will be executed successfully

      
      

-   Two approaches for fetching offenses

      
      

    -   Manual polling

          

        -   Fetch the tickets

              

            -   The tickets will be fetched from the project mentioned in the **Project key to
                ingest tickets (issues) from** app configuration parameter
            -   The tickets will be fetched in the oldest first order based on the **updated** time
                and governed by the **container_count** parameter in the On Poll action

        -   Fetch the components

              

            -   Fetch all created or updated components (e.g. fields, comments, and attachments) for
                each ticket (retrieved in the previous step)

        -   Create containers for the tickets and artifacts for the fields, comments, and the
            attachments

        -   It is recommended to provide a sufficiently large value in the **container_count**
            parameter for polling because manual polling does not remember the timestamp of last
            fetched ticket and it starts polling from the beginning every time. Hence, if the user
            runs the manual polling with e.g. 10 as the container count (the tickets are ingested
            successfully), then, the user again runs the manual polling with the same value in the
            container count; the app will fetch the same 10 tickets from the beginning and it will
            display the message as 'duplicate artifacts found' because the same artifacts were
            already ingested in the earlier manual polling run.

          

    -   Scheduled Polling

          

        -   Follows the same steps as manual polling with the below-mentioned points getting
            considered
        -   The application will fetch the number of tickets governed by the **Maximum tickets
            (issues) for scheduled polling** parameter (default: 100) in the On Poll action, whose
            **updated** time is greater than or equal to one minute less than the time stored in the
            **last_time** variable in the state file. The reason for reducing one minute from the
            **last_time** is to ensure that no tickets created or updated on the same minute are not
            getting skipped due to the granularity of Jira being 1 minute for the time-based
            filtering of the tickets.
        -   If the **last_time** variable is not present in the state file i.e. the On Poll is
            executing for the first time, the application will fetch the last **M** tickets ( **M:**
            Value provided in the **Maximum tickets (issues) to poll first time** app configuration
            parameter (default: 100)) and then, from the next consecutive runs, it will fetch **N**
            tickets ( **N:** Value provided in the **Maximum tickets (issues) for scheduled
            polling** app configuration parameter (default: 100)).
        -   The last_time will be updated by the **updated** time of the last ticket which was
            ingested

      

**Some example caveats**

-   Attempting to set both Status and Resolution fails because the process set by the user doesn't
    require a resolution to be set by the user, such as if there is only one resolution for a
    particular status.
-   Attempting to add a comment while setting Status may return success, however, the comment isn't
    posted. In this case, when the status change is made via the Jira UI, no dialogue appears to
    offer any additional input, therefore the API expects the same.
-   The "simple" format for the update ticket may not work to add a comment, while the "update"
    method does.
-   Test connectivity may fail due to invalid credentials, such as accidentally using the user's
    email address as the authentication login instead of the user's login name.
-   While adding an attachment to the Jira ticket using 'Update ticket' action, if the filename
    contains Unicode characters, the action is getting failed with the 500 Internal Server Error
    because of the Jira SDK issue. Due to this, action behaves differently with the various Phantom
    platforms. As a result, we have deployed the below-mentioned workflow which will ensure a
    minimal change in the filename and minimal/no data loss.
    1.  For the first time we try to add an attachment to the Jira ticket with the same name as the
        filename, if it may get successful, then it will add an attachment with the same name
    2.  But if it fails, then, we will check whether there are Unicode characters or not in the
        filename, if it has, there are highly possible chances that Jira SDK might get throws an
        exception due to these Unicode characters.
    3.  And in such a case, we removed those non-ASCII Unicode characters from the filename and add
        prefix FILENAME_ASCII to the filename. And, we again try to add an attachment with a newly
        created name to the Jira ticket.
    4.  If it passes, then it's okay and if it doesn't, then, there might be some other genuine
        issue rather than the SDK issue and we fail the action by rethrowing the same error.
