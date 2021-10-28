[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "    Copyright (c) Agari, 2021"
[comment]: # ""
[comment]: # "    This unpublished material is proprietary to Agari."
[comment]: # "    All rights reserved. The methods and"
[comment]: # "    techniques described herein are considered trade secrets"
[comment]: # "    and/or confidential. Reproduction or distribution, in whole"
[comment]: # "    or in part, is forbidden except by express written permission"
[comment]: # "    of Agari."
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
It is recommended to read the documentation for the app to understand the functioning of the actions
and the asset configuration or the action parameters associated with it. For further details, refer
to [<u>Agari Docs</u>](https://developers.agari.com/agari-platform/docs) .

## Steps to Generate Client ID and Client Secret

Follow these steps to obtain your Agari API credentials. Once you have your Agari account, log into
the Agari product and manually generate the 'client_id' and 'client_secret':

1.  Log into your Agari product.
2.  Click on your username in the upper right and select Settings.
3.  Click on the Generate API Secret link to generate an API 'client_id' and 'client_secret' (the
    link will read Regenerate API Secret if you have already generated an API client ID/secret
    previously).
4.  Copy both the 'client_id' and 'client_secret' that are generated and store them somewhere safe.

**Note:**

-   Keep your 'client_id' and 'client_secret' secure.
-   API clients can use your 'client_id' and 'client_secret' to gain access to the APIs as your
    user. Keep these values somewhere safe and secure. Never share them with anyone.
-   For security purposes, the 'client_secret' will not be displayed again, however you may generate
    a new one whenever needed by following the steps above.

## Explanation of the Asset Configuration Parameters

The asset configuration parameters affect \[test connectivity\] and some other actions of the
application. Below are the explanation and usage of all these parameters. The parameters related to
test connectivity action are Client ID and Client Secret.

-   **Client ID:** Client ID
-   **Client Secret:** Client Secret
-   **Policy Name:** This parameter allows the user to find by the policy name while fetching the
    policy events.
-   **Policy Action:** This parameter allows the user to find the policy action while fetching the
    policy events. The valid values for this parameter include: deliver, move, inbox, delete, none,
    all.  
    **Note:** When 'all' is selected, 'policy_action' will not be passed in the API call while
    fetching the policy events. The default behavior of the API would be considered.
-   **Exclude Alert Types:** This parameter allows the user to exclude the alert type while fetching
    the policy events. The valid values for this parameter include MessageAlert, SystemAlert,
    None.  
    **Note:** When 'None' is selected, 'exclude_alert_types' will not be passed in the API call
    while fetching the policy events. The default behavior of the API would be considered.
-   **Policy Enabled:** This parameter allows the user to find by the policies enabled while
    fetching the policy events. The valid values for this parameter include: True, False, All.  
    **Note:** When 'All' is selected, 'policy_enabled' will not be passed in the API call while
    fetching the policy events. The default behavior of the API would be considered.
-   **Filter:** This parameter allows filtering the policy events based on the search filters
    applied. It allows multiple filters combined using and/or conjunctions. Refer to the
    [<u>filtering</u>](https://developers.agari.com/agari-platform/docs/filtering) section in the
    Agari Docs for more details.
-   **Add Fields:** This parameter allows the user to add the optional fields to the default message
    payload. It expects a comma-delimited string as an input parameter.
-   **CEF mapping:** This parameter is a JSON dictionary represented as a serialized JSON string.
    Each key in the dictionary is a potential key name in the message artifact that is to be renamed
    to the value. For example, if the 'cef_mapping' is {"message_trust_score":"message_ts"}, your
    artifact will have a ‘message_ts’ CEF field instead of ‘message_trust_score’ CEF field.
-   **Start date:** This parameter allows the user to specify the earliest date time the search
    should target while fetching the policy events. This parameter will be taken into consideration
    for the first run of scheduled polling and Poll Now. The datetime should be in ISO 8601 format.
    The default value for the start date is the last 14 days. The provided date cannot be greater
    than the last 14 days.
-   **Sort:** This parameter allows sorting the data based on the 'created_at' date. The following
    are the valid values that the parameter can take:  
    -   oldest_first
    -   latest_first
-   **Max results:** The maximum number of results to ingest. The default value is 100.
-   **Max Workers for Polling:** This configuration parameter allows the user to configure the
    number of maximum workers while fetching the results from the Agari server for On Poll action.
    The number of workers defined is directly proportional to the number of threads created using
    ThreadPool Executor. ThreadPool Executor will provide a simple abstraction to spin up multiple
    threads and will use those threads to perform tasks concurrently. For example, if the number of
    workers is 10, the thread pool executor will essentially create 10 concurrent threads to process
    any jobs that we submit to it. The threading concept will be majorly used for the 'get policy
    event' and 'get message' API call while fetching the results for ingestion. Please note that
    increasing the number of workers will elevate the performance of the On Poll action in the Agari
    app. The only downside will be the increased utilization of resources on the Phantom platform,
    which may lead to unexpected behavior on the Phantom platform. The default value is 1.  
    **Note:** Assign the number of workers depending on the system configuration of the platform and
    the resources available.
-   **Note:** If non-required parameters are kept empty, then the default behavior of the API would
    be considered.

## Retry Mechanism

-   The 429 status code (rate limit) will be handled using the backoff factor and number of retries
    parameters in the session object.
-   **Number of Retries:** The number of retries defines the number of attempts for which the action
    will keep on retrying if the Agari API continuously hits "429 Too Many Requests". If the
    intermittent error gets eliminated before the number of retries gets exhausted, then, the action
    execution will continue along its workflow and if the intermittent error is still persistent and
    all the retries are exhausted, then, the action will fail with the latest error message being
    displayed. The number of retries is `      5     ` .
-   **Backoff Factor:** A backoff factor to apply between attempts after the second try (most errors
    are resolved immediately by a second try without a delay). The backoff factor is
    `      0.3     ` .
    -   Sleep time calculation:
        `        {backoff factor} * (2 ** ({number of total retries} - 1))       ` seconds.

## Explanation of the Agari Actions' Parameters

-   ### Test Connectivity (Action Workflow Details)

    -   This action will test the connectivity of the Phantom server to the Agari instance by making
        an initial API call using the provided asset configuration parameters. This action can also
        be used to generate a new bearer token.
    -   The action validates the provided asset configuration parameters. Based on the API call
        response, the appropriate success and failure message will be displayed when the action gets
        executed.

-   ### List Policy Events

    Fetches a list of policy events from the Agari Platform. The user can filter the results based
    on the action parameters as described below. The results can be sorted either in ascending or
    descending order based on the field attribute used. The user can paginate through the responses
    based on the offset parameter. The max results parameter can be used to limit the output
    responses.

    -   **<u>Action Parameter:</u> Max results**

          

        -   This parameter allows the user to limit the number of results. It expects a numeric
            value as an input. The default value is 100 for which it will fetch the first 100 policy
            events from the response.

    -   **<u>Action Parameter:</u> Offset**

          

        -   This parameter allows the user to set the starting point or offset for the response. It
            expects a numeric value as an input. If not provided, then 0 will be considered as the
            starting index.

    -   **<u>Action Parameter:</u> Sort**

          

        -   This parameter allows sorting the policy events based on the field specified with its
            sorting direction. It expects a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Rem Fields**

          

        -   This parameter allows the user to remove the fields from the default payload. It expects
            a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Add Fields**

          

        -   This parameter allows the user to add the optional fields to the default payload. It
            expects a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Fields**

          

        -   This parameter allows the user to specify the fields which are required to be fetched in
            the response. It expects a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Filter**

          

        -   This parameter allows filtering the policy events based on the search filters applied.
            It allows multiple filters combined using and/or conjunctions. Refer to the
            [<u>filtering</u>](https://developers.agari.com/agari-platform/docs/filtering) section
            in the Agari Docs for more details.

    -   **<u>Action Parameter:</u> Start date**

          

        -   This parameter allows the user to specify the earliest date time the search should
            target while fetching the policy events. The datetime should be in ISO 8601 format.

    -   **<u>Action Parameter:</u> End date**

          

        -   This parameter allows the user to specify the last date time the search should target
            while fetching the policy events. The datetime should be in ISO 8601 format.

    -   **<u>Action Parameter:</u> Policy Name**

          

        -   This parameter allows the user to find by the policy name while fetching the policy
            events.

    -   **<u>Action Parameter:</u> Policy Action**

          

        -   This parameter allows the user to find the policy action while fetching the policy
            events. The valid values for this parameter include: deliver, move, inbox, delete, none,
            all.  
            **Note:** When 'all' is selected, 'policy_action' will not be passed in the API call
            while fetching the policy events. The default behavior of the API would be considered.

    -   **<u>Action Parameter:</u> Exclude Alert Types**

          

        -   This parameter allows the user to exclude the alert type while fetching the policy
            events. The valid values for this parameter include MessageAlert, SystemAlert, None.  
            **Note:** When 'None' is selected, 'exclude_alert_types' will not be passed in the API
            call while fetching the policy events. The default behavior of the API would be
            considered.

    -   **<u>Action Parameter:</u> Policy Enabled**

          

        -   This parameter allows the user to find by the policies enabled while fetching the policy
            events. The valid values for this parameter include: True, False, All.  
            **Note:** When 'All' is selected, 'policy_enabled' will not be passed in the API call
            while fetching the policy events. The default behavior of the API would be considered.

    -   **Note:** If non-required parameters are kept empty, then the default behavior of the API
        would be considered.

    -   **Examples:**
        -   List the policy events with the policy name ‘Untrusted Messages’, sorted based on ID in
            descending order. Remove ‘notified_original_recipients’ and ‘summary’ from the response.
            -   Policy Name = Untrusted Messages
            -   Sort = id DESC
            -   Rem Fields = notified_original_recipients, summary

        -   List the policy events updated between 2021-04-21T09:58:30Z and 2021-04-21T12:23:27Z and
            sort them based on ‘updated at’ as the primary sort(ASC) and ID as the secondary
            sort(DESC). The results should also be limited to 15.

            -   Start Date = 2021-04-21T09:58:30Z
            -   End Date = 2021-04-21T12:23:27Z
            -   Sort = updated_at ASC, id DESC
            -   Max Results = 15

              
            **Note:** Max Results value will be handled internally which will paginate through the
            policy events.

        -   List the policy events updated after 2020-04-20T07:21:33Z and offset as 10. Policy
            enabled should be True and SystemAlert should be excluded. The results should be sorted
            based on created_at in ascending order.

            -   Offset = 10
            -   Filter = created_at.after(2020-04-20T07:21:33Z)
            -   Exclude Alert Types = SystemAlert
            -   Policy Enabled = True
            -   Sort = created_at ASC

              
            **Note:** The first 100 policy events will only be fetched as the max results parameter
            value is not provided by the user in this use case.

        -   List the policy events having ID 640767758 or 640767759 or 640767760. Also, check
            whether the policy action is ‘delete’ for them.
            -   Filter = id.eq(640767758) or id.eq(640767759) or id.eq(640767760)
            -   Policy Action = delete

        -   List the policy events with fields limited to ‘id’, ‘updated_at’, and ‘created_at’.
            Additionally, add ‘alert_definition_name’ to the response.
            -   Fields = id, updated_at, created_at
            -   Add Fields = alert_definition_name

-   ### Get Policy Event

    Fetch a specific policy event from the Agari Platform for the provided ID.

    -   **<u>Action Parameter:</u> ID**

          

        -   The unique policy event ID. This ID can be fetched from the output of the List Policy
            Events action\['id'\].

    -   **<u>Action Parameter:</u> Rem Fields**

          

        -   This parameter allows the user to remove the fields from the default payload. It expects
            a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Add Fields**

          

        -   This parameter allows the user to add the optional fields to the default payload. It
            expects a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Fields**

          

        -   This parameter allows the user to specify the fields which are required to be fetched in
            the response. It expects a comma-delimited string as an input parameter.

    -   **Note:** If non-required parameters are kept empty, then the default behavior of the API
        would be considered.

    -   **Examples:**
        -   Fetch the policy event with ID 640767773.
            -   ID = 640767773

        <!-- -->

        -   Fetch policy event with ID 640767773 and display only created at time and collector
            message ID associated with it.
            -   ID = 640767773
            -   Fields = collector_message_id, created_at

-   ### List Messages

    Fetches a list of messages from the Agari Platform. The user can filter the results based on the
    action parameters as described below. The results can be sorted either in ascending or
    descending order based on the field attribute used. The user can paginate through the responses
    based on the offset parameter and can limit the output response based on the max results
    parameter.

    -   **<u>Action Parameter:</u> Max results**

          

        -   This parameter allows the user to limit the number of results. It expects a numeric
            value as an input. The default value is 100 for which it will fetch the first 100
            messages from the response.

    -   **<u>Action Parameter:</u> Offset**

          

        -   This parameter allows the user to set the starting point or offset for the response. It
            expects a numeric value as an input. If not provided, then 0 will be considered as the
            starting index.

    -   **<u>Action Parameter:</u> Sort**

          

        -   This parameter allows sorting the messages based on the field specified with its sorting
            direction. It expects a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Rem Fields**

          

        -   This parameter allows the user to remove the fields from the default payload. It expects
            a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Add Fields**

          

        -   This parameter allows the user to add the optional fields to the default payload. It
            expects a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Fields**

          

        -   This parameter allows the user to specify the fields which are required to be fetched in
            the response. It expects a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Start date**

          

        -   This parameter allows the user to specify the earliest date time the search should
            target while fetching the messages. The datetime should be in ISO 8601 format.

    -   **<u>Action Parameter:</u> End date**

          

        -   This parameter allows the user to specify the last date time the search should target
            while fetching the messages. The datetime should be in ISO 8601 format.

    -   **<u>Action Parameter:</u> Search**

          

        -   This parameter allows searching the messages based on the search filters applied. It
            allows multiple filters combined using and/or conjunctions. Refer to the
            [<u>searching</u>](https://developers.agari.com/agari-platform/docs/searching) section
            in the Agari Docs for more details.

    -   **Note:**

          

        -   List Messages action can be used to fetch the messages which are not linked with any
            particular policy event.
        -   If non-required parameters are kept empty, then the default behavior of the API would be
            considered.

    -   **Examples:**
        -   List the messages which do not have attachment and sorted based on ID in descending
            order. Remove ‘from’ and ‘to’ fields from the response.
            -   Search = has_attachment=false
            -   Sort = id DESC
            -   Rem Fields = from, to

        -   List the messages updated between 2021-04-21T09:58:30Z and 2021-04-21T12:23:27Z and sort
            them based on ‘date’ as the primary sort(ASC) and ID as the secondary sort(DESC). The
            results should also be limited to 25.
            -   Start Date = 2021-04-21T09:58:30Z
            -   End Date = 2021-04-21T12:23:27Z
            -   Sort = date ASC, id DESC
            -   Max Results = 25

        -   List the messages after 2021-04-20T07:21:33Z and offset as 10. The message timestamp
            should be less than 1619074455000.

            -   Offset = 10
            -   Start Date = 2021-04-20T07:21:33Z
            -   Search = timestamp_ms\<1619074455000

              
            **Note:** The first 100 messages will only be fetched as the max results parameter value
            is not provided by the user in this use case.

        -   List the messages which are not linked with any policy and domain tags are not added for
            the message. Sort the results based on ID in ascending order.
            -   Search = policy_ids is null and domain_tags is null
            -   Sort = id ASC

-   ### Get Message

    Fetch a specific message from the Agari Platform for the provided ID.

    -   **<u>Action Parameter:</u> ID**

          

        -   The unique message ID. This ID can be fetched from the output of List Messages
            action\[‘id’\] or Get Policy Event action\[‘collector_message_id’\].

    -   **<u>Action Parameter:</u> Rem Fields**

          

        -   This parameter allows the user to remove the fields from the default payload. It expects
            a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Add Fields**

          

        -   This parameter allows the user to add the optional fields to the default payload. It
            expects a comma-delimited string as an input parameter.

    -   **<u>Action Parameter:</u> Fields**

          

        -   This parameter allows the user to specify the fields which are required to be fetched in
            the response. It expects a comma-delimited string as an input parameter.

    -   **Note:** If non-required parameters are kept empty, then the default behavior of the API
        would be considered.

    -   **Examples:**
        -   Fetch the message with ID 0ef8f456-a2ff-11eb-8180-0242ac130004.
            -   ID = 0ef8f456-a2ff-11eb-8180-0242ac130004
        -   Fetch message with ID 0ef8f456-a2ff-11eb-8180-0242ac130004 and remove the ‘from_domain’
            from the default payload.
            -   ID = 0ef8f456-a2ff-11eb-8180-0242ac130004
            -   Rem Fields = from_domain

-   ### Remediate Message

    Remediate the suspected message. The message can be moved or deleted from the inbox based on the
    remediation operation.

    -   **<u>Action Parameter:</u> ID**

          

        -   The unique message ID. This ID can be fetched from the output of List Messages
            action\[‘id’\] or Get Policy Event action\[‘collector_message_id’\].

    -   **<u>Action Parameter:</u> Remediation Operation**

          

        -   This parameter allows the user to move or delete the suspected message from the inbox.
            Valid values are: ‘move’, ‘delete’.

    -   **Examples:**
        -   Remediate the message with ID 0ef8f456-a2ff-11eb-8180-0242ac130004. The remediation
            operation should be ‘move’.
            -   ID = 0ef8f456-a2ff-11eb-8180-0242ac130004
            -   Remediation Operation = move

-   ### On Poll

    -   #### What is On Poll

        -   It will ingest the policy events and the message associated with them in the form of
            containers and artifacts in Phantom. The On Poll action will create one container for
            the policy event and two artifacts in the container \[Policy Event Artifact and Message
            Artifact\]. There are two approaches to polling which are mentioned below.

              

            -   POLL NOW (Manual polling)

                  

                -   It will fetch the data every time as per the corresponding asset configuration
                    parameters. It doesn’t store the last run context of the fetched data.

            -   Scheduled/Interval Polling

                  

                -   The ingestion action can be triggered at a regular time interval.
                -   It will fetch the data every time as per the corresponding asset configuration
                    parameters based on the stored context from the previous ingestion run. It
                    stores the last run context of the fetched data \[last_ingested_policy_event_id
                    and last_ingested_policy_event_date\]. It starts fetching data based on the
                    combination of the values of stored context for the previous ingestion run and
                    the corresponding asset configuration parameters having higher priority.

        <!-- -->

        -   **Note:** On Poll action will skip the policy events and messages in case of
            intermittent error while fetching the data from Agari or while processing the data. The
            logs associated with it, which includes the appropriate error details for skipping the
            policy event, will be logged in the `          spawn.log         ` file.

    -   #### Stored Context

        -   It is the concept of storing the context of the previous ingestion run. This concept
            will be used only for scheduled/interval polling. It will use the state file to store
            the last run context. This state file will be created for the asset of the application
            configured on the phantom platform.

          
          

    -   **<u>Action Parameter:</u> Max results**

          

        -   This parameter allows the user to limit the number of results. For scheduled or interval
            polling, this parameter can be used to limit the data for each polling cycle. It expects
            a numeric value as an input. The default value is 100 for which it will ingest only the
            first 100 events fetched.

    -   **<u>Action Parameter:</u> Sort**

          

        -   This parameter allows sorting the result data set based on the ‘created_at’ field. It
            can only take the values 'oldest_first' or 'latest_first'.

              
            **Note:** It is preferable to use ‘oldest_first’ as the ingestion mechanism to prevent
            any data loss.

    -   **<u>Action Parameter:</u> Add Fields**

          

        -   This parameter allows the user to add the optional fields to the default message
            payload. It expects a comma-delimited string as an input parameter.

              
            **Note:** Add Fields will be applied to the ‘get message’ API call (Message Artifact)
            during polling.

    -   **<u>Action Parameter:</u> Start date**

          

        -   This parameter allows the user to specify the earliest date time the search should
            target while fetching the policy events. This parameter will be taken into consideration
            for the first run of scheduled polling and Poll Now. The datetime should be in ISO 8601
            format. The default value for the start date is the last 14 days. The provided date
            cannot be greater than the last 14 days.

    -   **<u>Action Parameter:</u> Filter**

          

        -   This parameter allows filtering the policy events based on the search filters applied.
            It allows multiple filters combined using and/or conjunctions. Refer to the
            [<u>filtering</u>](https://developers.agari.com/agari-platform/docs/filtering) section
            in the Agari Docs for more details.

    -   **<u>Action Parameter:</u> Policy Name**

          

        -   This parameter allows the user to find by the policy name while fetching the policy
            events.

    -   **<u>Action Parameter:</u> Policy Action**

          

        -   This parameter allows the user to find the policy action while fetching the policy
            events. The valid values for this parameter include: deliver, move, inbox, delete, none,
            all.  
            **Note:** When 'all' is selected, 'policy_action' will not be passed in the API call
            while fetching the policy events. The default behavior of the API would be considered.

    -   **<u>Action Parameter:</u> Exclude Alert Types**

          

        -   This parameter allows the user to exclude the alert type while fetching the policy
            events. The valid values for this parameter include: MessageAlert, SystemAlert, None.  
            **Note:** When 'None' is selected, 'exclude_alert_types' will not be passed in the API
            call while fetching the policy events. The default behavior of the API would be
            considered.

    -   **<u>Action Parameter:</u> Policy Enabled**

          

        -   This parameter allows the user to find the policies enabled while fetching the policy
            events. The valid values for this parameter include: True, False, All.  
            **Note:** When 'All' is selected, 'policy_enabled' will not be passed in the API call
            while fetching the policy events. The default behavior of the API would be considered.

    -   **<u>Action Parameter:</u> CEF mapping**

          

        -   This parameter is a JSON dictionary represented as a serialized JSON string. Each key in
            the dictionary is a potential key name in an artifact that is to be renamed to the
            value. For example, if the 'cef_mapping' is {"message_trust_score":"message_ts"}, your
            artifact will have a ‘message_ts’ CEF field instead of ‘message_trust_score’ CEF field.

    -   **<u>Action Parameter:</u> Max Workers for Polling**

          

        -   This configuration parameter allows the user to configure the number of maximum workers
            while fetching the results from the Agari server for On Poll action. The number of
            workers defined is directly proportional to the number of threads created using
            ThreadPool Executor. ThreadPool Executor will provide a simple abstraction to spin up
            multiple threads and will use those threads to perform tasks concurrently. For example,
            if the number of workers is 10, the thread pool executor will essentially create 10
            concurrent threads to process any jobs that we submit to it. The threading concept will
            be majorly used for the 'get policy event' and 'get message' API call while fetching the
            results for ingestion. Please note that increasing the number of workers will elevate
            the performance of the On Poll action in the Agari app. The only downside will be the
            increased utilization of resources on the Phantom platform, which may lead to unexpected
            behavior on the Phantom platform. The default value is 1.  
            **Note:** Assign the number of workers depending on the system configuration of the
            platform and the resources available.

    -   **Note:** If non-required parameters are kept empty, then the default behavior of the API
        would be considered.

    -   **Examples:**
        -   Ingest the policy events with the policy name ‘Untrusted Messages’, sorted in the latest
            first order.
            -   Policy Name = Untrusted Messages
            -   Sort = latest_first

        -   List the policy events updated after 2021-04-21T09:58:30Z. Rename the CEF mapping for
            ‘mail_from’ to ‘from_mail’. The results should also be limited to 30.

            -   Start Date = 2021-04-21T09:58:30Z
            -   Max Results = 30
            -   CEF Mapping={“mail_from”: “from_mail”}

              
            **Note:** Max Results value will be handled internally which will paginate through the
            policy events.
