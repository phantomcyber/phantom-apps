[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "    Copyright (c) 2021 Cofense"
[comment]: # ""
[comment]: # "    This unpublished material is proprietary to Cofense."
[comment]: # "    All rights reserved. The methods and"
[comment]: # "    techniques described herein are considered trade secrets"
[comment]: # "    and/or confidential. Reproduction or distribution, in whole"
[comment]: # "    or in part, is forbidden except by express written permission"
[comment]: # "    of Cofense."
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Explanation of the Asset Configuration Parameters

The asset configuration parameters affect \[test connectivity\] and some other actions of the
application. Below are the explanation and usage of all these parameters. The parameters related to
test connectivity action are Server URL, Verify server certificate, Client ID, and Client Secret.

-   **Server URL:** The URL used to connect with the Cofense Triage server. Example:
    https://platform.cofensetriage.com
-   **Verify server certificate:** Validate server certificate.
-   **Client ID:** Client ID.
-   **Client Secret:** Client Secret.
-   **Data to be ingested:** The type of data that is to be ingested. The following are the valid
    values:  
    -   reports
    -   threat_indicators
-   **Threat indicator type:** The type of threat indicators to retrieve. The default value is "All"
    which retrieves all types of threat indicators. The following are the valid values that the
    parameter can take:  
    -   All
    -   Header
    -   Hostname
    -   URL
    -   MD5
    -   SHA256
-   **Threat indicator level:** The level of the threat indicators to retrieve. The default value is
    "All" which retrieves all levels of threat indicators. The following are the valid values that
    the parameter can take:  
    -   All
    -   Malicious
    -   Suspicious
    -   Benign
-   **Report location:** The location of the reports to retrieve. The default value is "All" which
    retrieves reports from all the locations. The following are the valid values that the parameter
    can take:  
    -   All
    -   Inbox
    -   Reconnaissance
    -   Processed
-   **Match priority:** The highest priority of a rule matching the reported email.
-   **Category ID:** The category ID of the report.
-   **Tags:** This parameter allows filtering the reports based on the list of comma-separated tags.
    If the tag value contains a comma, enclose it in double-quotes, for example:
    tag1,"test,tag",tag2. If a comma-separated list is provided, reports matching any of the tags
    from the provided list will be retrieved.
-   **Categorization tags:** This parameter allows filtering the reports based on the list of
    comma-separated categorization tags. If a comma-separated list is provided, reports matching any
    of the tags from the provided list will be retrieved.
-   **Ingest subfields:** Whether or not to ingest the subfields of the selected data. If this
    parameter is set to true, the data and all the resources related to the data that are present in
    the relationships will be ingested.
-   **Category ID to severity mapping:** The mapping in JSON format between the category ID of the
    report and the Phantom container severity. If no value is provided, then the default mapping
    will be used and, if the category ID isn't present in the default mapping the severity will be
    set to "Low". If a value is provided, the combination of the provided value and the default
    mapping will be used to decide the severity. The default mapping is: {"High": \["4"\], "Medium":
    \["3"\], "Low": \["1", "2", "5"\]}. Example value for the parameter is: {"High": \["8", "9"\],
    "Medium": \["7"\], "Low": \["6"\]}
-   **Cef mapping:** This parameter is a JSON dictionary represented as a serialized JSON string.
    Each key in the dictionary is a potential key name in an artifact that is to be renamed to the
    value. For example, if the cef_mapping is {"website":"requestURL"} your artifact will have
    requestURL cef field in place of website cef field. This parameter will be taken into
    consideration only during ingestion.
-   **Start date:** The initial start date and time of the ingestion. This parameter retrieves the
    data that was updated on or after the provided date. It will be taken into consideration during
    the poll now and the first run of scheduled/interval polling.
-   **Sort:** This parameter allows sorting the data based on the 'updated_at' date. The default
    value is "oldest_first" which sorts the results in the oldest first order. The following are the
    valid values that the parameter can take:  
    -   oldest_first
    -   latest_first
-   **Update state after:** This parameter saves the context after ingestion of every provided
    number of containers. This parameter is only used for scheduled/interval polling and only if the
    sort parameter value is "oldest_first".
-   **Max results:** Maximum number of results to ingest. If not provided all the data will be
    ingested.

## Explanation of the Actions' Parameters

-   ### Test Connectivity (Action Workflow Details)

    -   This action will test the connectivity of the Phantom server to the Cofense Triage instance
        by making an initial API call using the provided asset configuration parameters. This action
        can be used to generate a new token.
    -   The action validates the provided asset configuration parameters. Based on the API call
        response, the appropriate success and failure message will be displayed when the action gets
        executed.

-   ### Get reports

    -   **<u>Action Parameter:</u> Location**

          

        -   This parameter allows filtering the reports based on the location. The following are the
            valid values that the parameter can take:  
            -   All
            -   Inbox
            -   Reconnaissance
            -   Processed

    -   **<u>Action Parameter:</u> From address**

          

        -   This parameter allows filtering the reports based on the sender's email address of the
            reported email.

    -   **<u>Action Parameter:</u> Reporter's email**

          

        -   This parameter allows filtering the reports based on the reporter's email address of the
            reported email.

    -   **<u>Action Parameter:</u> Subject**

          

        -   This parameter allows filtering the reports with the subject containing a specific
            string. All the reports containing the provided value in the subject will be retrieved.

    -   **<u>Action Parameter:</u> Match priority**

          

        -   This parameter allows filtering the reports based on the highest priority of a rule
            matching the reported email.

    -   **<u>Action Parameter:</u> Category ID**

          

        -   This parameter allows filtering the reports based on the category ID of the report.

    -   **<u>Action Parameter:</u> Start date**

          

        -   This parameter allows filtering the reports updated on or after the provided date.

    -   **<u>Action Parameter:</u> End date**

          

        -   This parameter allows filtering the reports updated before the provided date.

    -   **<u>Action Parameter:</u> Tags**

          

        -   This parameter allows filtering the reports based on the list of comma-separated tags.
            If the tag value contains a comma, enclose it in double-quotes, for example:
            tag1,"test,tag",tag2. If a comma-separated list is provided, reports matching any of the
            tags from the provided list will be retrieved.

    -   **<u>Action Parameter:</u> Categorization tags**

          

        -   This parameter allows filtering the reports based on the list of comma-separated
            categorization tags. If a comma-separated list is provided, reports matching any of the
            tags from the provided list will be retrieved.

    -   **<u>Action Parameter:</u> Sort**

          

        -   This parameter allows sorting the reports based on the 'updated_at' date of the report.
            By default, it will sort in the oldest first order. The following are the valid values
            that the parameter can take:  
            -   oldest_first
            -   latest_first

    -   **<u>Action Parameter:</u> Ingest report**

          

        -   This parameter allows the ingestion of the report into the container.

    -   **<u>Action Parameter:</u> Ingest subfields**

          

        -   This parameter allows the ingestion of the fields relating to the report into the
            container. If this parameter is set to true, the report and all the resources related to
            the report that are present in the relationships together will get ingested into the
            container.

    -   **<u>Action Parameter:</u> Label**

          

        -   This parameter allows the ingestion of data into the container(s) with the provided
            label. The label must be valid or the action will fail. Required if 'ingest_report' or
            'ingest_subfields' is set. This parameter will be taken into consideration only during
            ingestion.

    -   **<u>Action Parameter:</u> Tenant**

          

        -   This parameter allows the creation of container(s) for the provided tenant ID or tenant
            name. The tenant must be valid or the action will fail. Required if 'ingest_report' or
            'ingest_subfields' is set. This parameter will be taken into consideration only during
            ingestion.

    -   **<u>Action Parameter:</u> Cef mapping**

          

        -   This parameter is a JSON dictionary represented as a serialized JSON string. Each key in
            the dictionary is a potential key name in an artifact that is to be renamed to the
            value. For example, if the cef_mapping is {"website":"requestURL"} your artifact will
            have requestURL cef field in place of website cef field. This parameter will be taken
            into consideration only during ingestion.

    -   **<u>Action Parameter:</u> Max results**

          

        -   Maximum number of results to return. If not provided all the data will be retrieved.

    -   **Note -** If no value is provided in any parameter, then all the records will be retrieved.

    -   **Example:**
        -   List all the reports present in Inbox containing “demo” word in the subject and having
            match priority equals 5 and is sent by 'abc@test.com'.
            -   Location = Inbox
            -   Subject = Demo
            -   Match Priority = 5
            -   From Address = abc@test.com
        -   List all the reports updated between 2020-09-23T08:31:58Z and 2020-09-29T09:00:00Z and
            sort them in oldest_first order.
            -   Start date = 2020-09-23T08:31:58Z
            -   End date = 2020-09-29T09:00:00Z
            -   Sort = oldest_first
        -   List the reports in the latest_first order.
            -   Sort = latest_first

-   ### Get report

    -   **<u>Action Parameter:</u> Report ID**

          

        -   The ID of the report to be retrieved.

    -   **<u>Action Parameter:</u> Ingest report**

          

        -   This parameter allows the ingestion of the report into the container.

    -   **<u>Action Parameter:</u> Ingest subfields**

          

        -   This parameter allows the ingestion of the fields relating to the report into the
            container. If this parameter is set to true, the report and all the resources related to
            the report that are present in the relationships together will get ingested into the
            container.

    -   **<u>Action Parameter:</u> Label**

          

        -   This parameter allows the ingestion of data into the container(s) with the provided
            label. The label must be valid or the action will fail. Required if 'ingest_report' or
            'ingest_subfields' is set. This parameter will be taken into consideration only during
            ingestion.

    -   **<u>Action Parameter:</u> Tenant**

          

        -   This parameter allows the creation of container(s) for the provided tenant ID or tenant
            name. The tenant must be valid or the action will fail. Required if 'ingest_report' or
            'ingest_subfields' is set. This parameter will be taken into consideration only during
            ingestion.

    -   **<u>Action Parameter:</u> Cef mapping**

          

        -   This parameter is a JSON dictionary represented as a serialized JSON string. Each key in
            the dictionary is a potential key name in an artifact that is to be renamed to the
            value. For example, if the cef_mapping is {"website":"requestURL"} your artifact will
            have requestURL cef field in place of website cef field. This parameter will be taken
            into consideration only during ingestion.

    -   **Example:**
        -   Fetch the report with ID equals 15.
            -   Report ID = 15

-   ### Categorize report

    -   **<u>Action Parameter:</u> Report ID**

          

        -   This parameter is the ID of the report which the user wants to categorize.

    -   **<u>Action Parameter:</u> Category ID**

          

        -   This parameter is the ID of the category into which the user wants to categorize the
            report. Category ID is either known by Cofense Triage users or it can be fetched from
            the output of Get categories action.

    -   **<u>Action Parameter:</u> Category Name**

          

        -   This parameter is the name of the category into which the user wants to categorize the
            report. This parameter can be provided if the category ID is not known by Cofense Triage
            users.

    -   **<u>Action Parameter:</u> Response ID**

          

        -   This parameter is the ID of the response.

    -   **<u>Action Parameter:</u> Categorization Tags**

          

        -   This parameter allows the user to provide multiple tags to be given to the report while
            categorizing it. It accepts a comma-separated list of tags.

    -   **Note -** If both category ID and category name are provided, then category ID will be
        given a higher priority.

    -   **Example:**
        -   Categorize the report having Report ID 5, with given category ID 1, and add
            categorization tag ‘test’.
            -   Report ID = 5
            -   Category ID = 1
            -   Categorization tags = test
        -   Categorize the report having Report ID 10, with given category ID 2 and add
            categorization tag ‘test tag’, also send a response using response template ID 2.
            -   Report ID = 10
            -   Category ID = 2
            -   Categorization tags = test tag
            -   Response ID = 2

-   ### Get reporters

    -   **<u>Action Parameter:</u> VIP**

          

        -   This parameter allows searching for the VIP reporters. If the value of the parameter is
            false, then all the reporters will be retrieved.

    -   **<u>Action Parameter:</u> Reputation score**

          

        -   This parameter allows searching for reporters having the provided reputation score. It
            allows a comma-separated list. If a comma-separated list is provided, then the reporters
            with any of the specified scores will be retrieved.

    -   **<u>Action Parameter:</u> Email**

          

        -   This parameter allows searching for the reporter with a specific email.

    -   **<u>Action Parameter:</u> Sort**

          

        -   This parameter allows sorting the reporters based on the ID. By default, it will sort in
            the oldest first order. The following are the valid values that the parameter can
            take:  
            -   oldest_first
            -   latest_first

    -   **<u>Action Parameter:</u> Max results**

          

        -   Maximum number of results to return. If not provided, all the data will be retrieved.

    -   **Note -** If no value is provided in any parameter, then all the records will be retrieved.

    -   **Example:**
        -   List the latest 15 VIP reporters with a reputation score equals 15.
            -   VIP = true
            -   Reputation Score = 15
            -   Max results = 15
            -   Sort = latest_first
        -   Fetch the reporter with the email address abc@test.com.
            -   Email = abc@test.com

-   ### Get reporter

    -   **<u>Action Parameter:</u> Reporter ID**

          

        -   This parameter is the ID of the reporter to fetch.

    -   **Example:**
        -   Fetch the reporter with the Reporter ID equals 10.
            -   Report ID = 10

-   ### Get URLs

    -   **<u>Action Parameter:</u> Risk score**

          

        -   This parameter is the risk score of the URL.

    -   **<u>Action Parameter:</u> Risk score operator**

          

        -   This parameter is the operator to work with the risk score parameter. The default value
            is 'eq'.For example: if the risk score = 5 and the risk score operator = 'lt', then all
            the URLs having a risk score less than 5 will be retrieved. The following are the valid
            values that the parameter can take:  
            -   eq
            -   not_eq
            -   lt
            -   lteq
            -   gt
            -   gteq

    -   **<u>Action Parameter:</u> URL Value**

          

        -   This parameter is the value of the URL to search for.

    -   **<u>Action Parameter:</u> Start date**

          

        -   This parameter allows filtering the URLs updated on or after the provided date.

    -   **<u>Action Parameter:</u> End date**

          

        -   This parameter allows filtering the URLs updated before the provided date.

    -   **<u>Action Parameter:</u> Sort**

          

        -   This parameter allows sorting the URLs based on the 'updated_at' date of the URL. By
            default, it will sort in the oldest first order. The following are the valid values that
            the parameter can take:  
            -   oldest_first
            -   latest_first

    -   **<u>Action Parameter:</u> Max results**

          

        -   Maximum number of results to return. If not provided, all the data will be retrieved.

    -   **Note -** If no value is provided in any parameter, then all the records will be retrieved.

    -   **Example:**
        -   List all the URLs having a risk score equals 5 in the latest first order.
            -   Risk score ID = 5
            -   Risk score operator = eq
            -   Sort = latest_first
        -   List the URL having value equals 'https://testurl.com'.
            -   URL value = https://testurl.com
        -   List oldest 5 URLs that are updated between 2020-09-23T08:31:58Z and
            2020-09-29T09:00:00Z.
            -   Start date = 2020-09-23T08:31:58Z
            -   End date = 2020-09-29T09:00:00Z
            -   Sort = oldest_first
            -   Max results = 5

-   ### Get url

    -   **<u>Action Parameter:</u> URL ID**

          

        -   This parameter is the ID of the URL to fetch.

    -   **Example:**
        -   Fetch the URL with URL ID equals 5.
            -   URL ID = 5

-   ### Create response

    -   **<u>Action Parameter:</u> Name**

          

        -   This parameter specifies a short display name of the response sent to individuals when a
            report is categorized.

    -   **<u>Action Parameter:</u> Description**

          

        -   This parameter specifies the expanded name or description of the response.

    -   **<u>Action Parameter:</u> Subject**

          

        -   This parameter specifies the subject of the response. It supports template variables.

    -   **<u>Action Parameter:</u> Body**

          

        -   This parameter specifies the body of the email. It supports template variables.

    -   **<u>Action Parameter:</u> To reporter**

          

        -   This parameter specifies whether to add the reporter to the response recipient list
            (true) or not (false). The default is true. Either 'to_reporter' or 'to_other', or both,
            must be enabled.

    -   **<u>Action Parameter:</u> To other**

          

        -   This parameter specifies whether to add the addresses specified in 'to_other_address' to
            the response recipient list (true) or not (false). The default is false. If true,
            specify one or more values in 'to_other_address'. Either to_reporter or 'to_other', or
            both, must be enabled.

    -   **<u>Action Parameter:</u> To other address**

          

        -   This parameter is a comma-separated list of email addresses to send the response to.
            Works with 'to_other'.

    -   **<u>Action Parameter:</u> Attach original**

          

        -   This parameter specifies whether to attach the original email to the response (true) or
            not (false).

    -   **<u>Action Parameter:</u> CC address**

          

        -   This parameter is a comma-separated list of email addresses to CC the response to.

    -   **<u>Action Parameter:</u> BCC address**

          

        -   This parameter is a comma-separated list of email addresses to BCC the response to.

    -   **Template variables:** The user can insert variables into the subject and body of the
        response while creating it. When the response is sent as a result of categorizing a report,
        Cofense Triage replaces the variables with information from that report. The following are
        the template variables

          

        -   \[SUBJECT\]: Replaced with the subject of the reported email.
        -   \[REPORT_DATE\]: Replaced with the date the email was reported.

    -   **Example:**
        -   Create a response with name: "Example Response", Description: "This is an example
            response", Subject: "Email '\[SUBJECT\]' reported \[REPORT_DATE\] is SAFE", and Body =
            "The email '\[SUBJECT\]' that you reported on \[REPORT_DATE\] is safe".
            -   Name = Example Response
            -   Description = This is an example response
            -   Subject = Email '\[SUBJECT\]' reported \[REPORT_DATE\] is SAFE
            -   Body = The email '\[SUBJECT\]' that you reported on \[REPORT_DATE\] is safe
        -   Create a response with name: "Example Response", Subject: "Email '\[SUBJECT\]' reported
            \[REPORT_DATE\] is SAFE", and Body = "The email '\[SUBJECT\]' that you reported on
            \[REPORT_DATE\] is safe". The response should be sent to the reporter and not others.
            -   Name = Example Response
            -   To reporter = true
            -   To other = false
            -   Subject = Email '\[SUBJECT\]' reported \[REPORT_DATE\] is SAFE
            -   Body = The email '\[SUBJECT\]' that you reported on \[REPORT_DATE\] is safe

    **Note:** This action is supported for Cofense Triage with version older than 1.23.

-   ### Get responses

    -   **<u>Action Parameter:</u> Max results**

          

        -   This parameter allows the user to limit the number of results. It expects a numeric
            value as an input.

    -   **Example:**
        -   List 50 responses.
            -   Max results = 50

    **Note:** This action is supported for Cofense Triage with version older than 1.23.

-   ### Create threat indicator

    -   **<u>Action Parameter:</u> Level**

          

        -   This parameter is the level of threat indicator. The following are the valid values that
            the parameter can take:  
            -   Malicious
            -   Suspicious
            -   Benign

    -   **<u>Action Parameter:</u> Type**

          

        -   This parameter is the type of threat indicator. The following are the valid values that
            the parameter can take:  
            -   Header
            -   Hostname
            -   URL
            -   MD5
            -   SHA256

    -   **<u>Action Parameter:</u> Value**

          

        -   This parameter is the value of the threat indicator. If the value of the parameter
            'type' is 'Header', then the value of this parameter should be in the form
            {header_key}:{header_value}.

    -   **<u>Action Parameter:</u> Source**

          

        -   This parameter is the source of the threat indicator. The default value of this
            parameter is "Splunk_Phantom-UI"

    -   **Example:**
        -   Create a malicious threat indicator with type: URL and value: 'https://testurl.com'.
            -   Level = Malicious
            -   Type = URL
            -   Value = 'https://testurl.com'
        -   Create a Suspicious threat indicator, source: 'Splunk_Phantom-UI', type: Header and
            value: 'From:test@test.com'
            -   Level = Suspicious
            -   Type = Header
            -   Value = From:test@test.com
            -   Source = Splunk_Phantom-UI

-   ### Get categories

    -   **<u>Action Parameter:</u> Name**

          

        -   This parameter allows the user to fetch the categories with the name containing a
            specific string.

    -   **<u>Action Parameter:</u> Malicious**

          

        -   This parameter allows the user to fetch the categories based on whether the category is
            used to classify malicious reports or not. If the value is false, then all the
            categories will be fetched.

    -   **<u>Action Parameter:</u> Max results**

          

        -   Maximum number of results to return. If not provided, all the data will be retrieved.

    -   **Note -** If no value is provided in any parameter, then all the records will be retrieved.

    -   **Example:**
        -   List the categories containing ‘threat’ in the name and are malicious.
            -   Name = Threat
            -   Malicious = true
        -   List 50 categories.
            -   Max results = 50

-   ### Get threat indicators

    -   **<u>Action Parameter:</u> Level**

          

        -   This parameter allows filtering based on the level of threat indicator. The following
            are the valid values that the parameter can take:  
            -   All
            -   Malicious
            -   Suspicious
            -   Benign

    -   **<u>Action Parameter:</u> Type**

          

        -   This parameter allows filtering based on the type of threat indicator. The following are
            the valid values that the parameter can take:  
            -   All
            -   Header
            -   Hostname
            -   URL
            -   MD5
            -   SHA256

    -   **<u>Action Parameter:</u> Source**

          

        -   This parameter allows filtering based on the source of the threat. If not provided,
            threat indicators from all the sources will be fetched.

    -   **<u>Action Parameter:</u> Value**

          

        -   This parameter allows filtering based on the actual value of the threat indicator.

    -   **<u>Action Parameter:</u> Start date**

          

        -   This parameter allows the user to fetch the threat indicators updated on or after the
            provided date.

    -   **<u>Action Parameter:</u> End date**

          

        -   This parameter allows the user to fetch the threat indicators updated before the
            provided date.

    -   **<u>Action Parameter:</u> Sort**

          

        -   This parameter allows sorting the result data set based on the 'updated_at' date of the
            threat indicator. By default, it will sort in the oldest first order. The following are
            the valid values that the parameter can take:  
            -   oldest_first
            -   latest_first

    -   **<u>Action Parameter:</u> Ingest threat indicator**

          

        -   This parameter allows ingestion of the threat indicator(s) into the container(s).

    -   **<u>Action Parameter:</u> Ingest subfields**

          

        -   This parameter allows the ingestion of the fields relating to the threat indicator into
            the container. If this parameter is set to true, the threat indicator and all the
            resources related to the threat indicator that are present in the relationships together
            will get ingested.

    -   **<u>Action Parameter:</u> Label**

          

        -   This parameter allows the ingestion of data into the container(s) with the provided
            label. The label must be valid or the action will fail. Required if
            'ingest_threat_indicator' or 'ingest_subfields' is set. This parameter will be taken
            into consideration only during ingestion.

    -   **<u>Action Parameter:</u> Tenant**

          

        -   This parameter allows the creation of container(s) for the provided tenant ID or tenant
            name. The tenant must be valid or the action will fail. Required if
            'ingest_threat_indicator' or 'ingest_subfields' is set. This parameter will be taken
            into consideration only during ingestion.

    -   **<u>Action Parameter:</u> Cef mapping**

          

        -   This parameter is a JSON dictionary represented as a serialized JSON string. Each key in
            the dictionary is a potential key name in an artifact that is to be renamed to the
            value. For example, if the cef_mapping is {"website":"requestURL"} your artifact will
            have requestURL cef field in place of website cef field. This parameter will be taken
            into consideration only during ingestion.

    -   **<u>Action Parameter:</u> Max results**

          

        -   Maximum number of results to return. If not provided all the data will be retrieved.

    -   **Note -** If no value is provided in any parameter then all the records will be retrieved.

    -   **Example:**
        -   List all the Malicious threat indicators that are URLs and are reported from the
            Triage-UI source.
            -   Level = Malicious
            -   Type = URL
            -   Source = Triage-UI
        -   List all the threat indicators updated between 2020-09-23T08:31:58Z and
            2020-09-29T09:00:00Z and sort them in oldest_first order.
            -   Start date = 2020-09-23T08:31:58Z
            -   End date = 2020-09-29T09:00:00Z
            -   Sort = oldest_first
        -   List 50 threat indicators in the latest first order.
            -   Max results = 50
            -   Sort = latest_first

-   ### Get email

    -   **<u>Action Parameter:</u> Report ID**

          

        -   This parameter is the ID of the report.

    -   **<u>Action Parameter:</u> Download method**

          

        -   This parameter allows the user to download the email as an artifact or as a vaulted
            file.

    -   **<u>Action Parameter:</u> Create vaulted file artifact**

          

        -   If storing the file as a vaulted file, this parameter allows the user to create an
            artifact referencing that file.

    -   **Example:**
        -   Download email for report ID equals 10.
            -   Report ID = 10
            -   Download method = vaulted file

-   ### Get Comments

    -   **<u>Action Parameter:</u> Body format**

          

        -   This parameter allows filtering the comments based on the body format. The following are
            the valid values that the parameter can take:  
            -   all
            -   text
            -   json

    -   **<u>Action Parameter:</u> Tags**

          

        -   This parameter allows filtering the comments based on the list of comma-separated tags.
            If the tag value contains a comma, enclose it in double-quotes, for example:
            tag1,"test,tag",tag2. If a comma-separated list is provided, comments matching any of
            the tags from the provided list will be retrieved.

    -   **<u>Action Parameter:</u> Start date**

          

        -   This parameter allows filtering the comments updated on or after the provided date.

    -   **<u>Action Parameter:</u> End date**

          

        -   This parameter allows filtering the comments updated before the provided date.

    -   **<u>Action Parameter:</u> Sort**

          

        -   This parameter allows sorting the comments based on the 'updated_at' date of the
            comment. By default, it will sort in the oldest first order. The following are the valid
            values that the parameter can take:  
            -   oldest_first
            -   latest_first

    -   **<u>Action Parameter:</u> Max results**

          

        -   Maximum number of results to return. If not provided, all the data will be retrieved.

    -   **Note -** If no value is provided in any parameter, then all the records will be retrieved.

    -   **Example:**
        -   List the latest 20 comments having 'text' body format with a tag 'test'.
            -   Body format = text
            -   Tags = test
            -   Sort = latest_first
            -   Max results = 20
        -   List all the comments updated between 2020-09-23T08:31:58Z and 2020-09-29T09:00:00Z and
            sort them in oldest_first order.
            -   Start date = 2020-09-23T08:31:58Z
            -   End date = 2020-09-29T09:00:00Z
            -   Sort = oldest_first
        -   List the comments in the latest_first order.
            -   Sort = latest_first

-   ### Get comment

    -   **<u>Action Parameter:</u> Comment ID**

          

        -   This parameter is the ID of the comment to fetch.

    -   **Example:**
        -   Fetch the comment with comment ID equals 5.
            -   Comment ID = 5

-   ### Get rule

    -   **<u>Action Parameter:</u> Rule ID**

          

        -   This parameter is the ID of the rule to fetch.

    -   **<u>Action Parameter:</u> Ingest report**

          

        -   This parameter allows ingestion of reports related to the rule.

    -   **<u>Action Parameter:</u> Ingest subfields**

          

        -   This parameter allows the ingestion of the fields relating to the report into the
            container. If this parameter is set to true, the report and all the resources related to
            the report that are present in the relationships together will get ingested into the
            container.

    -   **<u>Action Parameter:</u> Label**

          

        -   This parameter allows the ingestion of data into the container(s) with the provided
            label. The label must be valid or the action will fail. Required if 'ingest_report' or
            'ingest_subfields' is set. This parameter will be taken into consideration only during
            ingestion.

    -   **<u>Action Parameter:</u> Tenant**

          

        -   This parameter allows the creation of container(s) for the provided tenant ID or tenant
            name. The tenant must be valid or the action will fail. Required if 'ingest_report' or
            'ingest_subfields' is set. This parameter will be taken into consideration only during
            ingestion.

    -   **<u>Action Parameter:</u> Cef mapping**

          

        -   This parameter is a JSON dictionary represented as a serialized JSON string. Each key in
            the dictionary is a potential key name in an artifact that is to be renamed to the
            value. For example, if the cef_mapping is {"website":"requestURL"} your artifact will
            have requestURL cef field in place of website cef field. This parameter will be taken
            into consideration only during ingestion.

    -   **Example:**
        -   Fetch the rule with rule ID equals 5 and ingest the reports related to the rule.
            -   Rule ID = 5
            -   Ingest reports = True
            -   Label = events
            -   Tenant = Default

-   ### Get rules

    -   **<u>Action Parameter:</u> Name**

          

        -   This parameter allows filtering the rules with rule name containing a specific string.
            All the rules containing the provided value in the name will be retrieved.

    -   **<u>Action Parameter:</u> Description**

          

        -   This parameter allows filtering the rules with rule description containing a specific
            string. All the rules containing the provided value in the description will be
            retrieved.

    -   **<u>Action Parameter:</u> Priority**

          

        -   This parameter allows filtering the rules based on the priority.

    -   **<u>Action Parameter:</u> Tags**

          

        -   This parameter allows filtering the rules based on the list of comma-separated tags. If
            the tag value contains a comma, enclose it in double-quotes, for example:
            tag1,"test,tag",tag2. If a comma-separated list is provided, rules matching any of the
            tags from the provided list will be retrieved.

    -   **<u>Action Parameter:</u> Scope**

          

        -   This parameter allows filtering the rules based on the scope.

    -   **<u>Action Parameter:</u> Author name**

          

        -   This parameter allows filtering the rules with author name containing a specific string.
            All the rules containing the provided value in the author's name will be retrieved.

    -   **<u>Action Parameter:</u> Rule context**

          

        -   This parameter allows filtering the rules based on the context. The following are the
            valid values that the parameter can take:  
            -   All
            -   Internal safe
            -   Unwanted
            -   Threat hunting
            -   Phishing tactic
            -   Cleanup
            -   Unknown

    -   **<u>Action Parameter:</u> Active**

          

        -   This parameter allows filtering the rules based on the status. If the value of the
            parameter is false, then all the rules will be retrieved.

    -   **<u>Action Parameter:</u> Reports count**

          

        -   This parameter allows filtering the rules based on the number of reports the rule
            matched.

    -   **<u>Action Parameter:</u> Reports count operator**

          

        -   This parameter is the operator to work with the reports count parameter. The default
            value is 'eq'. For example: if the reports count = 5 and the reports count operator =
            'lt', then all the rules having a report count less than 5 will be retrieved. The
            following are the valid values that the parameter can take:  
            -   eq
            -   not_eq
            -   lt
            -   lteq
            -   gt
            -   gteq

    -   **<u>Action Parameter:</u> Start date**

          

        -   This parameter allows filtering the rules updated on or after the provided date.

    -   **<u>Action Parameter:</u> End date**

          

        -   This parameter allows filtering the rules updated before the provided date.

    -   **<u>Action Parameter:</u> Sort**

          

        -   This parameter allows sorting the rules based on the 'updated_at' date. By default, it
            will sort in the oldest first order. The following are the valid values that the
            parameter can take:  
            -   oldest_first
            -   latest_first

    -   **<u>Action Parameter:</u> Max results**

          

        -   Maximum number of results to return. If not provided all the data will be retrieved.

    -   **Note -** If no value is provided in any parameter, then all the records will be retrieved.

    -   **Example:**
        -   Fetch the active rules created by 'author1' with name equals 'test' having tag equals
            'test' and priority equals 1.
            -   Name = test
            -   Priority = 1
            -   Author name = author1
            -   Active = True
            -   Tags = test
        -   List all the rules updated between 2020-09-23T08:31:58Z and 2020-09-29T09:00:00Z and
            sort them in oldest_first order.
            -   Start date = 2020-09-23T08:31:58Z
            -   End date = 2020-09-29T09:00:00Z
            -   Sort = oldest_first
        -   Fetch 20 rules with report count equals 5.
            -   Reports count = 5
            -   Reports count operator = eq
            -   Max results = 20

-   ### Get integration submissions

    -   **<u>Action Parameter:</u> Type**

          

        -   This parameter is the type of integration submission.

    -   **<u>Action Parameter:</u> Value**

          

        -   This parameter is the value of integration submission.

    -   **Example:**
        -   List integration submissions of type MD5 with value equals
            f033362ca459dcab56aa6b2274751d13.
            -   Type = MD5
            -   Value = f033362ca459dcab56aa6b2274751d13
        -   List integration submissions of type URL with value equals http://test.com.
            -   Type = URL
            -   Value = http://test.com

-   ### On Poll

    -   ### What is On Poll

        -   It will ingest data from the external system into the phantom server in the form of
            containers and artifacts. There are two approaches to polling which are mentioned below.

              

            -   POLL NOW (Manual polling)

                  

                -   It will fetch the data every time as per the corresponding asset configuration
                    parameters. It doesn’t store the last run context of the fetched data. The
                    corresponding asset configuration parameters for the POLL NOW are
                    ingestion_type, threat_indicator_type, threat_indicator_level, report_location,
                    match_priority, category_id, tags, categorization_tags, ingest_subfields,
                    category_id_to_severity, cef_mapping, start_date, sort and max_results.

            -   Scheduled/Interval Polling

                  

                -   Scheduled Polling: The ingestion action can be triggered at every specified
                    timestamp interval.
                -   Interval Polling: The ingestion action can be triggered at every time range
                    interval.
                -   It will fetch the data every time as per the corresponding asset configuration
                    parameters based on the stored context from the previous ingestion run. It
                    stores the last run context of the fetched data. It starts fetching data based
                    on the combination of the values of stored context for the previous ingestion
                    run and the corresponding asset configuration parameters. The corresponding
                    asset configuration parameters for the scheduled/interval are ingestion_type,
                    threat_indicator_type, threat_indicator_level, report_location, match_priority,
                    category_id, tags, categorization_tags, ingest_subfields,
                    category_id_to_severity, cef_mapping, start_date, sort, update_state_after and
                    max_results.

    -   ### Containers and Artifacts creation

        -   We have configured two types of data ingestion which you can select from the asset
            configuration parameters. Below are the two types

              

            -   reports: It will ingest only the reports.
            -   threat_indicators: It will ingest only the threat indicators.

        -   Container

              

            -   A container is a composite object that consists of one or more artifacts that can be
                automated. Containers are the top-level data structure that Playbooks operate on.
                Every container has a common header, and beneath that, the ability to store
                arbitrary less structured JSON.

        -   Artifacts

              

            -   Artifacts are objects that are associated with a Container and serve as
                corroboration or evidence related to the Container.

        -   Each report or threat indicator will be ingested as an artifact in a separate container.
            Each subfield related to the report or the threat indicator will get ingested into the
            container of that report or threat indicator as a separate artifact if the
            'ingest_subfields' parameter is true. Below is the explanation based on the type of data
            for that.

              

            -   **reports**

                  
                    For this type, one container will be created for each report.

                -   Container 1:- Subject of the report

                      

                    -   This container will be used to store fetched report data in the form of
                        artifacts.

            -   **threat indicators**

                  
                    For this type, one container will be created for each threat indicator.

                -   Container 1:- Threat Indicator ID - ID

                      

                    -   This container will be used to store fetched threat indicator data in the
                        form of artifacts.

    -   ### Stored Context

        -   It is the concept of storing the context of the previous ingestion run. This concept
            will be used in the scheduled/interval polling. It will use the state file to store the
            last run context. This state file will be created for the created asset for the
            application on the phantom platform.

              

            -   State file location:

                  

                -   For non-NRI Instances:
                    /opt/phantom/local_data/app_states/7129d563-a28d-4afc-8081-f909dce54293
                -   For NRI Instances:
                    /home/phanru/phantomcyber/local_data/app_states/7129d563-a28d-4afc-8081-f909dce54293

            -   The default format of state file: {"app_version": "1.0.0"}

    -   **Example:**
        -   Ingest the Malicious threat indicators that are URLs and are updated on or after
            2020-09-23T08:31:58Z.
            -   Ingestion type = threat_indicators
            -   Threat Indicator Level = Malicious
            -   Threat Indicator Type = URL
            -   Start date = 2020-09-23T08:31:58Z
        -   Ingest the reports present in Inbox having match priority equals 5 and are updated on or
            after 2020-09-23T08:31:58Z.
            -   Ingestion type = reports
            -   Report Location = Inbox
            -   Match Priority = 5
            -   Start date = 2020-09-23T08:31:58Z
