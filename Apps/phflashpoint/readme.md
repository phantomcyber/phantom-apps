[comment]: # " File: redme.html"
[comment]: # ""
[comment]: # "    Copyright (c) Flashpoint, 2020"
[comment]: # ""
[comment]: # "    This unpublished material is proprietary to Flashpoint."
[comment]: # "    All rights reserved. The methods and"
[comment]: # "    techniques described herein are considered trade secrets"
[comment]: # "    and/or confidential. Reproduction or distribution, in whole"
[comment]: # "    or in part, is forbidden except by express written permission"
[comment]: # "    of Flashpoint."
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
[comment]: # ""
## Explanation of Asset Configuration Parameters

The asset configuration parameters affect \[test connectivity\] and all the other actions of the
application. Below are the explanation and usage of all those parameters.

-   **Base URL -** The URL to connect to the Flashpoint server.
-   **API Token -** The API token of the user.
-   **Retry Wait Period (in seconds) -** The value of this parameter defines the waiting period in
    seconds for which to hold the current execution of the action on receiving the “500 Internal
    Server Error” and then, retry the same API call after the waiting period is exhausted. This
    ensures that the integration provides a mechanism of attempting to overcome the intermittent
    “500 Internal Server Error”. It allows only non-zero positive integer values as input. The
    default value is 5 seconds.
-   **Number Of Retries -** The value of this parameter defines the number of attempts for which the
    action will keep on retrying if the Flashpoint API continuously returns the “500 Internal Server
    Error”. If the intermittent error gets eliminated before the number of retries gets exhausted,
    then, the action execution will continue along its workflow with the next set of API calls and
    if the intermittent error is still persistent and all the number of retries are exhausted, then,
    the action will fail with the latest error message being displayed. It allows only zero or
    positive integer values as input. The default value is 1 retry.
-   **Session Timeout -** This is an optional asset configuration parameter. The value of this
    parameter will be used as the session timeout value in the ‘Get Compromised Credentials’ and
    ‘Run Query’ actions while using the session scrolling pagination. The default value is 2 minutes
    and the maximum allowed value is 60 minutes.

## Steps to generate API Token

1.  Go to [Flashpoint](https://fp.tools/) .
2.  Select **APIs & Integrations** from the left side panel.
3.  Under the **FLASHPOINT API** section, select **Manage API Tokens** .
4.  Click on the **GENERATE TOKEN** .
5.  Enter a **Token Label** and your current FPTools credentials in the **Username** and
    **Password** fields in the appeared **Generate API Token** prompt.
6.  Click on the **GENERATE** button.
7.  This will generate a new API token and will display it in the **GENERATE API TOKEN** section on
    the page.

  **Note-** Save your generated API token somewhere secure, as you will no longer be able to
retrieve this key after leaving this page.

## Explanation of Flashpoint Actions' Parameters

1.  ### Test Connectivity (Action Workflow Details)

    -   This action will test the connectivity of the Phantom server to the Flashpoint instance by
        making an initial API call to the Indicators API using the provided asset configuration
        parameters.
    -   The action validates the provided asset configuration parameters. Based on the API call
        response, the appropriate success and failure message will be displayed when the action gets
        executed.

      

2.  ### List Indicators

    -   **<u>Action Parameter</u> ​ - Attribute Types**

        -   This parameter enables search by attribute types. It is an optional action parameter. It
            supports the comma-separated list of attribute types values. Each value from the
            provided comma-separated list must correspond to one of the MISP types, a list of which
            can be found [here](https://www.circl.lu/doc/misp/categories-and-types/#types) .
        -   **Examples:**
            -   Get recent md5, sha1, or source IP indicators
                -   Attribute Types = md5,sha1,ip-src

          
          

    -   **<u>Action Parameter</u> ​ - Query**

        -   This parameter will be used for free text searching. It is an optional parameter. You
            can also provide different queries to filter out indicators results.
        -   **Examples:**
            -   Filtering results based on the field value
                -   Query = category:”Payload Delivery”
            -   Free text search(when using multiple words, use a + instead of space, and for
                specific word search use “test text” (inverted double quotes) in the query action
                parameter.)
                -   Query = gandcrab+ransomware
                -   Query = “test text”

          
          

    -   **<u>Action Parameter</u> - Limit**

        -   This parameter is used to limit the number of indicator results. The default value
            is 500. If the limit is not provided, it will fetch by default 500 indicator results.

          
          

    -   **<u>Notes</u> -** The user will have to provide URL value in the "Attribute Types" action
        parameter and the URL value enclosed in double-quotes in the "Query" parameter if they want
        to search for an IoC having a specific URL value. This does not work correctly if the user
        provides the URL value without double-quotes in the "Query" parameter. This is based on the
        current API behavior of the Flashpoint.

      

3.  ### Search Indicators

    -   **<u>Action Parameter</u> ​ - Attribute Type and Attribute Value**

        -   These parameters are required parameters. They will be used to retrieve specific
            indicator results based on the provided values.
        -   **Examples:**
            -   Get indicator matching a specific hash value

                -   Attribute Type = md5 (any of md5,sha1,sha256, etc.)
                -   Attribute Value= 16139ce9025274a388a4281fef65049e

                  
                  

            -   Get indicator matching a specific filename

                -   Attribute Type = filename
                -   Attribute Value= "PLEASE-CHECK”

                <u>Note</u> - In the above example, without the double quotes around the filename,
                it will search for every filename that matches 'PLEASE'. The hyphen/space will be
                considered as the end of the search value and it will search for indicators matching
                the value until the first encountered hyphen/space.

                  
                  

            -   Get indicator matching a specific source IP Address

                -   Attribute Type = ip-src
                -   Attribute Value = 111.255.198.92

                  
                  

            -   Get indicator matching a specific URL value
                -   Attribute Type = url
                -   Attribute Value=
                    http://ww1.gadmobs.com/?subid1=bf5b0786-272c-11e9-b8c7-e15edf920d61

                <u>Note</u> - Internally, this URL value passed within the inverted comma(for ad-hoc
                fixation) in the request parameters. Because without the inverted comma, the server
                responded with the Internal Server Error unnecessarily.

          
          

    -   **<u>Action Parameter</u> ​ - Limit**

        -   This parameter is used to limit the number of indicator results. The default value
            is 500. If the limit is not provided, it will fetch by default 500 indicator results.

          
          

    -   **<u>Notes</u> -** This action is not working with the valid value of IoC type which
        consists of pipe symbol(\|) in its name. In case of searching the IoC of that type, you can
        use \[run query\] or \[list indicators\] actions by providing an appropriate query in the
        "Query" action parameter. Below are the examples:

        <u>For \[run query\] action</u> :  
          
        Search for IoC value which consists of pipe symbol(\|) in the IoC attribute type

        -   <u>Usage</u> :
        -   Query = +basetypes:indicator_attribute +type:"\<ioc_type>" +value.\\\*:\<ioc_value>

          

        -   <u>Example</u> :
        -   Query = +basetypes:indicator_attribute +type:"ip-dst\|port" +value.\\\*:5.79.68.110\|80

        <u>For \[list indicators\] action</u> :  
          
        Search for IoC value which consists of pipe symbol(\|) in the IoC attribute type

        -   <u>Usage</u> :
        -   Attribute Types = \<ioc_type>
        -   Query = +value.\\\*:\<ioc_value>

          

        -   <u>Example</u> :
        -   Attribute Types = ip-dst\|port
        -   Query = +value.\\\*:"5.79.68.110\|80"

      

4.  ### List Reports

    -   **<u>Action Parameter</u> ​ - Limit**

        -   This is an optional parameter. It is used to limit the number of fetched intelligence
            reports. The default value is 500. If the limit is not provided, it will fetch by
            default 500 intelligence reports.

          
          
        **<u>Note</u> -** Based on the current API analysis, the endpoint for this action fetches a
        huge set of data. Hence, the action run might take more time for a larger limit value.

      

5.  ### Get Report

    -   **<u>Action Parameter</u> ​ - Report ID**
        -   This is a required parameter. It is a Flashpoint intelligence report ID.
        -   **Examples:**
            -   Fetch an intelligence report having the provided report ID value
                -   Report ID = wrh9BCZETzu3AO3CUopOlw

      

6.  ### List Related Reports

    -   **<u>Action Parameter</u> ​ - Report ID**

        -   This is a required parameter. It is a Flashpoint intelligence report ID.
        -   **Examples:**
            -   Fetch default 500 related intelligence reports for the provided report ID
                -   Report ID = wrh9BCZETzu3AO3CUopOlw
                -   Limit = Keep it empty

          
          

    -   **<u>Action Parameter</u> ​ - Limit**

        -   This is an optional parameter. It is used to limit the number of fetched intelligence
            reports. The default value is 500. If the limit is not provided, it will fetch by
            default 500 intelligence reports.

          
          
        **<u>Note</u> -** Based on the current API analysis, the endpoint for this action fetches a
        huge set of data. Hence, the action run might take more time for a larger limit value.

      

7.  ### Get Compromised Credentials

    -   **<u>Action Parameter</u> ​ - Filter**

        -   This parameter will be used for filtering the data of credentials sightings on the
            Flashpoint instance. It is an optional parameter. If not given, it will get all the
            compromised credentials. A few sample values of the filter action parameter are listed
            below.
            -   +is_fresh:true (search for only new credential sightings)
            -   +breach.first_observed_at.date-time:\[now-30d TO now\] (search for credential
                sightings which are discovered in the last month based on the date provided from the
                source of this credential sightings data)
            -   +breach.fpid:nIbeDs_VXyKedBmuhFEaGQ (search for all credential sightings in a
                Breach)
            -   +email:username (search for a username)
            -   +email.keyword:username@domain.com (search for an email address)
            -   +domain.keyword:domain.com (search for credentials sightings data of a particular
                domain)
        -   **Examples:**
            -   Search for credential sightings of the given domain and that are discovered in the
                last month based on the date provided from the source of this credential sightings
                data
                -   Filter = +domain.keyword:domain.com+breach.first_observed_at.date-time:\[now-30d
                    TO now\]
            -   Search for credential sightings of the given domain and that are discovered in the
                last month based on the date of indexing of the data into the Flashpoint server
                -   Filter = +domain.keyword:domain.com+header\_.indexed_at:\[now-30d TO now\]
            -   Search for credential sightings which are discovered in the last month based on the
                date of indexing of the data into the Flashpoint server
                -   Filter = +header\_.indexed_at:\[now-30d TO now\]
            -   Search for credential sightings which are discovered in between the provided
                timestamps based on the date provided from the source of this credential sightings
                data
                -   Filter = +breach.first_observed_at.timestamp:\[1234567890 TO 1234567890\]
        -   **Usage:**
            -   For making filter parameter value
                -   Query= +basetypes:credential-sighting\<filter>

                Here, the filter is any supported values by the search API endpoint.

          
          

    -   **<u>Action Parameter</u> ​ - Limit**
        -   This parameter is used to limit the number of fetched compromised credentials. The
            default value is 500. If the limit is not provided, it will fetch by default 500
            compromised credentials. The internal pagination logic for fetching a large number of
            compromised credentials implements the scrolling session-based Credentials All Search
            APIs.

      

8.  ### Run Query

    -   **<u>Action Parameter</u> ​ - Query**

        -   This parameter will be used to search across all fields in the marketplace data by
            appending terms to it or limit searches to individual fields by appending \<field
            name>:\<value> to the ‘Query’ parameter. The queries supported by action are listed
            below.
            -   Credential breach queries (+basetypes:breach)
            -   CVE queries (+basetypes:cve)
            -   Card queries (+basetypes:card)
            -   Paste queries (+basetypes:paste)
            -   Chat queries (+basetypes:generic-product)
            -   Indicator attribute queries (+basetypes:indicator_attribute)
            -   Credential sightings queries (+basetypes:credential-sighting)
            -   Vulnerability queries (+basetypes:vulnerability)
            -   Conversation queries (+basetypes:conversation)
            -   Chan queries (+basetypes:chan)
            -   Blog queries (+basetypes:blog)
            -   Reddit queries (+basetypes:reddit)
            -   Forum queries (+basetypes:forum)
        -   **Examples:**
            -   Search for "Analyst Research" breaches
                -   Query= +basetypes:breach+source_type:"Analyst Research"
            -   Search for "testing" across all free-form fields (message body, channel profile,
                channel name, and user name) for chat queries
                -   Query = +basetypes:chat+testing
            -   Search for credential sightings of the given domain and that are discovered in the
                last month based on the date provided from the source of this credential sightings
                data
                -   Filter =
                    +basetypes:credential-sighting+domain.keyword:domain.com+breach.first_observed_at.date-time:\[now-30d
                    TO now\]
            -   Search for all search results which are discovered in the last month based on the
                date of indexing of the data into the Flashpoint server
                -   Filter = +header\_.indexed_at:\[now-30d TO now\]
            -   Filter all search results by ISO date/time range based on the date provided from the
                source of this search data
                -   Query = +created_at.date-time:\["2018-10-24T10:05:10+00:00" TO
                    "2018-10-26T10:05:10+00:00"\]
            -   Filter results by Unix time for all paste results based on the date provided from
                the source of this paste search data
                -   Query = +basetypes:paste+created_at.timestamp:\[1234567890 TO 1234567890\]
        -   **Usage:**
            -   For making query parameter value
                -   Query= \<basetypes_query>\<search_filter>

                Here, basetypes_query and search_filter are any supported values by the search API
                endpoint.

          
          

    -   **<u>Action Parameter</u> ​ - Limit**
        -   This parameter is used to limit the number of fetched all search data. The default value
            is 500. If the limit is not provided, it will fetch by default 500 search items. The
            internal pagination logic for fetching a large number of search items implements the
            scrolling session-based All Search APIs.

      
