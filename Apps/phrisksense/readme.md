[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "    Copyright (c) RiskSense, 2020"
[comment]: # ""
[comment]: # "    This unpublished material is proprietary to RiskSense."
[comment]: # "    All rights reserved. The methods and"
[comment]: # "    techniques described herein are considered trade secrets"
[comment]: # "    and/or confidential. Reproduction or distribution, in whole"
[comment]: # "    or in part, is forbidden except by express written permission"
[comment]: # "    of RiskSense."
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Explanation of the Asset Configuration Parameters

The asset configuration parameters affect \[test connectivity\] and all the other actions of the
application. Below are the explanation and usage of all these parameters.

-   **Base URL:** The URL used to connect with the RiskSense server. It represents the RiskSense
    platform's API base URL where /api/v1 represents the API version. Example:
    https://platform.risksense.com/api/v1
-   **Client Name:** Name of the client. All the actions will be executed for this client.
-   **API Token:** It is the API token of the user.
-   **Verify Server Certificate:** Validate server certificate
-   **Number of Retries:** The value of this parameter defines the number of attempts for which the
    action will keep on retrying if the RiskSense API continuously returns the “500 Internal Server
    Error” or "429 Too Many Requests". If the intermittent error gets eliminated before the number
    of retries gets exhausted, then, the action execution will continue along its workflow and if
    the intermittent error is still persistent and all the number of retries is exhausted, then, the
    action will fail with the latest error message being displayed. The parameter expects a positive
    integer value as input. If the parameter is not provided, then 2 (default value) will be
    considered as the value for the parameter.
-   **Backoff Factor:** A backoff factor to apply between attempts after the second try (most errors
    are resolved immediately by a second try without a delay). The parameter expects a valid float
    value as input. If the parameter is not provided, then 0.3 (default value) will be considered as
    the value for the parameter.
    -   Sleep time calculation: {backoff factor} \* (2 \*\* ({number of total retries} - 1))
        seconds.

## Steps to generate the API token

-   Go to the RiskSense platform and open 'User Settings'.
-   Navigate to the 'API TOKENS' section and click on the 'Generate' button.
-   Enter the name of the new token.

## Explanation of the RiskSense Actions' Parameters

-   ### Test Connectivity (Action Workflow Details)

    -   This action will test the connectivity of the Phantom server to the RiskSense instance by
        making an initial API call to the Client API using the provided asset configuration
        parameters.
    -   The action validates the provided asset configuration parameters. Based on the API call
        response, the appropriate success and failure message will be displayed when the action gets
        executed.

-   ### List Users

    -   **<u>Action Parameter:</u> Max Results**

          

        -   This parameter allows the user to limit the number of results. If the parameter is not
            provided, it will fetch by default 1000 results. The internal pagination logic is
            applied for fetching a large number of results.

    -   **Example:**
        -   List 600 users
            -   Max Results = 600

-   ### List Tags

    -   **<u>Action Parameter:</u> Max Results**

          

        -   This parameter allows the user to limit the number of results. If the parameter is not
            provided, it will fetch by default 1000 results. The internal pagination logic is
            applied for fetching a large number of results.

    -   **Example:**
        -   List 600 tags
            -   Max Results = 600

-   ### List Hosts

    -   **<u>Action Parameter:</u> Field Name**

          

        -   This parameter allows the user to filter the result data set based on the host
            attributes provided as input. It allows the comma-separated values of the host
            attributes. The user can get the list of valid host attributes by executing the List
            Filter Attributes action. The uid of the filter attribute must be provided here.  
            Here are a few examples of host attributes: hostName, ipAddress, criticality, rs3,
            assessment_labels.

    -   **<u>Action Parameter:</u> Operator**

          

        -   This parameter allows the user to provide the operator which will be applied to the
            value(s) provided in the Fieldname parameter. It allows the comma-separated values of
            valid operators. The user can get the list of valid operators by executing the List
            Filter Attributes action.  
            Here are a few examples of the operators:  
            -   **EXACT -** Filter records exactly matching the criteria.
            -   **IN -** Filter records matching any of the comma-separated values.
            -   **LIKE -** Filter the records with fieldname’s value having the string provided by
                the user.
            -   **RANGE -** Filter the records with fieldname’s value falling in the numerical/date
                range provided.

    -   **<u>Action Parameter:</u> Value**

          

        -   This parameter allows the user to provide the value of the host attributes, which is
            mentioned in the Fieldname parameter, to be considered for filter criteria. It expects a
            JSON formatted list of values.

    -   **<u>Action Parameter:</u> Exclusivity**

          

        -   This parameter allows the user to determine whether to fetch the results that are
            matching the filter criteria (defined by the Fieldname, Operator, and Value parameter)
            or to fetch the results that are not matching the filter criteria. It allows the
            comma-separated boolean values (true/false).

    -   **<u>Action Parameter:</u> Sort By**

          

        -   This parameter allows the user to provide the fieldname by which to sort the records. It
            allows the comma-separated values of valid host attributes. If multiple host attributes
            are provided, then multiple sorting will be applied starting from the left-most host
            attribute.
        -   **Note -** If an incorrect attribute value is provided in this parameter, then the
            sorting of the results by that attribute will be ignored.

    -   **<u>Action Parameter:</u> Sort Direction**

          

        -   This parameter allows the user to provide sorting order to be applied to the host
            attribute provided in the Sort By parameter. It allows the comma-separated values of
            valid Sort Direction(s) (ASC/DESC).

    -   **<u>Action Parameter:</u> Page**

          

        -   This parameter allows the user to provide the index of the page from where the results
            are to be fetched. It expects a numeric value as an input. If not provided, then 0 will
            be considered as the starting index of the page.

    -   **<u>Action Parameter:</u> Max Results**

          

        -   This parameter allows the user to limit the number of results. If the parameter is not
            provided, it will fetch by default 1000 results. The internal pagination logic is
            applied for fetching a large number of results.

    -   **Note:**

          

        -   The Fieldname, Operator, Value, and Exclusivity parameters are used to create a filter.
            So, the length of these four parameters must be the same.
        -   Similarly, a sorting direction is required for a host attribute that is used for
            sorting. So, the length of Sort By and Sort Direction parameters must be the same.

    -   **Examples:**
        -   List the hosts having hostname like a “test”, sorted based on the ID in descending
            order.
            -   Fieldname = hostName
            -   Operator = LIKE
            -   Value = \[“test”\]
            -   Exclusivity = false
            -   Sort By = id
            -   Sort Direction = DESC
        -   List the hosts that are not discovered on 2014-05-01. Results are sorted first by rs3 in
            ascending order and then by ID in ascending order.
            -   Fieldname = discoveredOn
            -   Operator = EXACT
            -   Value = \[“2014-05-01”\]
            -   Exclusivity = true
            -   Sort By = rs3, id
            -   Sort Direction = ASC, ASC
            -   **Note:** The date format is in YYYY-MM-DD. Also while using the EXACT operator,
                note that the expected results will be fetched only if the value provided in the
                Value parameter will be exactly matched. So, make sure that there are no unnecessary
                spaces in the Value parameter.
        -   List the hosts having ID 1 or 2 or 3.
            -   Fieldname = id
            -   Operator = IN
            -   Value = \[“1,2,3”\]
            -   Exclusivity = false
            -   **Note:** While using IN operator, note that the expected results will be fetched
                only if the value provided in the Value parameter will be exactly matched. So, make
                sure that there is no space provided between the comma and the value. Example:
                Incorrect Value = \[“1,\<space>2,3\<space>”\], Correct Value = \[“1,2,3”\]
        -   List the hosts having criticality in the range of 2 to 5. The maximum results to be
            fetched are 200.
            -   Fieldname = criticality
            -   Operator = RANGE
            -   Value = \[“2,5”\]
            -   Exclusivity = false
            -   Max Results = 200
        -   List the hosts having hostname like a test and rs3 value 850.
            -   Fieldname = hostName,rs3
            -   Operator = LIKE, EXACT
            -   Value = \[“test”, “850”\]
            -   Exclusivity = false, false

-   ### List Apps

    -   **<u>Action Parameter:</u> Field Name**

          

        -   This parameter allows the user to filter the result data set based on the application
            attributes provided as input. It allows the comma-separated values of application
            attributes. The user can get the list of valid application attributes by executing the
            List Filter Attributes action. The uid of the filter attribute must be provided here.  
            Here are a few examples of application attributes: name, description, criticality,
            assessment_labels, discovered_on.

    -   **<u>Action Parameter:</u> Operator**

          

        -   This parameter allows the user to provide the operator which will be applied to the
            value(s) provided in the Fieldname parameter. It allows the comma-separated values of
            valid operators. The user can get the list of valid operators by executing the List
            Filter Attributes action.  
            Here are a few examples of the operators:  
            -   **EXACT -** Filter records exactly matching the criteria.
            -   **IN -** Filter records matching any one of the comma-separated values.
            -   **LIKE -** Filter the records with fieldname’s value having the string provided by
                the user.
            -   **RANGE -** Filter the records with fieldname’s value falling in the numerical/date
                range provided.

    -   **<u>Action Parameter:</u> Value**

          

        -   This parameter allows the user to provide the value of the application attributes, which
            are mentioned in the Fieldname parameter, to be considered for filter criteria. It
            expects a JSON formatted list of values.

    -   **<u>Action Parameter:</u> Exclusivity**

          

        -   This parameter allows the user to determine whether to fetch the results that are
            matching the filter criteria (defined by the Fieldname, Operator, and Value parameter)
            or to fetch the results that are not matching the filter criteria. It allows the
            comma-separated boolean values (true/false).

    -   **<u>Action Parameter:</u> Sort By**

          

        -   This parameter allows the user to provide the fieldname by which to sort the records. It
            allows the comma-separated values of valid application attributes. If multiple
            application attributes are provided, then multiple sorting will be applied starting from
            the left-most application attribute.
        -   **Note -** If an incorrect attribute value is provided in this parameter, then the
            sorting of the results by that attribute will be ignored.

    -   **<u>Action Parameter:</u> Sort Direction**

          

        -   This parameter allows the user to provide sorting order to be applied to the application
            attribute provided in the Sort By parameter. It allows the comma-separated values of
            valid Sort Direction(s) (ASC/DESC).

    -   **<u>Action Parameter:</u> Page**

          

        -   This parameter allows the user to provide the index of the page from where the results
            are to be fetched. It expects a numeric value as an input. If not provided, then 0 will
            be considered as the starting index of the page.

    -   **<u>Action Parameter:</u> Max Results**

          

        -   This parameter allows the user to limit the number of results. If the parameter is not
            provided, it will fetch by default 1000 results. The internal pagination logic is
            applied for fetching a large number of results.

    -   **Note:**

          

        -   The Fieldname, Operator, Value, and Exclusivity parameters are used to create a filter.
            So, the length of these four parameters must be the same.
        -   Similarly, a sorting direction is required for a host attribute that is used for
            sorting. So, the length of Sort By and Sort Direction parameters must be the same.

    -   **Examples:**
        -   List the applications having a name like a “test”, sorted based on the ID in descending
            order.
            -   Fieldname = name
            -   Operator = LIKE
            -   Value = \[“test”\]
            -   Exclusivity = false
            -   Sort By = id
            -   Sort Direction = DESC
        -   List the applications having the group name “Default Group”. Results are sorted first by
            name in ascending order and then by ID in descending order.
            -   Fieldname = group_names
            -   Operator = EXACT
            -   Value = \[“Default Group”\]
            -   Exclusivity = false
            -   Sort By = name, id
            -   Sort Direction = ASC, DESC
        -   List the applications having ID 1 or 2 or 3.
            -   Fieldname = id
            -   Operator = IN
            -   Value = \[“1,2,3”\]
            -   Exclusivity = false
        -   List the applications having asset criticality in the range of 2 to 5. The maximum
            results to be fetched are 200.
            -   Fieldname = criticality
            -   Operator = RANGE
            -   Value = \[“2,5”\]
            -   Exclusivity = false
            -   Max Results = 200
        -   List the applications having a name like a test and criticality is one of 4,5,6.
            -   Fieldname = name,criticality
            -   Operator = LIKE, IN
            -   Value = \[“test”, “4,5,6”\]
            -   Exclusivity = false, false

-   ### List Unique Findings

    -   **Note:** RiskSense is rewriting the API which is being used for this action.

    -   **<u>Action Parameter:</u> Field Name**

          

        -   This parameter allows the user to filter the result data set based on the unique host
            finding attributes provided as input. It allows the comma-separated values of unique
            host finding attributes. The uid of the filter attribute must be provided here.  
            Here are a few examples of host attributes: title, group_names, severity,
            assessment_labels.

    -   **<u>Action Parameter:</u> Operator**

          

        -   This parameter allows the user to provide the operator which will be applied to the
            value(s) provided in the Fieldname parameter. It allows the comma-separated values of
            valid operators. The user can get the list of valid operators by executing the List
            Filter Attributes action.  
            Here are a few examples of the operators:  
            -   **EXACT -** Filter records exactly matching the criteria.
            -   **IN -** Filter records matching any one of the comma-separated values.
            -   **LIKE -** Filter the records with fieldname’s value having the string provided by
                the user.
            -   **RANGE -** Filter the records with fieldname’s value falling in the numerical/date
                range provided.

    -   **<u>Action Parameter:</u> Value**

          

        -   This boolean parameter allows the user to provide the value of the unique host finding
            attributes, which is mentioned in the Fieldname parameter, to be considered for filter
            criteria. It expects a JSON formatted list of values.

    -   **<u>Action Parameter:</u> Exclusivity**

          

        -   This parameter allows the user to determine whether to fetch the results that are
            matching the filter criteria (defined by the Fieldname, Operator, and Value parameter)
            or to fetch the results that are not matching the filter criteria. It allows the
            comma-separated boolean values (true/false).

    -   **<u>Action Parameter:</u> Sort By**

          

        -   This parameter allows the user to provide the fieldname by which to sort the records. It
            allows the comma-separated values of valid unique host finding attributes. If multiple
            unique host finding attributes are provided, then multiple sorting will be applied
            starting from the left-most unique host finding attribute.
        -   **Note -** If an incorrect attribute value is provided in this parameter, then the
            sorting of the results by that attribute will be ignored.

    -   **<u>Action Parameter:</u> Sort Direction**

          

        -   This parameter allows the user to provide sorting order to be applied to the unique host
            finding attribute provided in the Sort By parameter. It allows the comma-separated
            values of valid Sort Direction(s) (ASC/DESC).

    -   **<u>Action Parameter:</u> Page**

          

        -   This parameter allows the user to provide the index of the page from where the results
            are to be fetched. It expects a numeric value as an input. If not provided, then 0 will
            be considered as the starting index of the page.

    -   **<u>Action Parameter:</u> Max Results**

          

        -   This parameter allows the user to limit the number of results. If the parameter is not
            provided, it will fetch by default 1000 results. The internal pagination logic is
            applied for fetching a large number of results.

    -   **Note:**

          

        -   The Fieldname, Operator, Value, and Exclusivity parameters are used to create a filter.
            So, the length of these four parameters must be the same.
        -   Similarly, a sorting direction is required for a host attribute that is used for
            sorting. So, the length of Sort By and Sort Direction parameters must be the same.

    -   **Examples:**
        -   List the unique host findings having a title like a “Solaris”, sorted based on the
            severity in descending order.
            -   Fieldname = title
            -   Operator = LIKE
            -   Value = \[“Solaris”\]
            -   Exclusivity = false
            -   Sort By =severity
            -   Sort Direction = DESC
        -   List the unique host findings having the Assessment “First Assessment”. Results are
            sorted first by title in ascending order and then by severity in descending order.
            -   Fieldname = assessment_labels
            -   Operator = EXACT
            -   Value = \[“First Assessment”\]
            -   Exclusivity = false
            -   Sort By = title, severity
            -   Sort Direction = ASC, DESC
        -   List the unique host findings having group ID 1 or 2 or 3.
            -   Fieldname = group_ids
            -   Operator = IN
            -   Value = \[“1,2,3”\]
            -   Exclusivity = false
        -   List the unique host findings having severity in the range of 2.0 to 5.0, maximum
            results to be fetched are 200.
            -   Fieldname = severity
            -   Operator = RANGE
            -   Value = \[“2.0,5.0”\]
            -   Exclusivity = false
            -   Max Results = 200
        -   List the unique host findings having a title like a “Solaris” and severity is one of
            4.0,5.0,6.0.
            -   Fieldname = title,severity
            -   Operator = LIKE, IN
            -   Value = \[“Solaris”, “4.0,5.0,6.0”\]
            -   Exclusivity = false, false

-   ### List Host Findings

    -   **<u>Action Parameter:</u> Field Name**

          

        -   This parameter allows the user to filter the result data set based on the host finding
            attributes provided as input. It allows the comma-separated values of host finding
            attributes. The user can get the list of valid host finding attributes by executing the
            List Filter Attributes action. The uid of the filter attribute must be provided here.  
            Here are a few examples of host finding attributes: state, id, criticality, riskRating,
            assessment_labels.

    -   **<u>Action Parameter:</u> Operator**

          

        -   This parameter allows the user to provide the operator which will be applied to the
            value(s) provided in the Fieldname parameter. It allows the comma-separated values of
            valid operators. The user can get the list of valid operators by executing the List
            Filter Attributes action.  
            Here are a few examples of the operators:  
            -   **EXACT -** Filter records exactly matching the criteria.
            -   **IN -** Filter records matching any one of the comma-separated values.
            -   **LIKE -** Filter the records with fieldname’s value having the string provided by
                the user.
            -   **RANGE -** Filter the records with fieldname’s value falling in the numerical/date
                range provided.

    -   **<u>Action Parameter:</u> Value**

          

        -   This parameter allows the user to provide the value of the host finding attributes,
            which is mentioned in the Fieldname parameter, to be considered for filter criteria. It
            expects a JSON formatted list of values.

    -   **<u>Action Parameter:</u> Exclusivity**

          

        -   This parameter allows the user to determine whether to fetch the results that are
            matching the filter criteria (defined by the Fieldname, Operator, and Value parameter)
            or to fetch the results that are not matching the filter criteria. It allows the
            comma-separated boolean values (true/false).

    -   **<u>Action Parameter:</u> Status**

          

        -   This parameter allows the user to determine whether to fetch the open host findings or
            the closed host findings. It expects a string value (Valid values: Open/Closed).

    -   **<u>Action Parameter:</u> Sort By**

          

        -   This parameter allows the user to provide the fieldname by which to sort the records. It
            allows the comma-separated values of valid host finding attributes. If multiple host
            finding attributes are provided, then multiple sorting will be applied starting from the
            left-most host attribute.
        -   **Note -** If an incorrect attribute value is provided in this parameter, then the
            sorting of the results by that attribute will be ignored.

    -   **<u>Action Parameter:</u> Sort Direction**

          

        -   This parameter allows the user to provide sorting order to be applied to the host
            finding attribute provided in the Sort By parameter. It allows the comma-separated
            values of valid Sort Direction(s) (ASC/DESC).

    -   **<u>Action Parameter:</u> Page**

          

        -   This parameter allows the user to provide the index of the page from where the results
            are to be fetched. It expects a numeric value as an input. If not provided, then 0 will
            be considered as the starting index of the page.

    -   **<u>Action Parameter:</u> Max Results**

          

        -   This parameter allows the user to limit the number of results. If the parameter is not
            provided, it will fetch by default 1000 results. The internal pagination logic is
            applied for fetching a large number of results.

    -   **Note:**

          

        -   The Fieldname, Operator, Value, and Exclusivity parameters are used to create a filter.
            So, the length of these four parameters must be the same.
        -   Similarly, a sorting direction is required for a host attribute that is used for
            sorting. So, the length of Sort By and Sort Direction parameters must be the same.

    -   **Examples:**
        -   List the host findings having a title like a “test”, sorted based on the ID in
            descending order.
            -   Fieldname = title
            -   Operator = LIKE
            -   Value = \[“test”\]
            -   Exclusivity = false
            -   Sort By = id
            -   Sort Direction = DESC
        -   List the host findings having the state “assigned”. Results are sorted first by
            riskRating in descending order and then by ID in ascending order.
            -   Fieldname = state
            -   Operator = EXACT
            -   Value = \[“assigned”\]
            -   Exclusivity = false
            -   Sort By = riskRating, id
            -   Sort Direction = DESC, ASC
        -   List the host findings having ID 1 or 2 or 3.
            -   Fieldname = id
            -   Operator = IN
            -   Value = \[“1,2,3”\]
            -   Exclusivity = false
        -   List the host findings having asset criticality in the range of 2 to 5. The maximum
            results to be fetched are 200.
            -   Fieldname = criticality
            -   Operator = RANGE
            -   Value = \[“2,5”\]
            -   Exclusivity = false
            -   Max Results = 200
        -   List the host findings having status “Closed” and criticality is NOT in the range of 4
            to 8.
            -   Fieldname = criticality
            -   Operator = RANGE
            -   Value = \[“4,8”\]
            -   Exclusivity = true
            -   Status = Closed

-   ### List Filter Attributes

    -   **<u>Action Parameter:</u> Asset Type**

          

        -   Type of the asset of which the filter attributes will be fetched. Example: host,
            hostFinding, application, applicationFinding, tag, user.

    -   **Examples:**
        -   List filter attributes of host asset type.
            -   Asset Type = host
        -   List filter attributes of host finding asset type.
            -   Asset Type = hostFinding
        -   List filter attributes of application asset type.
            -   Asset Type = application

-   ### Get Hosts

    -   **<u>Action Parameter:</u> Host ID**

          

        -   The unique host ID of the host. The Host ID is either known by RiskSense users or it can
            be fetched from the output of List Hosts action.

    -   **<u>Action Parameter:</u> Host Name**

          

        -   The hostname of the host. Host Name is either known by RiskSense users or it can be
            fetched from the output of List Hosts action.

    -   **Note:**

          

        -   If both the parameters (Host Name and Host ID) are provided, then the action will be
            executed based on the host ID.

    -   **Examples:**
        -   Get the host(s) having hostname “image1”
            -   Host Name= image1
        -   Get the host(s) having ID “7”
            -   Host ID = 7
        -   Hostname = “image1” and ID = “7”
            -   Host Name = image1
            -   Host ID = 7

-   ### Get Host Finding

    -   **<u>Action Parameter:</u> Host Finding ID**

          

        -   The unique host finding ID of the host finding. Host finding ID is either known by
            RiskSense users or it can be fetched from the output of List Host Findings action.

    -   **Examples:**
        -   Get the host finding having ID “6”
            -   Host Finding ID = 6

-   ### Get App

    -   **<u>Action Parameter:</u> App ID**

          

        -   The unique application ID of the application. The Application ID is either known by
            RiskSense users or it can be fetched from the output of List Apps action.

    -   **Examples:**
        -   Get the application having ID “5”
            -   Application ID = 5

-   ### List Vulnerabilities

    -   **<u>Action Parameter:</u> Host Finding ID**

          

        -   The host finding ID for which the vulnerabilities are to be fetched. Host finding ID is
            either known by RiskSense users or it can be fetched from the output of List Hosts
            action.

    -   **Examples:**
        -   List the vulnerabilities of the host finding having ID “6”
            -   Host Finding ID = 6

-   ### Tag Asset

    -   **Note:** This app supports the below tag types.

          

        -   CUSTOM
        -   LOCATION
        -   COMPLIANCE
        -   REMEDIATION
        -   PEOPLE
        -   SCANNER
        -   CMDB

    -   **<u>Action Parameter:</u> Tag Name**

          

        -   This parameter allows the user to provide the name of an existing tag or to provide the
            name of a new tag, which will get associated with the assets. Users can get the list of
            all the available tags using the List Tags action.

    -   **<u>Action Parameter:</u> Asset Type**

          

        -   Type of the asset to which the tag will be applied. Example: host, hostFinding,
            application, applicationFinding.

    -   **<u>Action Parameter:</u> Field Name**

          

        -   This parameter allows the user to filter the result data set based on the asset type’s
            attributes provided as input. It allows the comma-separated values of the attributes.
            The user can get the list of valid asset types’ attributes by executing the List Filter
            Attributes action. The uid of the filter attribute must be provided here.  
            Here are a few examples: name, title, severity, rs3, riskRating, group_names,
            description, criticality, assessment_labels, discovered_on.

    -   **<u>Action Parameter:</u> Operator**

          

        -   This parameter allows the user to provide the operator which will be applied to the
            value(s) provided in the Fieldname parameter. It allows the comma-separated values of
            valid operators. The user can get the list of valid operators by executing the List
            Filter Attributes action.  
            Here are a few examples of the operators:  
            -   **EXACT -** Filter records exactly matching the criteria.
            -   **IN -** Filter records matching any one of the comma-separated values.
            -   **LIKE -** Filter the records with fieldname’s value having the string provided by
                the user.
            -   **RANGE -** Filter the records with fieldname’s value falling in the numerical/date
                range provided.

    -   **<u>Action Parameter:</u> Value**

          

        -   This parameter allows the user to provide the value of the asset type’s attributes,
            which are mentioned in the Fieldname parameter, to be considered for filter criteria. It
            expects a JSON formatted list of values.

    -   **<u>Action Parameter:</u> Exclusivity**

          

        -   This parameter allows the user to determine whether to fetch the results that are
            matching the filter criteria (defined by the Fieldname, Operator, and Value parameter)
            or to fetch the results that are not matching the filter criteria. It allows the
            comma-separated boolean values (true/false).

    -   **<u>Action Parameter:</u> Create New Tag**

          

        -   This parameter allows the user to create a new tag if the provided tag name in the Tag
            Name parameter is not available on the RiskSense platform.
        -   **Note -** This parameter will only come into picture when the provided tag name is not
            available.

    -   **<u>Action Parameter:</u> Tag Type**

          

        -   Type of the new tag. This parameter is used to create a new tag.
        -   **Note -** This parameter is required when the provided tag name is not available and
            the Create New Tag parameter is enabled.

    -   **<u>Action Parameter:</u> Tag Description**

          

        -   Description of the new tag. This parameter is used to create a new tag.
        -   **Note -** This parameter is required when the provided tag name is not available and
            the Create New Tag parameter is enabled.

    -   **<u>Action Parameter:</u> Tag Owner ID**

          

        -   Owner of the new tag. This parameter is used to create a new tag. Users can get the list
            of all the available owner IDs using the List Users action.
        -   **Note -** This parameter is required when the provided tag name is not available and
            the Create New Tag parameter is enabled.

    -   **<u>Action Parameter:</u> Tag Color**

          

        -   Color of the new tag. This parameter is used to create a new tag.
        -   **Note -** This parameter is required when the provided tag name is not available and
            the Create New Tag parameter is enabled.

    -   **<u>Action Parameter:</u> Propagate To All Findings**

          

        -   It denotes if an asset tag should be applied to all its findings. This parameter is used
            to create a new tag.
        -   Propagate to all findings is a special boolean. If a tag is created at asset level
            (example: host/app level) and if the use case is to propagate those tags to associated
            findings also, then this parameter should be enabled. If not, it should be disabled.
        -   **Note -** This parameter is required when the provided tag name is not available and
            the Create New Tag parameter is enabled.

    -   **Note:**

          

        -   The Fieldname, Operator, Value, and Exclusivity parameters are used to create a filter.
            So, the length of these four parameters must be the same.

    -   **Examples:**
        -   Tag all the host findings that are in the assigned state. Tag Name = “ state assigned”.
            **Note-** Assuming that the “state assigned” tag is already available and the tag ID
            is 1234.
            -   Tag Name = state assigned
            -   Asset Type = hostFinding
            -   Fieldname = state
            -   Operator = EXACT
            -   Value = \[“assigned”\]
            -   Exclusivity = false
            -   Create New Tag = false
        -   Tag all the hosts having rs3 value in the range of 300-400 with a tag named “high risk”.
            If tag is not available, create new tag with Description = “high risk alert”, Tag Type=
            “CUSTOM”, Tag Color= “#648d9f”, Tag Owner ID = “321”. Also, this tag should get
            associated with all the findings of the hosts as well. **Note** - Assuming that the
            “high risk” tag is not available
            -   Tag Name = high risk
            -   Asset Type = host
            -   Fieldname = rs3
            -   Operator = RANGE
            -   Value = \[“300,400”\]
            -   Exclusivity = false
            -   Create New Tag = true
            -   Tag Type = CUSTOM
            -   Tag Description = high risk alert
            -   Tag Owner ID = 321
            -   Tag Color = “#648d9f”
            -   Propagate To All Findings = True
        -   Tag all the applications with the tag name “test tag”. **Note-** Assuming that the “test
            tag” tag is already available and the tag ID is 1233.
            -   Tag Name = test tag
            -   Asset Type = application
            -   Create New Tag = false

            **Note-** This will associate the tag named “test tag” to all the applications of the
            client (provided in the configuration parameter). Please make sure that you filter the
            assets correctly using the filter parameters (Fieldname, Operator, Value, Exclusivity).
        -   Tag all the applicationFindings with a tag named “tag application finding” **Note-**
            Assuming that the “tag application finding” tag is not available
            -   Tag Name = tag application finding
            -   Asset Type = applicationFinding
            -   Create New Tag = false

            **Note-** As the tag is not available and the user is not requesting for a new tag
            creation, the action will fail with a proper error message.
        -   Tag all the hosts having rs3 value in the range of 650-850 with a tag named “low risk”.
            If tag is not available, create new tag with Description = “low risk alert”, Tag Type=
            “CUSTOM”, Tag Color= “#648d9f”, Tag Owner ID = “321”. Also, this tag should get
            associated with all the findings of the hosts as well. **Note-** Assuming that the “low
            risk” tag is already available
            -   Tag Name = low risk
            -   Asset Type = host
            -   Fieldname = rs3
            -   Operator = RANGE
            -   Value = \[“650,850”\]
            -   Exclusivity = false
            -   Create New Tag = true
            -   Tag Type = CUSTOM
            -   Tag Description = low risk alert
            -   Tag Owner ID = 321
            -   Tag Color = “#648d9f”
            -   Propagate To All Findings = True

            **Note-** As the user is trying to create a tag which is already created, the tag will
            not get updated and the already existing tag will get associated with the filtered
            assets.
        -   Tag all the hosts having rs3 value in the range of 650-850 with a tag named “low risk”.
            If tag is not available, create new tag with Description = “low risk alert”, Tag Type=
            “CUSTOM”, Tag Color= “#648d9f”, Tag Owner ID = “321”. Also, this tag should get
            associated with all the findings of the hosts as well. **Note-** Assuming that the “low
            risk” tag does not exist and there is no asset available for the provided filter related
            input parameter (Fieldname, Operator, Exclusivity, Value).
            -   Tag Name = low risk
            -   Asset Type = host
            -   Fieldname = rs3
            -   Operator = RANGE
            -   Value = \[“650,850”\]
            -   Exclusivity = false
            -   Create New Tag = true
            -   Tag Type = CUSTOM
            -   Tag Description = low risk alert
            -   Tag Owner ID = 321
            -   Tag Color = “#648d9f”
            -   Propagate To All Findings = True

            **Note-** The new tag will not be created and won't be associated as no data is
            available for the provided filter inputs. The action will return an appropriate error
            message.
