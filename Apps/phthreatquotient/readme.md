[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "    ThreatQuotient Proprietary and Confidential"
[comment]: # "    Copyright (c) 2016-2021 ThreatQuotient, Inc. All rights reserved."
[comment]: # ""
[comment]: # "    NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc."
[comment]: # "    The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc."
[comment]: # "    and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are"
[comment]: # "    protected by trade secret or copyright law."
[comment]: # ""
[comment]: # "    Dissemination of this information or reproduction of this material is strictly forbidden unless prior"
[comment]: # "    written permission is obtained from ThreatQuotient, Inc."
[comment]: # ""
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
# <span id="Splunk_SOAR_App_0"></span> Splunk SOAR App

## <span id="Introduction_2"></span> Introduction

The Splunk SOAR App for ThreatQ allows a user to execute a variety of actions on ThreatQ from a
Phantom playbook.  
With ThreatQ as a single source of truth for Threat Intelligence, you will be able to accurately
triage a sighting, and ultimately, make a quick decision.  
This will allow your analysts to focus on what’s important to their organization, instead of getting
inundated with sightings of non-malicious indicators.  
The goal being, to increase your response time and improve your ROI.

## <span id="Installation_9"></span> Installation

This section will describe how you can install the app into your Phantom instance

**WARNING** : This release (v2.x) has fundamentally changed how the App operates!  
If you are upgrading from v1.x, please refer to the
`     App Instructions -> Upgrading from 1.x to 2.x    ` section!

1.  Download the Splunk SOAR App (tar.gz) for ThreatQ via any of these methods:
    -   Marketplace
    -   Download Center
    -   Splunkbase
2.  Login to your Phantom instance
3.  In your navigation dropdown, select `      Apps     `
4.  Click on the `      Install App     ` button at the top right of your Apps page
5.  Select the Splunk SOAR App for ThreatQ tar.gz file

## <span id="Configuration_26"></span> Configuration

Once the app is installed, you will see a ThreatQ logo on your Apps page. If you do not, you can
search for `     ThreatQ    ` in the search bar

1.  Next to the ThreatQ logo, click on the `      Configure New Asset     ` button
2.  Fill out the following information in the `      Asset Info     ` tab, and save:
    -   **Asset name** : threatq
    -   **Asset description** : Integration with the ThreatQ Threat Intelligence Platform
    -   **Product vendor** : ThreatQuotient
    -   **Product name** : ThreatQ
3.  Fill out the following information in the `      Asset Settings     ` tab, and save:
    -   **Server IP/Hostname** : Enter the hostname or IP address for your ThreatQ instance
    -   **Client ID** : Enter your API Credentials found under your `        My Account       ` page
        in ThreatQ
    -   **Username** : Enter your username to authenticate with ThreatQ
    -   **Password** : Enter your password to authenticate with ThreatQ
    -   **Trust SSL Certificate?** : Check this box if you want to trust the ThreatQ certificate
        (default: checked)
4.  Click the `      Test Connectivity     ` button after saving to test your connection information
    -   If this test fails, verify your Phantom instance has access to your ThreatQ instance, as
        well as make sure your credentials are correct
5.  The ThreatQ App should now be configurable within a playbook!

## <span id="App_Actions_46"></span> App Actions

The following actions come out of the box with the Splunk SOAR App for ThreatQ

### <span id="Query_Indicators_50"></span> Query Indicators

**Name:** query_indicators

**Description:** Query a list of indicators against ThreatQ

**Parameters:**

-   indicator_list: A list of indicator values to query

### <span id="Create_Indicators_59"></span> Create Indicators

**Name:** create_indicators

**Description:** Create indicators in ThreatQ

**Parameters:**

-   indicator_list: A list of indicators to add

**Formatting:**  
See *Details \> Formatting an Indicator List*

### <span id="Create_Task_71"></span> Create Task

**Name:** create_task

**Description:** Create a task in ThreatQ

**Parameters:**

-   task_name: The name of the task to create
-   assigned_to: The email or username of a user within ThreatQ to assign the task to
-   task_status: The task status in ThreatQ
-   task_priority: The task priority in ThreatQ
-   task_description: The description of the task
-   indicator_list: A list of indicators to relate to the task

**Formatting:**  
See *Details \> Formatting an Indicator List*

### <span id="Create_Event_88"></span> Create Event

**Name:** create_event

**Description:** Creates an event in ThreatQ, based on the container metadata in Phantom

**Parameters:**

-   event_type: The type of event to create in ThreatQ
-   indicator_list: A list of indicators to relate to the event

**Formatting:**  
See *Details \> Formatting an Indicator List*

### <span id="Create_Spearphish_101"></span> Create Spearphish

**Name:** upload_spearphish

**Description:** Creates a spearphish event in ThreatQ, based on a spearphish email in the Phantom
vault

**Parameters:**

-   vault_id: The ID of an email file in your Phantom vault
-   indicator_status: The indicator status for any parsed indicators from the spearphish

### <span id="Upload_File_111"></span> Upload File

**Name:** upload_file

**Description:** Creates a file (attachment) in ThreatQ

**Parameters:**

-   vault_id: The ID of the file in your Phantom vault
-   parse_for_indicators: Whether or not to parse the file for indicators
-   default_indicator_status: The indicator status for any parsed indicators from the file

### <span id="Start_Investigation_122"></span> Start Investigation

**Name:** start_investigation

**Description:** Start an investigation within ThreatQ

**Parameters:**

-   investigation_name: The name of the investigation to create in ThreatQ
-   investigation_priority: The priority of the investigation in ThreatQ
-   investigation_description: The description of the investigation in ThreatQ
-   investigation_visibility: Whether the investigation is public or private
-   indicator_list: A list of indicators to relate to the investigation

**Formatting:**  
See *Details \> Formatting an Indicator List*

### <span id="Create_Adversaries_138"></span> Create Adversaries

**Name:** create_adversaries

**Description:** Create adversaries in ThreatQ

**Parameters:**

-   adversary_list: A list of adversary names to create in ThreatQ

### <span id="Create_Custom_Objects_147"></span> Create Custom Objects

**Name:** create_custom_objects

**Description:** Creates custom objects in ThreatQ

**Parameters:**

-   object_list: A list of custom object values in ThreatQ
-   object_type: The type of object that the object list specifies

### <span id="Add_Attribute_157"></span> Add Attribute

**Name:** add_attribute

**Description:** Adds an attribute to a list of custom objects

**Parameters:**

-   object_list: A list of custom object values in ThreatQ
-   object_type: The type of object that the object list specifies
-   attribute_name: The name for the attribute to add
-   attribute_value: The value for the attribute to add

### <span id="Set_Indicator_Status_169"></span> Set Indicator Status

**Name:** set_indicator_status

**Description:** Sets the status of an indicator in ThreatQ

**Parameters:**

-   indicator_list: A list of indicators
-   indicator_status: The status to give to the list of indicators

**Formatting:**  
See *Details \> Formatting an Indicator List*

## <span id="App_Instructions_182"></span> App Instructions

### <span id="Formatting_an_Indicator_List_184"></span> Formatting an Indicator List

You can pass a list of indicators to action in few different ways. Each being parsed, slightly
differently, but with similar outcomes

-   If only values are specified, the integration will attempt to “detect” the indicator types and
    upload the known values (i.e. `      1.1.1.1, badurl.com     ` )
-   You can specify indicator types by separating the type and value by a `      :     ` or
    `      =     ` character (i.e. `      IP Address: 1.1.1.1, FQDN: badurl.com     ` )
-   You can even pass the function a list of dictionaries, specifying the indicator type and value,
    like so:

``` json
[
    {
        "type": "IP Address",
        "value": "1.1.1.1"
    },
    {
        "type": "FQDN",
        "value": "badurl.com"
    }
]
```

### <span id="Upgrading_from_1x_to_2x_204"></span> Upgrading from 1.x to 2.x

While many of the actions in v2.x of the Phantom App look very similar to the v1.x App, they operate
very differently. Chances are, you will need to recreate all of the ThreatQ App actions, and
reconfigure them. Please review all of the actions under the `     App Actions    ` section to see
how to configure them.

## <span id="Known_IssuesLimitations_208"></span> Known Issues/Limitations

N/A

## <span id="Changelog_212"></span> Changelog

-   Version 2.0.3
    -   Rewrite of the app to improve stability, error handling, and input support
    -   Remove all “reputation” actions, and replaced them with an all-in-one query action
    -   Adds actions to interact with custom objects
    -   All response views now share the same template, including tables for attributes and related
        objects (including custom objects)
    -   Response data is now better formatted to be used within phantom playbooks to make better
        decisions
    -   Querying an indicator will query *all* information about that indicator, including
        attributes, score, status, and relationships. That information is then made accessible
        within the conditions block in order to make a decision
-   Version 1.0.0
    -   Initial release
