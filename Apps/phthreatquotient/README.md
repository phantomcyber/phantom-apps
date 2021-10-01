# Splunk SOAR App

## Introduction

The Splunk SOAR App for ThreatQ allows a user to execute a variety of actions on ThreatQ from a Phantom playbook. 
With ThreatQ as a single source of truth for Threat Intelligence, you will be able to accurately triage a sighting, and ultimately, make a quick decision. 
This will allow your analysts to focus on what's important to their organization, instead of getting inundated with sightings of non-malicious indicators. 
The goal being, to increase your response time and improve your ROI.

## Installation

This section will describe how you can install the app into your Phantom instance

**WARNING**: This release (v2.x) has fundamentally changed how the App operates! 
If you are upgrading from v1.x, please refer to the `App Instructions -> Upgrading from 1.x to 2.x` section!

1. Download the Splunk SOAR App (tar.gz) for ThreatQ via any of these methods:
    - Marketplace
    - Download Center
    - Splunkbase
2. Login to your Phantom instance
3. In your navigation dropdown, select `Apps`
4. Click on the `Install App` button at the top right of your Apps page
5. Select the Splunk SOAR App for ThreatQ tar.gz file

## Configuration

Once the app is installed, you will see a ThreatQ logo on your Apps page. If you do not, you can search for `ThreatQ` in the search bar

1. Next to the ThreatQ logo, click on the `Configure New Asset` button
2. Fill out the following information in the `Asset Info` tab, and save:
    - **Asset name**: threatq
    - **Asset description**: Integration with the ThreatQ Threat Intelligence Platform
    - **Product vendor**: ThreatQuotient
    - **Product name**: ThreatQ
3. Fill out the following information in the `Asset Settings` tab, and save:
    - **Server IP/Hostname**: Enter the hostname or IP address for your ThreatQ instance
    - **Client ID**: Enter your API Credentials found under your `My Account` page in ThreatQ
    - **Username**: Enter your username to authenticate with ThreatQ
    - **Password**: Enter your password to authenticate with ThreatQ
    - **Trust SSL Certificate?**: Check this box if you want to trust the ThreatQ certificate (default: checked)
4. Click the `Test Connectivity` button after saving to test your connection information
    - If this test fails, verify your Phantom instance has access to your ThreatQ instance, as well as make sure your credentials are correct
5. The ThreatQ App should now be configurable within a playbook!

## App Actions

The following actions come out of the box with the Splunk SOAR App for ThreatQ

### Query Indicators

**Name:** query_indicators

**Description:** Query a list of indicators against ThreatQ

**Parameters:**
- indicator_list: A list of indicator values to query

### Create Indicators

**Name:** create_indicators

**Description:** Create indicators in ThreatQ

**Parameters:**
- indicator_list: A list of indicators to add

**Formatting:**
See _Details > Formatting an Indicator List_

### Create Task

**Name:** create_task

**Description:** Create a task in ThreatQ

**Parameters:**
- task_name: The name of the task to create
- assigned_to: The email or username of a user within ThreatQ to assign the task to
- task_status: The task status in ThreatQ
- task_priority: The task priority in ThreatQ
- task_description: The description of the task
- indicator_list: A list of indicators to relate to the task

**Formatting:**
See _Details > Formatting an Indicator List_

### Create Event

**Name:** create_event

**Description:** Creates an event in ThreatQ, based on the container metadata in Phantom

**Parameters:**
- event_type: The type fo event to create in ThreatQ
- indicator_list: A list of indicators to relate to the task

**Formatting:**
See _Details > Formatting an Indicator List_

### Create Spearphish

**Name:** upload_spearphish

**Description:** Creates a spearphish event in ThreatQ, based on a spearphish email in the Phantom vault

**Parameters:**
- vault_id: The ID of an email file in your Phantom vault
- indicator_status: The indicator status for any parsed indicators from the spearphish

### Upload File

**Name:** upload_file

**Description:** Creates a file (attachment) in ThreatQ

**Parameters:**
- vault_id: The ID of an file in your Phantom vault
- parse_for_indicators: Whether or not to parse the file for indicators
- default_indicator_status: The indicator status for any parsed indicators from the file

### Start Investigation

**Name:** start_investigation

**Description:** Create a task in ThreatQ

**Parameters:**
- investigation_name: The name of the investigation to create in ThreatQ
- investigation_priority: The priority of the investigation in ThreatQ
- investigation_description: The description of the investigation in ThreatQ
- investigation_visibility: Whether the investigation is public or private
- indicator_list: A list of indicators to relate to the task

**Formatting:**
See _Details > Formatting an Indicator List_

### Create Adversaries

**Name:** create_adversaries

**Description:** Create adversaries in ThreatQ

**Parameters:**
- adversary_list: A list of adversary names to create in ThreatQ

### Create Custom Objects

**Name:** create_custom_objects

**Description:** Creates custom objects in ThreatQ

**Parameters:**
- object_list: A list of custom object values in ThreatQ
- object_type: The type of object that the object list specifies

### Add Attribute

**Name:** add_attribute

**Description:** Adds an attribute to a list of custom objects

**Parameters:**
- object_list: A list of custom object values in ThreatQ
- object_type: The type of object that the object list specifies
- attribute_name: The name for the attribute to add
- attribute_value: The value for the attribute to add

### Set Indicator Status

**Name:** set_indicator_status

**Description:** Sets the status of an indicator in ThreatQ

**Parameters:**
- indicator_list: A list of indicators to relate to the task
- indicator_status: The status to give to the list of indicators

**Formatting:**
See _Details > Formatting an Indicator List_

## App Instructions

### Formatting an Indicator List

You can pass a list of indicators to an action in few different ways. Each being parsed, slightly differently, but with similar outcomes

- If only values are specified, the integration will attempt to "detect" the indicator types and upload the known values (i.e. `1.1.1.1, badurl.com`)
- You can specify indicator types by separating the type and value by a `:` or `=` character (i.e. `IP Address: 1.1.1.1, FQDN: badurl.com`)
- You can even pass the function a list of dictionaries, specifying the indicator type and value, like so:
```json
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

### Upgrading from 1.x to 2.x

While many of the actions in v2.x of the Phantom App look very similar to the v1.x App, they operate very differently. Chances are, you will need to recreate all of the ThreatQ App actions, and reconfigure them. Please review all of the actions under the `App Actions` section to see how to configure them.

## Known Issues/Limitations

N/A

## Changelog


* Version 2.0.0
  * Rename the app
  * Rewrite of the app to improve stability, error handling, and input support
  * Remove all "reputation" actions, and replaced them with an all-in-one query action
  * Adds actions to interact with custom objects
  * All response views now share the same template, including tables for attributes and related objects (including custom objects)
  * Response data is now better formatted to be used within phantom playbooks to make better decisions
  * Querying an indicator will query _all_ information about that indicator, including attributes, score, status, and relationships. That information is then made accessible within the conditions block in order to make a decision
* Version 1.0.0
  * Initial release
