# Zoom Automation Project
## Objective


This project was created in response to a marked increase in work from home employees, which has inevitably led to a significant rise in Zoom usage. The objective of this project is to supplement log data provided by Zoom webhooks with important additional context (e.g., was the meeting password protected, was waiting room turned on). Additionally, we wanted to provide security practitioners a way to proactively ensure that security best practices are being followed with regards to Zoom meetings.

## High Level Overview

This project is predicated on the fact that Zoom logs are already being ingested into Splunk by way of JWT Webhooks. The process flow from there is as follows:

- Ingest Zoom meeting logs into Phantom by way of "polling" action.
- Enrich Zoom meeting and user log data with the Zoom App for Phantom.
- Push enriched data back into Splunk kvstores for alert and dashboard integration.

Additional capabilities:
- Update Zoom user settings to adhere to your organization's Zoom best practices.
- Update scheduled Zoom meetings to require a password.
- Get file transfer transcripts from Zoom chat logs.

## The Documentation
This project is broken into several parts:
- [Zoom Automation Project](#zoom-automation-project)
  - [Objective](#objective)
  - [High Level Overview](#high-level-overview)
  - [The Documentation](#the-documentation)
  - [Zoom App for Phantom](#zoom-app-for-phantom)
    - [Installing the App](#installing-the-app)
    - [App Configurations (Zoom Side)](#app-configurations-zoom-side)
    - [App Configuration (Phantom Side)](#app-configuration-phantom-side)
    - [Actions](#actions)
  - [**Updated** Splunk App for Phantom](#updated-splunk-app-for-phantom)
    - [Where to find it](#where-to-find-it)
    - [Installing the App](#installing-the-app-1)
    - [Update Details](#update-details)
    - [Configuring the on poll query and related fields](#configuring-the-on-poll-query-and-related-fields)
  - [Playbooks](#playbooks)
    - [Where to find them](#where-to-find-them)
    - [How to install](#how-to-install)
    - [About](#about)
  - [Splunk Add-on for Zoom Enrichment](#splunk-add-on-for-zoom-enrichment)
    - [Where to find them](#where-to-find-them-1)
    - [How to install](#how-to-install-1)
    - [About](#about-1)
  - [Sample queries](#sample-queries)

## Zoom App for Phantom

### Installing the App

In the `compiled_app` directory there is a ready to install version of this app. Just download it and click "Install App" on the Phantom Apps page.

### App Configurations (Zoom Side)
For the Zoom app for Phantom to be configured correctly, you must first create a JWT App in the your Zoom App Marketplace account. A JWT App can be created by going [here](https://marketplace.zoom.us/develop/create) and clicking the "Create" button under the "JWT" app type. Once you've created your JWT app you'll be provided with an **API Key** and and **API Secret**, keep track of these. They will be necessary for the configuration on Phantom side.

### App Configuration (Phantom Side)
The configuration of the Zoom App for Phantom requires three fields **API Key** and **API Secret** which are provided by Zoom. The third field is the "Base URL" field which is simply the base URL for the Zoom REST API. The default value provided, "https://api.zoom/us/v2" should not need to be changed.

### Actions
Actions are all fairly simple and documented with the normal app documentation process, for details please install the app and review the documentation at your leisure. That said, one of the main purposes of this app was to provide additional context about meetings that can only be provided via the Zoom API, most notably whether or not the meetings are being password protected.

The two actions that provide information on the configuration of passwords on meetings are **get meeting** and **get meeting invite**. Get meeting should be invoke when a "meeting.started" event is ingested from Phantom. The **get meeting** API call provides tons of detail, but will only successfully run against currently in-flight meetings. Further details on how to ingest and act on Zoom events are provided [here](#app-configuration-phantom-side)

**get meeting invite** should be invoked when the "meeting.created" event  is ingested by phantom. This command call the meeting invite API endpoint and parses the relevant details from in, namely the password, if there is one. 

These two actions will give you data that can be used to gain insight into who is running unprotected meetings, how often, and what are the topics of those meetings.

## **Updated** Splunk App for Phantom

**DISCLAIMER**: This is a fork of the Splunk App for Phantom, not officially supported.
 
### Where to find it

You can find the Update Splunk app [here](../splunk)

### Installing the App

In the `compiled_app` directory there is a ready to install version of this app. Just download it and click "Install App" on the Phantom Apps page.

### Update Details
This updated Splunk App for Phantom will allow you to add (**add kvstore data**) and remove (**remove kvstore data**) data from existing KV stores in Splunk. The playbooks provided as part of this project leverage these actions to bring the enrichment data from the **get meeting** and **get meeting invite** actions back to Splunk.

### Configuring the on poll query and related fields
There are plenty of ways to ingest data from Splunk to Phantom, however for the lowest friction we've chosen to go with a polling action from Phantom. In this case Phantom is configured to make an outbound connection to Splunk, run a predefined query, and ingest the results.

The fields required for configuration are as follows:
- Query to use with On Poll
  - We recommend starting with a query like the following `index=<your_index> sourcetype="zoom:webhook" earliest=-15m ((event="meeting.created" AND payload.object.start_time=*) OR event="meeting.started") | rename payload.object.topic as topic, payload.object.host_id as host_id, payload.object.id as meeting_id | table _time, event, topic, host_id, meeting_id`
  - This will ingest all meeting.started events as well as the creation of any future meetings.
- Fields to save with On Poll
  - This field tells Phantom which fields from the query results you want to save in the Phantom event.
  - If you're using our recommended query, it should be populated with `_time, event, topic, host_id, meeting_id`
- Name to give containers created via ingestion
  - This will serve as a prefix to our even name in Phantom - we recommend `Zoom:`
- Values to append to container name
  - This fields defines field names from your query results that will be used dynamically to create your Phantom event name.
  - We recommend using the meeting topic and time by using these two fields: `topic, _time`

## Playbooks

### Where to find them

The playbooks associated with this project can be found [here](../../Playbooks/Zoom_Enrichment_Use_Case)

### How to install

This app can be installed in Splunk by going to "Manage Apps" and then "Install app from file."

### About
Currently, four playbooks are provided to demonstrate the functionality provided by the Zoom App and updated Splunk App. You may find these useful, but it is recommended you modify them before putting them insto production:

1. Zoom Router
   - This playbook is designed to route meeting records from Splunk to the correct playbook.
     - Meeting.created goes to Zoom Scheduled Meeting Enrichment playbook
     - Meeting.started goes to Zoom Meeting Enrichment playbook
   - When ready to fully automate Zoom enrichment, set this playbook to active and "Operates On" to the label configured for ingest.
2. Zoom Meeting Enrichment
   - This playbook is designed to respond to ingested meeting.started. It will get the information from the in-flight meeting, get information about those host of that meeting, and send the meeting details to the zoom_meeting_details kvstore provided in the Splunk Add-on for Zoom Enrichment
   - Additionally, if it is discovered that no password set on the meeting, an educational email will be sent to the meeting host informing them of the risks of unprotected Zoom meetings.
   - Finally, a step that will update the meeting host's settings to require passwords on all meeting types and require waiting rooms.
   - Modification Recommendations:
     - Review the email message and customize it to what you want.
     - Decide if you really want to update user settings, and if so, make sure you're comfortable with each of the applicable settings to the action. Additionally, you may want to include information about modified user settings to your message to the meeting host.
     - Make sure the `from address` of the `send email` action has your desired email address.
3. Zoom Scheduled Meeting Enrichment
   - This playbook is designed to respond to ingested meeting.created events with a future start_time (i.e., future meetings). It will get the meeting invite for the meeting, get information about the host of the meeting, and send the meeting invite details to the zoom_meeting_invites kvstore provided by the Splunk Add-on for Zoom Enrichment.
   - Additionally, if it is discovered that no password is set on the meeting, the meeting will be updated with a password, and an education email will be sento the meeting host informing them of the change and the risk of unprotected Zoom meetings.
   - Modification Recommendations:
     - Review the email message and customize it to what you want.
     - Decide if you really enforce a password on the scheduled meeting. If not, you may want to modify the meeting_host notification message.
     - Make sure the `from address` of the `send email` action has your desired email address.
4. Zoom User Enrichment
   - This playbook is designed to enrich zoom user data - likely user host (if you're using the same ingestion queries we recommended, the user_id will be the `host_id` from the ingested events). This will get general user information (e.g., user email, timezone, etc.) as well as user settings (e.g., require password on newly scheduled meetings), it will also update the kvstores zoom_user_details and zoom_user_settings provided by the Splunk Add-on for Zoom Enrichment.
   - Additionally, if it is discovered that passwords and/or waiting rooms are not enabled on the user account in question, it will send an educational email to the user informing them of the risks of unprotected zoom meetings.
   - Modification Recommendations:
     - Review the email message and customize it to what you want.
     - Make sure the `from address` of the `send email` action has your desired email address.
5. Zoom Meeting Post Mortem
   - This playbook is designed to get information on files transferred in Zoom chat during the course of an ended meeting. It will send this information to the zoom_meeting_files kvstore provided by the Splunk Add-on for Zoom Enrichment.
   - Note: Files are only available for 24 hours after a meeting ends.
   - Modification Recommendations:
     - N/A

## Splunk Add-on for Zoom Enrichment

### Where to find them

The Splunk Add-on for Zoom Enrichment app can be found [here](../../Splunk_Apps/Zoom_Enrichment_Use_Case/)

### How to install

Download the spl file. Login to Splunk. Go to "Manage Apps". Click "Install App from File."

### About

This app is designed to provide kvstores for zoom enrichment data provided by phantom.

1. zoom_meeting_details
   - Used to store rich details about Zoom meetings. Can only be populated while a meeting is actively in session.
3. zoom_meeting_invite
   - Used to store meeting invite details for future scheduled meetings.
4. zoom_user_settings
   - Used to store user settings for Zoom users.
5. zoom_user_details
   - Used to store user profile information for Zoom users.
6. zoom_meeting_files
   - Used to store meetings about files transfered durign the course of a zoom meeting.

## Sample queries

As noted the recommended ingestion query to be implemented with the phantom polling action is:
- `index=<your_index> sourcetype="zoom:webhook" earliest=-15m ((event="meeting.created" AND payload.object.start_time=*) OR event="meeting.started") | rename payload.object.topic as topic, payload.object.host_id as host_id, payload.object.id as meeting_id | table _time, event, topic, host_id, meeting_id`

Finding meetings that took place, or are in progess that had no password applied:
- `index=<your index> sourcetype="zoom:webhook" event="meeting.started" | lookup zoom_meeting_details id as payload.object.id | search NOT(encrypted_password=*)`

Finding meetings that are scheduled, but have no password:
- `index=<your index> sourcetype="zoom:webhook" event="meeting.created" payload.object.start_time=* | lookup zoom_meeting_invites meeting_id as payload.object.id | search NOT(password=*)`

Finding users that do not have passwords required and/or do not require waiting room functionality
- `index=<your index> sourcetype="zoom:webhook" event="meeting.started" | lookup zoom_user_settings user_id as payload.object.host_id | search (schedule_meeting_require_password_for_scheduling_new_meetings=0 OR schedule_meeting_require_password_for_instant_meetings=0 OR schedule_meeting_require_password_for_pmi_meetings="none" OR in_meeting_waiting_room="0")`

