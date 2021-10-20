[comment]: # ""
[comment]: # "File: readme.md"
[comment]: # "Copyright (c) 2020-2021 RADAR, LLC"
[comment]: # ""
[comment]: # "Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## About Radar Software for Privacy Incident Response Management:

Radar performs a comprehensive privacy risk assessment and determines when the incident is
notifiable under current data breach regulations. Radar guides privacy analysts through the
profiling and risk scoring of an incident, providing all necessary documentation to support an
organization’s burden of proof obligation under federal, state, and international breach laws.

For more information visit: <https://www.radarfirst.com/radar>

## Setup and Configuration

To use the Radar Phantom App, a Radar admin should request documentation from the Radar integrations
team.

To request this documentation:

-   Log into Radar at <https://app.radarfirst.com/login>
-   Select "Admin" from the top navigation.
-   From the admin UI, select "Integrations" from the top navigation.
-   From the list of integrations, select "Learn more" where Splunk Phantom is listed.
-   Follow the directions for contacting the Radar integration team.

When running the Radar app on the Splunk Phantom platform, the 'base_url' must be configured on the
company settings page. To configure the 'base_url' go to admin/company_settings/info and specify a
valid URL for the base URL field. If the 'base_url' is not configured, the 'create_privacy_incident'
action will throw an error message as 'Base URL for phantom appliance must be configured'.

## Asset Configuration

The configuration that must be set is under the "Asset Settings" tab. Below lists some details for
each configuration setting:

-   Radar API Bearer Token - A valid Radar bearer token with privileges for reading and writing
    radar incidents and notes.
-   Radar API URL - Defaults to the production URL, but can be set to a test or staging URL.
-   Time Zone - Should reflect the time that the Splunk Phantom instance is running in. This
    configuration is used in a couple of different ways:
    -   To specify a privacy incident’s ‘discovered’ timezone, when it is created by the “create
        privacy incident” action. This data is used during incident assessment and is critically
        important in determining regulatory timelines for incident notification to governmental
        agencies.
    -   Used when displaying certain action outputs, such as the “created at” and “updated at”
        outputs from the “get privacy incident” action. These timestamps are converted to the time
        zone specified in the asset configuration.

#### Environment Variables

Under the 'Advanced' section of the asset settings, set environment variables to configure the app
settings:

**ALLOW_SELF_SIGNED_CERTS** - Should be set to '1' to turn off verification of SSL Certificates
during action requests.
