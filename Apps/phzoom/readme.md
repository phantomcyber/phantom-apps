[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
### SDK and SDK Licensing details for the app

#### PyJWT

This app uses the PyJWT module, which is licensed under the MIT License (MIT), Copyright (c) Jose
Padilla.

#### random-password-generator

This app uses the random-password-generator module, which is licensed under the MIT License (MIT),
Copyright (c) Surya Teja Reddy Valluri.

### Objective

This app was created in response to a marked increase in work from home employees, which has
inevitably led to a significant rise in Zoom usage. This app provides important additional context
about meetings (e.g., was the meeting password protected, was the waiting room turned on). This app
provides security practitioners a way to ensure that security best practices are being followed with
regard to Zoom meetings.

### App Configurations (Zoom Side)

For the Zoom app for Phantom to be configured correctly, you must first create a JWT App in your
Zoom App Marketplace account. A JWT App can be created by going
[here](https://marketplace.zoom.us/develop/create) and clicking the "Create" button under the "JWT"
app type. Once you've created your JWT app you'll be provided with an API Key and an API Secret,
keep track of these. They will be necessary for the configuration on the Phantom side.

### App Configuration (Splunk> Phantom Side)

The configuration of the Zoom App for Splunk> Phantom requires three fields API Key and API Secret
which are provided by Zoom. The third field is the "Base URL" field which is simply the base URL for
the Zoom REST API. The default value provided, "https://api.zoom/us/v2" should not need to be
changed.

### Actions

Actions are all fairly simple and documented with the normal app documentation process. That said,
one of the main purposes of this app was to provide additional context about meetings that can only
be provided via the Zoom API, most notably whether or not the meetings are being password protected.

The two actions that provide information on the configuration of passwords on meetings are "get
meeting" and "get meeting invitation". These two actions will give you data that can be used to gain
insight into who is running unprotected meetings, how often, and what are the topics of those
meetings.
