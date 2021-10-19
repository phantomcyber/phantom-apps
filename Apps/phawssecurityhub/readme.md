[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
**Functioning of On Poll**

-   There are two approaches for ingesting data using the On Poll action.  

-   **SQS Polling**

      

    SQS polling is the preferred ingestion technique due to limitations in the AWS SecurityHub API
    used to ingest findings. Detailed instructions on configuring SQS-polling can be found below.

-   **Normal Polling**

      
      

    1.  On Poll

        This is manual On Poll. Here, the findings data of the past N days (poll_now_days
        configuration parameter) will be ingested.

    2.  Scheduled Polling

        In the first run, the findings data of the past M days (Scheduled_poll_days configuration
        parameter) will be ingested and then, for the consecutive runs, only the findings are
        updated after the last run's time (last_ingested_date stored in the state file) will be
        fetched.

    3.  Interval Polling

        The logic of fetching and ingesting the findings is the same as scheduled polling.

      

## Ingesting Security Hub Findings from SQS

The following section explains how to configure the preferred means of ingesting findings from AWS,
SQS polling. These instructions leverage a CloudFormation template to set up the forwarding of
Security Hub findings into an SQS queue. Phantom in turn ingests the findings from this queue.

  

Note that SQS-based polling will ignore the **poll_now_days** and **scheduled_poll_days** asset
configuration parameters.

### 1 - Forward Security Hub Alerts to an SQS Queue

Start by navigating to the CloudFormation page on your AWS console and running CloudFormation
template linked below. The template will generate a new CloudWatch Event Rule which will forward all
new Security Hub findings to an SQS Queue.

CloudFormation Template:
<https://splunkphantom.s3.amazonaws.com/cloud-formation/phantom-sechub-to-sqs.yaml>

![Cloud Formation - Selecting the Phantom
Template](https://splunkphantom.s3.amazonaws.com/images/PhantomSecHubToSQSCloudFormation.png)

After the Cloud Formation stack has been created be sure to take note of the
*securityHubToPhantomSQSURL* field in the output - you will need it later.

![Cloud Formation
Output](https://splunkphantom.s3.amazonaws.com/images/PhantomCloudFormationOutputHighlighted.png)

### 2 - Configure your Phantom App Asset

Next, login to your Splunk Phantom instance. If you are new to Phantom you can easily launch the
Phantom Community Edition available in the AWS Marketplace.

Navigate to the "Apps" page in Phantom. Search for the Security Hub app - if you don't find it in
your search results, you may need to select the *New Apps* and install the app before proceeding.
Select "Configure New Asset" for the v1.1+ Security Hub App.

> **Important** These instructions require the Phantom Security Hub app v1.1 or higher - if you are
> running an older version, be sure to upgrade it by selecting "Upgrade Apps" in your phantom
> instance or downloading the latest version of the app from my.phantom.us/apps and manually
> installing it.

![Security Hub Phantom App
Configure](https://splunkphantom.s3.amazonaws.com/images/security-hub-app-asset.png)

### App Configuration Parameters

Setting up the Security Hub Phantom app requires input on 3 configuration tabs.

##### Asset Info

Provide a unique name asset name. It is a good idea to use a name that reminds you which AWS
environment the app connects to.

##### Ingest Settings

-   Select a Label to apply to all Findings consumed from security hub, or create a new one by
    typing in the drop-down box
-   Select "Interval" to enable periodic polling of the SQS Queue
-   Modify the polling interval as desired to suit your organization's needs.  

##### Asset Settings

Supply values for the following fields:

-   AWS Access Key - The access key associated with an IAM account
-   AWS Secret Key - The secret key associated with an IAM account
-   SQS URL - The URL provided by the Cloud Formation template from part 1 of this guide

![Security Hub Phantom App - Asset Settings
Tab](https://splunkphantom.s3.amazonaws.com/images/phantom-sechub-app-assetsettings.png)

### Finalize the Configuration

Once you have configured the Asset Info, Ingest Settings, and Asset Settings select *Save* to
finalize your app configuration. You are now ready to start consuming Security Hub Findings in
Phantom!

Any new Security Hub Findings will now appear on your Phantom "Events" page according to your
polling interval. Note that the integration relies on forwarding events from the Security Hub to the
SQS queue, so the app will only know about any findings that were created after the Cloud Formation
template was run in Step 1.

----------------------------------------------------------------------------------------------------
