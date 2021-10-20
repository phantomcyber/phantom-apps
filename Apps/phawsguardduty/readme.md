[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2019-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## SDK and SDK Licensing details for the app

### boto3

This app uses the boto3 module, which is licensed under the Apache Software License (Apache License
2.0), Copyright (c) Amazon Web Services.

### botocore

This app uses the botocore module, which is licensed under the Apache Software License (Apache
License 2.0), Copyright (c) Amazon Web Services.

### s3transfer

This app uses the s3transfer module, which is licensed under the Apache Software License (Apache
License 2.0), Copyright (c) Amazon Web Services.

### six

This app uses the six module, which is licensed under the MIT License (MIT), Copyright (c) Benjamin
Peterson.

### urllib3

This app uses the urllib3 module, which is licensed under the MIT License (MIT), Copyright (c)
Andrey Petrov.

### python_dateutil

This app uses the python_dateutil module, which is licensed under the Apache Software License, BSD
License (Dual License), Copyright (c) Gustavo Niemeyer.

### jmespath

This app uses the jmespath module, which is licensed under the MIT License (MIT), Copyright (c)
James Saryerwinnie.

## Asset Configuration

There are two ways to configure an AWS GuardDuty asset. The first is to configure the **access_key**
, **secret_key** and **region** variables. If it is preferred to use a role and Phantom is running
as an EC2 instance, the **use_role** checkbox can be checked instead. This will allow the role that
is attached to the instance to be used. Please see the [AWS EC2 and IAM
documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)
for more information.

Region parameter provided in the asset configuration parameter and region of the bucket which is
created in AWS console must match otherwise user will get InvalidLocationConstraint error.

For the **Update bucket** action,
API is unable to validate the KMS key. Hence, it is recommended to provide a
valid KMS key in this action parameter otherwise it will affect the S3 bucket.
e.g If we update the S3 bucket with the invalid KMS key and then run create object action on the bucket then the action will not work for encryption = NONE.

## Assumed Role Credentials

The optional **credentials** action parameter consists of temporary **assumed role** credentials
that will be used to perform the action instead of those that are configured in the **asset** . The
parameter is not designed to be configured manually, but should be used in conjunction with the
Phantom AWS Security Token Service app. The output of the **assume_role** action of the STS app with
data path **assume_role\_\<number>:action_result.data.\*.Credentials** consists of a dictionary
containing the **AccessKeyId** , **SecretAccessKey** , **SessionToken** and **Expiration** key/value
pairs. This dictionary can be passed directly into the credentials parameter in any of the following
actions within a playbook. For more information, please see the [AWS Identity and Access Management
documentation](https://docs.aws.amazon.com/iam/index.html) .

## On Poll Guidelines

-   **Configuration Parameters**

      

    -   The asset configuration parameter `         poll_now_days        ` is optional, with the
        default value of 30 days. This configuration parameter is used for the manual polling using
        Poll Now.
    -   The asset configuration parameter `         filter_name        ` is optional and if not
        specified, it will fetch all the findings. This configuration parameter is used in all the
        On Poll modes (manual polling, scheduled polling, and interval polling).

      

-   **Manual Polling**

      

    -   Manual polling will fetch all the findings (in latest first order) based on the given
        `         filter_name        ` (if `         filter_name        ` is not provided, all
        findings will be fetched) for the last `         poll_now_days        ` from the current
        time (if `         poll_now_days        ` is not specified, default 30 days will be
        considered).

      

-   **Scheduled\|Interval Polling**

      

    -   The scheduled\|interval polling fetches the findings (in oldest first order to ensure zero
        data loss) based on the same logic of the manual polling for the first run. The 'updatedAt'
        time of the last fetched finding gets stored in this first run.
    -   For the consecutive runs, the findings get fetched after the stored 'updatedAt' time in the
        previous run.
    -   If the `         filter_name        ` gets changed at an intermediate stage of the
        scheduled\|interval polling, the next run of polling will auto-detect the change and it will
        poll the findings and reset the 'updatedAt' time based on the new
        `         filter_name        ` .

      

-   **Recommendations for Filter Creation on AWS GuardDuty UI**

      

    -   For the On Poll action, it is not recommended to include 'updatedAt' (time-based) filter
        criteria in the filter created on AWS GuardDuty UI to avoid conflicts with the timing logic
        of the On Poll action.
    -   If 'updatedAt' (time-based) filter criteria is included in the filter created on AWS
        GuardDuty UI, it will be explicitly replaced with the timing logic of the On Poll action
        **(keeping other filter criteria the same)** .
