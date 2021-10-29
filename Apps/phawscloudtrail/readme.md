[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2018-2021 Splunk Inc."
## Asset Configuration

There are two ways to configure an AWS CloudTrail asset. The first is to configure the
**access_key** , **secret_key** and **region** variables. If it is preferred to use a role and
Phantom is running as an EC2 instance, the **use_role** checkbox can be checked instead. This will
allow the role that is attached to the instance to be used. Please see the [AWS EC2 and IAM
documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)
for more information.

## Assumed Role Credentials

The optional **credentials** action parameter consists of temporary **assumed role** credentials
that will be used to perform the action instead of those that are configured in the **asset** . The
parameter is not designed to be configured manually, but should instead be used in conjunction with
the Phantom AWS Security Token Service app. The output of the **assume_role** action of the STS app
with data path **assume_role\_\<number>:action_result.data.\*.Credentials** consists of a dictionary
containing the **AccessKeyId** , **SecretAccessKey** , **SessionToken** and **Expiration** key/value
pairs. This dictionary can be passed directly into the credentials parameter in any of the following
actions within a playbook. For more information, please see the [AWS Identity and Access Management
documentation](https://docs.aws.amazon.com/iam/index.html) .
