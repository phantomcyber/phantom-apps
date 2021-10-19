[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
Actions in this app utilize the following API:
https://cloud.google.com/compute/docs/reference/rest/v1

## Explanation of Asset Configuration Parameters

The asset configuration parameters affect \[test connectivity\] and all the other actions of the
application. Below are the explanation and usage of all those parameters.

-   **Contents of Service Account JSON file -** After creating a Service Account for authenticating
    with Google Cloud Storage (https://console.cloud.google.com/iam-admin/serviceaccounts/project),
    the file can be downloaded. Paste the contents into the asset configuration input as-is.
-   **Project ID -** The Google Cloud Project ID.
