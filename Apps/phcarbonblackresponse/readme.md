[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
Every action uses the **api_token** configured on the Carbon Black Response asset. This token
represents a user on the Carbon Black Response server. Many actions like **list endpoints** require
the user to have permissions to be able to view sensors. The Carbon Black Response user that Phantom
uses must have the privileges needed to perform the actions being attempted. For example, to
quarantine endpoints, the account used by Phantom must have Carbon Black Response administrator
privileges.
