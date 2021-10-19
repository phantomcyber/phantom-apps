[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2020 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
\- \`client_id\` and \`client_password\` credentials must be taken from an existing API client for
accessing the Cisco SecureX Threat Response APIs. The official documentation on how to create such a
client can be found here(https://visibility.amp.cisco.com/#/help/integration). Make sure to properly
set some scopes which will grant the client different (ideally minimum) privileges.

Make sure you have this scopes specified:

\- Enrich

\- Inspect

\- \`region\` must be one of: \`''\` (default), \`'eu'\`, \`'apjc'\`. Other regions are not
supported yet.
