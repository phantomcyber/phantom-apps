[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2020 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
# Authentication

All requests must be authenticated with a bearer token. Use the HTTP header Authorization with the
value Bearer {token}. If the token is absent or invalid, Terraform Cloud responds with HTTP status
401 and a JSON API error object. The 401 status code is reserved for problems with the
authentication token; forbidden requests with a valid token result in a 404. There are three kinds
of token available:

-   **User tokens** — each Terraform Cloud user can have any number of API tokens, which can make
    requests on their behalf.
-   **Team tokens** — each team can have one API token at a time. This is intended for performing
    plans and applies via a CI/CD pipeline.
-   **Organization tokens** — each organization can have one API token at a time. This is intended
    for automating the management of teams, team membership, and workspaces. The organization token
    cannot perform plans and applies
