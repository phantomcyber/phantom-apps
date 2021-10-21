[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2020 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
### Poll Now

It should be used to get a sense of the containers and artifacts that are created by the app. It
makes use of asset configuration parameter `     max_containers    ` , that can be:

-   **enabled**

    Window *Poll Now* allows the user to set the *Maximum containers* that should be ingested at
    this instance. Since a single container is created for each alert, this value equates to the
    maximum alerts that are ingested by the app. All remaining alerts would be ignored.

-   **disabled**

    Any *Maximum containers* value set in window *Poll Now* will be ignored. The system will ingest
    all alerts found with `       start_time      ` greater than 5 days ago.

### Scheduled Polling

This mode is used to schedule a polling action on the asset at regular intervals, configured via
asset tab *Ingest Settings* .

In the case of Scheduled Polling, on every poll, the app remembers the last time of successful
ingestion and will pickup filtering alerts based on `     start_time    ` greater than this value in
the next scheduled poll.
