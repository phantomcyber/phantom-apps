[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2020-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
# Tanium Threat Response Typical Usage Example

To get the information from Tanium Threat Response, you will need to follow a certain flow of
actions to get what you want. First, you will need to run a search to find the computer that Threat
Response can interact with. To get that you can run the `     list computers    ` action to search
through the computers that are connected to Threat Response. You will get back the top 10 computers
that match a search query, so being as specific as possible would be better.

Once you find the computer that you want to collect information from, you need to create a
connection using the `     create connection    ` action, where the name returned from the
`     list computers    ` is used. Otherwise, the connection may take a while and fail. This action
only sends the request to create the connection and will not return the status of that connection.

You can then test to see if your connection was made by running `     get connection    ` . It will
list the status of all the current connections. An **active** status means you can run the other
actions to get information that you may need. Live connections will timeout and need to be recreated
in those cases. Connections to snapshots will stay open and should be closed after everything is
completed.

You can get the list of all the snapshots by running the `     list snapshots    ` action. It will
list all the snapshots, i.e., the snapshot files that are uploaded manually and the snapshots that
are captured through Tanium UI. The `     list local snapshots    ` action lists only those
snapshots which are captured through Tanium UI. Also, the endpoint used in the
`     list local snapshots    ` action will be deprecated in the future so we would suggest you use
the `     list snapshots    ` action instead of the `     list local snapshots    ` action.

To delete a snapshot, you can run the `     delete snapshot    ` action by providing the **host**
and the **filename** . The `     delete local snapshot    ` action does not work as per the
expectation, as the status of the deleted snapshot does not get reflected on the UI. Hence, we would
suggest you use the `     delete snapshot    ` action instead of the
`     delete local snapshot    ` action.
