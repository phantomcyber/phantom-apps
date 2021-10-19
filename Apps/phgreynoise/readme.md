[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Playbook Backward Compatibility

-   Version 2.0.0 of this application is a complete rewrite and is not backward compatible with
    version 1.0.0. Hence, it is requested to the end-user to please update their existing playbooks
    by re-inserting \| modifying \| deleting the corresponding action blocks to ensure the correct
    functioning of the playbooks created on the earlier versions of the app. If the end-user does
    not want to upgrade their playbooks, they can remain on or downgrade to the old version(v1.0.0).

## Description

The GreyNoise Enrichment plugin for Phantom enriches observables to identify activity associated
with mass-internet scanning, creating more time to investigate other higher priority observables.
This enrichment provides context into IP behavior: intent, tags, first seen, last seen, geo-data,
ports, OS, and JA3.  
  
The GreyNoise Enrichment plugin for Phantom requires an API key. Set up an account to receive an API
key and find GreyNoise documentation here: <https://developer.greynoise.io/>

## Actions

#### lookup ip

Check to see if a given IP has been seen by GreyNoise engaging in internet scanning behavior.

#### riot lookup ip

Identifies IPs from known benign services and organizations that commonly cause false positives.

#### community lookup ip

An action requiring at least a free community API key to query IPs in the GreyNoise dataset and
retrieve a subset of the IP reputation data returned by the lookup ip and lookup reputation actions.
A free API key can be obtained at <https://www.greynoise.io/viz/signup>

#### lookup ips

Check whether IP addresses in a set have been seen engaging in internet scanning behavior. This
action is similar to *lookup ip* except that it processes more than one IP at a time. IPs should be
comma-separated.

#### ip reputation

Delivers full IP context: time ranges, IP metadata (network owner, ASN, reverse DNS pointer,
country), associated actors, activity tags, and raw port scan and web request information.

#### gnql query

GreyNoise Query Language (GNQL) uses Lucene deep under the hood. GNQL enables users to make complex
and one-off queries against the GreyNoise dataset.  
For more information, please visit: <https://developer.greynoise.io/reference#gnqlquery-1>

#### on poll

Retrieves GNQL query results on a set interval. The default number of results returned is 25.  
Notes:

-   The on poll action will spawn a container for each result returned. Phantom performance may be
    degraded if an overly large query is used.

-   Potentially useful queries may include ones that limit results to assets owned by your
    organization, such as:

-   -   metadata.organization:your_organization classification:malicious
    -   8.8.8.0/30 (replace with your address block) classification:malicious

-   To test your query or to learn more about GNQL queries, please visit
    <https://developer.greynoise.io/reference#gnqlquery-1>

#### test connectivity

Test connectivity to GreyNoise. Requires a valid paid or free community API key.

## Legal

For terms and legal information, please visit <https://greynoise.io/terms>
