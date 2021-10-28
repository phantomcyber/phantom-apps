[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Overview

The Cybereason platform finds a single component of an attack and connects it to other pieces of
information to reveal an entire campaign and shut it down. There are two types of alerts that
Cybereason will create:

-   Malops: This stands for a Malicious Operation, and will describe machines, users, processes, and
    connections used in the attack.
-   Malware: These alerts are generated when a user tries to run a piece of malware.

## Playbook Backward Compatibility

-   The new version of this application is a complete rewrite and is not backward compatible. Hence,
    it is requested to the end-user to please update their existing playbooks by re-inserting \|
    modifying \| deleting the corresponding action blocks to ensure the correct functioning of the
    playbooks created on the earlier versions of the app. If the end-user does not want to upgrade
    their playbooks, they can remain on or downgrade to the old version(v1.0.7).
