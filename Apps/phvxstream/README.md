# VxPhantom

The Falcon Sandbox Phantom App

Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

Copyright (C) 2018 Hybrid Analysis GmbH

============

## Requirements

- [Phantom](https://phantom.us) >= 3.5.180

Installing the App in Phantom
---

#### For Phantom 3.5.

- [App & Assets Management](https://my.phantom.us/3.5/docs/admin/apps_assets)

## Final Notes

Usage
--
Should you not be using hybrid-analysis.com as the application server, but a private cloud or on premise instance, please E-Mail support@crowdstrike.com for help on enabling the Phantom integration on your instance.

Testing connectivity
---

After creating the Falcon Sandbox asset, we recommended to test the application server connectivity. That way,
you make sure that the provided base URL and API credentials are working correctly.

Creating a new tarball installation file (developers only)
---

1. Go to `VxPhantom` directory,
2. Run `python -m compileall .` command to prepare .pyc files (you can remove already existing .pyc files `find . -type f -name '*.pyc' -delete`),
3. Run `python compile_app.py -d -t` command.

