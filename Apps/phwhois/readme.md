[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
The app uses the tldextract python module while executing the 'whois domain' action. This module
uses the tld list from publicsuffix.org. The app ships with a tld list, however, it will try to
update the list the first time it runs and then tries to update it at a regular interval. The
interval is set in the app config.

This app will ignore the HTTP_PROXY and HTTPS_PROXY environment variables.

The user is requested to use CONFIGURE NEW ASSET option to configure a new asset.

## ipwhois

This app uses the python-ipwhois module, which is licensed under the BSD License, Copyright (c)
2013-2019 Philip Hane.

## pythonwhois

This app uses the python pythonwhois module, which is licensed under the WTFPL License, Copyright
(c) Sven Slootweg.

## tldextract

This app uses the python tldextract module, which is licensed under the BSD License, Copyright (c)
John Kurkowski.

## dnspython

This app uses the python dnspython module, which is licensed under the ISC License, Copyright (c)
Bob Halley.

## requests-file

This app uses the python requests-file module, which is licensed under the Apache 2.0 License,
Copyright (c) David Shea.
