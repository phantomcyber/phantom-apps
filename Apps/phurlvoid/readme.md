[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
The app uses the tldextract python module, while executing the **domain reputation** action. This
module uses the tld list from publicsuffix.org. The app ships with a tld list, however it will try
to update the list the first time it runs and then try to update it at a regular interval. The
interval is set in the app config.
