[comment]: # ""
[comment]: # "    File: readme.md"
[comment]: # "    Copyright (c) 2018-2021 Splunk Inc."
[comment]: # "    "
[comment]: # "    Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
[comment]: # ""
Without additional configuration on the proxy server, it will not be possible to connect to WinRM
using NTLM authentication through an HTTP(S) proxy. If authentication is set to basic, then it will
still work, however.

To use the proxy settings you need to add the proxy server as an environment variable. You can add
an environment variable using the below command.

-   For Linux/Mac: `      export HTTP_PROXY="http://<proxy server>:<proxy port>/"     `
-   For Windows powershell: `      $env:HTTP_PROXY="http://<proxy server>:<proxy port>/"     `

If the user tries to add any invalid proxy URL, the proxy will be bypassed and won't affect the
app's connectivity.

To use this app you must have the Windows Remote Management service running on the endpoint you wish
to connect to. For help regarding this process, consult this link:
<https://msdn.microsoft.com/en-us/library/aa384372(v=vs.85).aspx>

WinRM Ports Requirements (Based on Standard Guidelines of [IANA
ORG](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) )

-   WinRM(service) TCP(transport layer protocol) port for Windows Remote Management Service - 47001

The protocol and port can be specified with the IP/hostname. For example, if using HTTPS on port
5986, the IP/Hostname should be **https://192.168.10.21:5986** .

In the configuration options for the asset, a default protocol and port for actions can be
specified. These options will be prepended or appended to the IP/hostname provided for all actions
including **test connectivity** . If a different protocol or port number is specified in the
IP/hostname field, the corresponding default will be ignored.

This app supports adding a custom parser for the actions **run script** and **run command** . By
default, the output of these actions will just be the status code, standard out, and standard error
of whatever gets ran. If you want to capture a specific string or fail on a certain status code, you
will need to provide a custom parser.

The custom parser should be a file added to the vault containing a function named **custom_parser**
.

``` shell
import phantom.app as phantom


def custom_parser(action_result, response):
    # type: (ActionResult, winrm.Response) -> bool
    data = {}
    data['status_code'] = response.status_code
    data['std_out'] = response.std_out
    data['std_err'] = response.std_err

    action_result.add_data(data)
    return phantom.APP_SUCCESS
```

This is equivalent to the default parser which is used if nothing is provided. It takes in an
ActionResult and a Response object (from the pywinrm module), and it is expected to return a boolean
value (phantom.APP_SUCCESS and phantom.APP_ERROR are equivalent to True and False).

Here is an example of a parser that will extract all the IPs from the output, and fail if there is a
non-zero status code.

``` shell
import re
import phantom.app as phantom
from phantom import utils as ph_utils


def custom_parser(action_result, response):
    # type: (ActionResult, winrm.Response) -> bool
    data = {}
    data['status_code'] = response.status_code
    data['std_out'] = response.std_out
    data['std_err'] = response.std_err

    if data['status_code'] != 0:
        # This will be the message displayed
        action_result.add_data(data)
        return action_result.set_status(
            phantom.APP_ERROR, "Error: Returned a non-zero status code"
        )

    # This can still return values like 999.999.999.999
    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data['std_out'])
    # Get only valid IPs
    filtered_ips = []
    for ip in ips:
        if ph_utils.is_ip(ip):
            filtered_ips.append(ip)

    data['ips'] = filtered_ips

    action_result.add_data(data)
    return phantom.APP_SUCCESS
```

As a final thing to consider, the playbook editor will not be aware of any custom data paths which
your parser introduces. Using the above example, if you wanted to use the list of ips in a playbook,
you would need to type in the correct datapath manually (action_result.data.\*.ips).

For more information on datapaths and the ActionResult object, refer to the Phantom App Developer
Guide.

Both the **run script** and **run command** actions also support running commands asynchronously. By
default, the app will wait for these actions to finish. In the case of starting a long-running job
or some other command which you want to start but don't care for the output, then you can check the
**async** parameter. After the command starts, it will return a **command_id** and **shell_id** ,
which you can optionally use to retrieve the output of that command at a later time.
