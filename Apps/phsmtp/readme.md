[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2014-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## General Points

-   Attachments and HTML formatting are supported
-   The asset configuration parameter **Enable SMTPUTF8 support (Check this only if the SMTP server
    supports SMTPUTF8 option)** should be disabled if the SMTP server does not support the SMTPUTF8
    configuration option. For the SMTP servers supporting SMTPUTF8, please enable this parameter. If
    this parameter is kept disabled for the SMTP servers supporting SMTPUTF8, all the actions having
    Unicode characters in TO, CC or BCC attributes will fail due to encoding issues in Python 3
    installation of the app due to a known SDK behavior.
-   The **username** and **password** fields for an SMTP Asset are optional because some SMTP
    servers do not require any authentication to accept mail. The **ssl_config** and **port** fields
    are related, but only the field **port** is optional. This is because each of the ssl_config
    options has an associated default port number, and you only have to specify the port if you want
    to override that default. For example, the default SMTP port for StartTLS-style encryption is
    587, but it's also possible to do start TLS on port 25. So in that case, you may want to select
    StartTLS and specify port 25. The default port numbers are listed in this table:

|         SSL Method    | Port |
|-----------------------|------|
|          **None**     | 25   |
|          **SSL**      | 465  |
|          **StartTLS** | 587  |

## Playbook Backward Compatibility

-   The behavior of the following action has been modified. Hence, it is requested to the end-user
    to please update their existing playbooks by re-inserting the corresponding action blocks or by
    providing appropriate values to these action parameters to ensure the correct functioning of the
    playbooks created on the earlier versions of the app.

      

    -   Send RawEmail - To run this action, provide the **raw_email** parameter as a string
        separated using the new line character ('\\n' between headers like to, from, cc, bcc,
        subject) ('\\n\\n' before providing the body text or HTML after the headers). The example
        value for the same has been provided in the **Examples for Send RawEmail** section below.
        The action can also be executed using the playbook.  
        To run the action using playbook, the user can also provide the **raw_email** parameter as a
        multi-line string, i.e., any string enclosed within three double-quotes ("""some-string""")
        or three single-quotes ('''some-string''')

## Actions Key Points

-   Send Email

      

    -   For email consisting of HTML body to be processed correctly as HTML, it must start with
        either "\<!DOCTYPE html" declaration or "&lthtml" and the tag should end with ">"

-   Send Email and Send HTMLEmail

      

    -   For emails consisting of Unicode characters, set the **encoding** asset configuration flag
        to true.

-   Send RawEmail

      

    -   The **encoding** asset configuration flag does not apply to this action.

## Examples for Send RawEmail

-   The **raw_email** action parameter can be provided in the following ways.

      

    -   Example 1  
        **raw_email** =
        to:receiver@testdomain.com\\nfrom:sender@testdomain.com\\nsubject:Test\\n\\nThis is body
        text
    -   Example 2:  
        **raw_email** =
        to:receiver@testdomain.com\\nfrom:sender@testdomain.com\\nContent-type:text/html\\nsubject:HTML
        Test\\n\\n\<html>\<body>\<h2>This is test\</h2>\<br>This is some üñîçøðé
        data.\</body>\</html>
    -   Example 3:  
        **raw_email** =
        to:receiver1@testdomain.com,receiver2@testdomain.com\\nfrom:sender@testdomain.com\\nsubject:CommaSeparated
        Recipients Test\\n\\nThis is test data.
