[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## App Information

-   This LDAP application utilizes the LDAP3 library for Python. This was chosen, in part, due to
    the pythonic design of the library and the quality of the documentation. Both SSL and TLS are
    supported.
-   Please make sure to view additional documentation for this app on our [GitHub Open Source
    Repo!](https://github.com/phantomcyber/phantom-apps/tree/next/Apps/phadldap#readme)

## LDAP Ports Requirements (Based on Standard Guidelines of [IANA ORG](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) )

-   LDAP(service) TCP(transport protocol) - 389
-   LDAP(service) UDP(transport protocol) - 389
-   LDAP(service) TCP(transport protocol) over TLS/SSL (was sldap) - 636
-   LDAP(service) UDP(transport protocol) over TLS/SSL (was sldap) - 636

## Asset Configuration

The asset for this app requires an account with which to Bind and perform actions. If you are only
ever going to perform information gathering tasks (e.g. getting account attributes) then a standard
user account would be fine. However, if you plan on doing things like Unlocking, Resetting
Passwords, Moving objects, etc. - then you will need an account with permissions to actually perform
these actions. It is best practice to NOT use a "Domain Administrator" (or higher) account. Instead,
delegate the appropriate least-privilege access to a service account with a very strong password.
Lastly, it is strongly recommended to use SSL and disallow insecure (plain text and unsigned binds)
if at all possible.

## Run Query Action

This action provides the user the ability to run generic queries with the LDAP syntax. The action
takes a filter (in LDAP syntax), an optional search base to search within, and specific attributes
that you would like to return.

-   Common AD LDAP Run Query Examples

      

    -   Get Users belonging to a specific OU, Container, or Group

          

        -   filter = (samaccountname=\*)
        -   attributes = samaccountname;mail
        -   search_base = distinguishedNameOfOU/Container/Group

    -   List Group Names that a User belongs to

          

        -   filter = (&(member=distinguishedNameOfUserHERE)(objectClass=group))
        -   attributes = name

    -   Return results if mail attribute is present OR sAMAccountName matches '\*admin\*'

          

        -   filter = (\|(mail=\*)(samaccountname=\*admin\*))
        -   attributes = samaccountname;mail;userprincipalname;distinguishedname

    -   If you would like to learn more about LDAP Filter Syntax, check out this [Microsoft
        Wiki](https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx)

  
