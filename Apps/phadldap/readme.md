# AD LDAP
## Community App Project #1

First:  
My thanks to everyone who is actively contributing to the Phantom community. Doubly-so for those of you working on Apps in our GitHub repo and in our Slack channel.

Second:  
This app serves a few purposes. The primary is that I wanted additional features available for LDAP. The second is that I thought some of the hackers in the community might want to dig into a project "owned" by us - and finally, for folks just developing their dev chops, a place to learn and grow.

Third:  
This page is intended to serve as a _living_ document for this app with plently of use-cases, examples, and technical information. Please feel free to contribute!


## The Documentation
- [App Information](#app-information)
- [App Configuration](#app-configuration)
- [Actions](#actions)
    - [Run Query](#run-query)
    - [Add group members](#add-group-members)
    - [Remove group members](#remove-group-members)
    - [Get Attributes](#get-attributes)
    - [Set Attributes](#set-attributes)
    - [Disable Account](#disable-account)
    - [Enable Account](#enable-account)
    - [Unlock Account](#unlock-account)
    - [Reset Password](#reset-password)
    - [Move Object](#move-object)

## App Information
This LDAP application utilizes the [LDAP3](https://ldap3.readthedocs.io/) library for Python. This was chosen, in part, due to the pythonic design of the library and the quality of the documentation.

The AD LDAP app only supports [Simple Binding](https://ldap3.readthedocs.io/bind.html#simple-bind) at this time but other methods (e.g. NTLM) could be added relatively easily. It should be noted that [SSL](https://ldap3.readthedocs.io/ssltls.html) and [TLS](https://ldap3.readthedocs.io/ssltls.html#the-tls-object) are supported.


### App Configuration
The configuration for this app is relatively straightforward. Let's looks at each component:

First, you'll need an account with which to Bind and perform actions. If you are only ever going to perform *information gathering* tasks (e.g., getting account attributes) then a standard user account would be fine. However, if you plan on doing things like Unlocking, Resetting Passwords, Moving objects, etc. - then you will need an account with permissions to actually perform these actions.  I would caution you to NOT use a "Domain Administrator" (or higher) account. Instead, delegate the appropriate least-privilege access to a service account with a very strong password... In other words, harden the account.
Obviously this can require more thorough testing than just giving the account Domain Admin privs... but thats why you make the big bucks. :)


Second: If you find yourself NOT using SSL, then you should take a good, hard look at why you're doing that. If you don't use SSL then someone could observe the password crossing over the wire. This is bad. Instead: fix SSL. If you have other binding requirements (other than Basic), raise an Issue on the project, maybe we can get it implemented.

(As an aside: My recommendation as a security professional is to disallow insecure (plaintext AND unsigned binds) if at all possible ([ref](#references): 1, 2, 3))

## Actions
### Run Query
One of the things I had been missing from the original Phantom LDAP application was a _generic_ query command. This app has implemented such functionality which will be demonstrated presently.

*Note: This command is useful for those who are familiar with LDAP syntax.*

Imagine you've run the following query:  
`(|(mail=*)(samaccountname=*admin*))`

![](.docs/run_query_action.png)

The effectively says: "If the mail attribute is present or samaccountname matches '\*admin\*', return results. Also in the screenshot above, I have omitted the searchbase which, in this app, means the root dn will be found and used (see `_get_root_dn()` for implementation details). Finally, we name the following attributes to be gathered:  

`samaccountname;mail;userprincipalname;distinguishedname` (Note: semi-colon separated)

In my lab, I got the following results:

![](.docs/run_query_result.png)

Note that the UI has a custom renderer to show all the attributes requested.

#### Important Notes for 'Run Query':
Because the Phantom architecture requires the resulting values in the data path to be coded during app-development, the attributes dynamically requested cannot be defined in the json file. Consequently, they are not available when using the VPE. Instead, you must plug in the attribute by name. For an arbitrary example, imagine you have a playbook that periodically runs looking for users who *do* have a `manager` assigned but do *not* have a `mail` attribute assign. We might set up a playbook like this:

![](.docs/run_query_playbook.png)

We might set our LDAP params like the following. Note that the query I'm using in this example is: `(&(manager=*)(!(mail=*)))`. This can be thought of as:
- AND
    - manager must exist
    - NOT
        - mail must exist

Or more plainly: "manager attribute must be populated and the mail attribute must not."

![](.docs/run_query_ldap_params.png)

Now we can format the response in preperation for adding a note.

![](.docs/run_query_format_params.png)

In the above screenshot, you see that there is a datapath available for selection called `get_users_with_no_mail:action_result.data.*.entries.*.attributes` (circled in red). However, the attributes we selected in the LDAP Query block (samaccountname;mail;manager) are not see in the UI. Therefore, you must type the attribute name in as I have done in the second, bottom circled section (where I've added ".manager").  Interestingly, Active Directory returns those with Microsoft's internal mixed-case formatting - like samaccountname = sAMAccountName. This is difficult to remember when trying to select a field, so to reduce the friction with that, the App automatically lower-cases all attribute names.

Finally, we just call the API action to add a note using the output of our format block and run the playbook. (NOTE: For the astute amongst you that noticed an inconsistency between screenshots - I removed the `mail` attribute for this demo... So, the screenshots aren't lying, the truth changed.)

![](.docs/run_query_playbook_run.png)

And we can see the users were found and added to a note.

![](.docs/run_query_added_note.png).

Of course, the output of `run query` could easily be used as input to many other AD LDAP actions or actions of other Apps.

---

### Add Group Members
The `add group members` action allows for a many-to-many group modification. Specifically, any number of group members can be added to any number of groups. For example, consider the screenshot below.

![](.docs/add_grpmem_action.png)

Here, the users `robert` and `sam` will be added to the groups `splunk-admins` and `phantom-admins`. This is helpful in cases where certain actions might necessitate group additions (or removals) to multiple groups. Any number of situations might come to mind where this could be useful, for example a "no interactive logon" group used by a GPO and a "disable-sso" group tied to the single sign-on environment might be used during a phishing remediation.

Also, as is the goal with all actions of the "ADLDAP" App, we include the "use_samaccountname" parameter. This allows for the usage of sAMAccountName instead of distinguishedName attributes to reference objects in the directory. However:  
*If you use this option, then both groups AND users must be a semi-colon separated list of samaccountnames*. Do not mix distinguishednames and samaccountnames, it will not work.

Another interesting point to note is that the `add/remove groups members` actions are not tied to _users_. Other Active Directory objects (such as computers) can also be added (and removed) from groups.

Let's look at a quick, and relatively contrived, example of using the `add group members` command. Imagine we have a lab and have just spun up a new analytics group. These people have the 'analytics' department attribute set in Active Directory and we want to add them to the 'lab-employees' and the 'splunk-analysts' group. However, we only want to add people with the 'analytics' department. Here is a screenshot of our starting scenario:

![](.docs/add_grpmem_ad_pre.png)

You can see that the folks in the Analytics group are neither in the 'splunk-analysts' group nor the 'lab-employees' group. So we'll write a little playbook with the `run query` action and the `add group members` to set this right. One important thing to know is that the first playbook below is the _easiest_ way to implement the logic but is not optimized for performance. I will cover that in the [Important Notes](#Important-notes-for-add/remove-group-members) section below.

The playbook looks like the following:  
![](.docs/add_grpmem_playbook_nonoptimal.png)

The first block is our query block. You can read about this more generally in the ![](#run-query) section, but the settings here are as follows. Note that our LDAP query is `(department=analytics)`.

![](.docs/add_grpmem_ldap_query.png)

This block can directly be connected to the `add group members` block and configured thusly:

![](.docs/add_grpmem_add_nonopt.png)

This command will make several things available to the data path, including all of the attributes you requested (in this case, just 'samaccountname') - but they (the selected attributes) will not be availble to select in the UI due to reasons covered in the [run query](#run-query) section, so we'll have to type those in here. In the screenshot above, you can see that I have appended ".samaccountname" to the selected attribute of `run_query_1:action_result.data.*.entries.*.attributes` to make `run_query_1:action_result.data.*.entries.*.attributes.samaccountname`, which was used as the input to `members` field. You can also see that the groups to which the users will be added are `splunk-analysts` and `lab-employees` (separated by a semi-colon).

When this is run, the output displays the distinguishedNames and function (add or remove) of the user. The following screenshot is an example:

![](.docs/add_grpmem_action_ui.png)


#### Important Notes for Add/Remove Group Members
One important note regarding this (and `remove group members`) action is around optimization. The previous example set-up works just fine and can be used without issue. However, because the `add group members` block is connected directly to the `run query` block, the `add group members` block will be called once for each result returned by `run query`. So, if a large number of results are returned, then Domain Controller is going to be hit once for each user instead of a single connection doing all the work.

How to optimize? Well, the `add group members` block is built to support any number of users being passed in and then it will only connect to the directory once for all of them - much faster. The set-up for this is actually only slightly more complicated than the one above. It only adds a single format block and will look something like this:

![](.docs/add_grpmem_playbook_optimal.png)

This format block is configured like this:

![](.docs/add_grpmem_format.png)

The top red square shows the required formatting for looping (see documentation). The format is as follows:
```
%%
{0};
%%
```

The second red block shows input to the format block being the fully populated attribute: `run_query_1:action_result.data.*.entries.*.attributes.samaccountname`.

What this will do is construct a string (instead of a list) for input in the `add group members` block. That will allow the block to optimize it's connection to the directory and do all the group adjustments with a single bind operation.

Ultimately, this is the recommended technique for performance but ultimately, the design choices are yours.

---

### Remove Group Members

TODO: See [Add Group Members](#add-group-members)

---

### Get Attributes
The `get attributes` action is useful if you do not wish to specify a full LDAP query using the `run query` action but would rather just specify some objects and get their associated attributes back. This action solely works with AND logic. In other words, it will return any results found for all principals entered.

A deviation from the norm with this action is that we allow enter generic security principals instead of just distinguishedname or samaccountname. What does this mean for you? It means that you can enter any of:

- samaccountname
- userprincipalname
- distinguishedname

Additionally, you can "mix/match". For example you might enter: `sam;cn=user,ou=accounting,dc=company,dc=lab` and the system will split out `sam` and `cn=user,ou=accounting,dc=company,dc=lab` and run queries for both. This works because under the hood the following query is run:

```
for i in principal:
    query += "(userprincipalname={0})(samaccountname={0})(distinguishedname={0})".format(i)
query += ")"
```

This will find any of the three types mentioned.

Let's look at a simple use-case for `get attributes`. In this example we are simply going to prompt a user to enter a principal from a prompt as well as some desired attributes.  We will retrieve them and then have another prompt to display what was found.  Of course this is a trivial example, but one can imagine using the command for context enrichment in an unlimited set of use-cases.

The playbook:
![](.docs/get_attributes_playbook.png)

When the first prompt fires, it asks the questions. See screenshot below:

![](.docs/get_attributes_prompt1.png)

And upon completing the prompt, `get attributes` fires, collects the data, and responds back:

![](.docs/get_attributes_prompt2.png)

In the screenshot above you may notice that what was returned was the full JSON object. This may not as useful to you as, say, specific attributes being returned by name. What's going on here?

In the configuration for the second prompt, I had it configured thusly:

![](.docs/get_attributes_prompt2_json.png)

The fact that I was using `get_attribute_1:action_result.data.*.entries.*.attributes` and not specifying a _specific_ attribute means that it is going to return the entire structure back to me. Let's imagine I changed it to look like the following:

![](.docs/get_attributes_prompt2_manager.png)

Now when I run the same playbook, the second prompt gives me just the action I specified:

![](.docs/get_attributes_prompt2_attr.png)

The individual attributes are not able to be selected in the VPE due to the reasons specified [here](#Important-Notes-for-Run-Query). So just like `run query`, you will have to specify the ones you want by appending the attribute name to the parameter.


# References
1. https://blogs.technet.microsoft.com/russellt/2016/01/13/identifying-clear-text-ldap-binds-to-your-dcs/
2. https://blogs.technet.microsoft.com/askds/2008/04/02/directory-services-debug-logging-primer/
3. https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements
