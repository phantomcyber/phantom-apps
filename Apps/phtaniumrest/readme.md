[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2019-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
## Playbook Backward Compatibility

-   The existing action parameters have been modified for the action given below. Hence, it is
    requested to the end-user to please update their existing playbooks by re-inserting \| modifying
    \| deleting the corresponding action blocks or by providing appropriate values to these action
    parameters to ensure the correct functioning of the playbooks created on the earlier versions of
    the app.

      

    -   Run Query - 3 new action parameters 'wait_for_results_processing',
        'return_when_n\_results_available', 'wait_for_n\_results_available' are added which helps to
        limit the data fetched from the Tanium server.

-   New action 'Get Question Results' has been added. Hence, it is requested to the end-user to
    please update their existing playbooks by inserting the corresponding action blocks for this
    action on the earlier versions of the app.

## Asset Configuration

-   **Consider question results complete at (% out of 100)**

<!-- -->

-   Consider Tanium question results complete at this value, a percentage out of 100. This parameter
    impacts the **run query** and **list processes** actions only. Note that a similar value can be
    defined in Tanium user preferences – you might want to reflect the same value in your app asset
    configuration as you use in your Tanium user configuration. The time spent returning your
    results is dependent on how much data you have on your Tanium instance and you may want your
    action to end with a certain percentage threshold instead of waiting for Tanium to return 100%
    of the results.

## Permissions for Interacting with Tanium REST API

-   **Actions may fail if the account you are using to connect to Tanium does not have sufficient
    permissions.**

      
      

<!-- -->

-   Computer Groups

      

    -   A component of Tanium permissions is the “Computer Groups” which an account can operate on.
        Please ensure the account you used to configure the Tanium REST API app has access to any
        machines you run queries or actions on.

      

-   Suggested Roles for Phantom Account in Tanium

      

    -   The following Tanium Roles shown below can be configured within Tanium and applied to the
        account used to connect to Phantom. Note that these roles represent guidance by the Splunk
        Phantom team based on testing against Tanium 7.3.314. **The permissions required in your
        environment may vary.**

    -   On Tanium 7.3.314, roles can be configured by selecting Permissions > Roles in the Tanium
        UI. Roles can be applied to a user account by selecting Administration > Users > (View
        User) > Edit Roles in the Tanium UI.

    -   Alternatively, you can **Import from XML** directly under Permissions > Roles in the Tanium
        UI. The XML files containing the roles described below are attached to this app's folder.

          
          
        `                     Role #1 Name:                    Phantom All Questions         `

        -   `                         Permissions:                        Can Ask Question and Saved Question. Needed for run query and list processes actions.           `
        -   `                         Ask Dynamic Question:                        Yes           `
        -   `                         Show Interact:                        Yes           `
        -   `                         Advanced Permissions:                        Read Sensor, Read Saved Question           `

        `                               Role #2 Name:                    Phantom Actions         `

        -   `                         Permissions:                        Can execute actions only. Needed for execute action and terminate process.           `
        -   `                         Show Interact:                        Yes           `
        -   `                         Advanced Permissions:                        Read Action, Write Action, Read Package           `

## Pagination

-   Pagination is not implemented in this release. So, the results for the actions mentioned below
    will be the results that are fetched in a single API call.

      

    -   List processes
    -   List questions
    -   Run query

## How to use Run Query Action

-   The **Run Query** action uses **Tanium's Interact Question Bar** to ask questions to retrieve
    information from endpoints. For example, you can ask a question that determines whether any
    endpoints are missing critical security patches.

-   Parameter Information:  
    These parameters modify questions asked using one of the two modes of operation specified below.
    -   **wait_for_results_processing:** Some long-running sensors return intermediate results with
        the contents "results currently unavailable", and then [later the sensor fills in the
        results](https://docs.tanium.com/interact/interact/results.html#:~:text=Results%20Currently%20Unavailable)
        . This option instructs the App to wait until the results are returned to Tanium and only
        after that return the final results. The waiting is still time bounded by the
        **timeout_seconds** setting.
    -   **return_when_n\_results_available:** When set, the Tanium REST App will return results to
        the playbook as soon as \`N\` results are returned, even if the **Consider question results
        complete at (% out of 100)** percentage has not been met. This is useful in scenarios where
        the playbook expects to get at most \`N\` results, and wants to return as soon as this
        occurs.
    -   **wait_for_n\_results_available:** When set, the Tanium REST App will wait (up to the
        **timeout_seconds** timeout) until at least \`N\` results are returned. This is helpful in
        situations where the Tanium server is under high utilization. Sometimes the App will
        estimate that 100% of hosts have reported results, even when there are a few stragglers
        left. If the playbook author knows that it should be getting \`N\` results, this will wait
        past the **Consider question results complete at (% out of 100)** percentage.

-   Two modes of operation are supported for the run query action:

      
      

    -   Manual Questions
        -   Using Tanium question syntax, users can directly provide the question to be asked to the
            Tanium server in the **query_text** parameter. For more information on Tanium's question
            syntax, [click here.](https://docs.tanium.com/interact/interact/questions.html)

        -   Make sure the **is_saved_question** box is unchecked since you are providing a question
            from scratch.

        -   Use the **group name** parameter to run your query on a particular computer group in
            your Tanium instance. Users can create a computer group with specific IP
            addresses/hostnames on the Tanium UI under Administration>Computer Groups. For a guide
            on how to create/manage computer groups in Tanium, [click
            here.](https://docs.tanium.com/platform_user/platform_user/console_computer_groups.html)

              

            -   NOTE: If the **group_name** parameter is not provided, the query will be executed on
                all registered IP addresses/hostnames in your Tanium instance.

              

        -   Parameterized Query

              

            -   Users can provide the parameter(s) of a Parameterized query in square
                brackets(\[parameter-1, parameter-2, ..., parameter-n\]).

                  

                -   Example: Get Process Details\["parameter-1","parameter-2"\] from all machines
                    with Computer Name contains localhost

            -   Users can ignore the parameter part in the query if they want the default value to
                be considered. Below are the 2 ways a user can achieve this:

                  

                -   Query: Get Process Details from all machines with Computer Name contains
                    localhost
                -   Query: Get Process Details\["",""\] from all machines with Computer Name
                    contains localhost

            -   If a user wants to add only one parameter out of two parameters, users can keep the
                parameter empty. Below are the examples:

                  

                -   Example: Get Process Details\["parameter-1",""\] from all machines with Computer
                    Name contains localhost
                -   Example: Get Process Details\["","parameter-2"\] from all machines with Computer
                    Name contains localhost

            -   For two or more sensors in a query, users can select one of the below:

                  

                -   Provide value for all the parameters of all the sensors in the query

                      

                    -   Example: Get Child Processes\["parameter-1"\] and Process
                        Details\["parameter-2","parameter-3"\] from all machines

                -   Do not provide value for any of the parameters of any of the sensors in the
                    query

                      

                    -   Example: Get Child Processes and Process Details from all machines

                -   Provide value for the parameters you want to provide. The parameters for which
                    you don't want to add value, please use double quotes("")

                      

                    -   Example: Get Child Processes\[""\] and Process Details\["SHA1", ""\] from
                        all machines
                    -   Example: Get Child Processes\["csrss.exe"\] and Process Details\["", ""\]
                        from all machines

                  

            -   Scenarios:

                  

                1.  If the Child Processes sensor expects 1 parameter and Process Details expects 2
                    parameters. But the user provides only 2 parameters instead of 3, then action
                    will fail with a proper error message.
                    -   Example: Get Child Processes\["parameter-1"\] and Process
                        Details\["parameter-2"\] from all machines
                2.  If the Child Processes sensor expects 1 parameter and Process Details expects 2
                    parameters. But the user provides more than 3 parameters, then action will fail
                    with a proper error message.
                    -   Example: Get Child Processes\["parameter-1", "parameter-2"\] and Process
                        Details\["parameter-3", "parameter-4"\] from all machines
                3.  If the Child Processes sensor expects 1 parameter and Process Details expects 2
                    parameters. But if the user does not provide any parameter in the Child
                    Processes sensor and 3 parameters in Process Details sensor, then the first
                    parameter from Process Details will be considered as the only parameter of the
                    Child Processes sensor and the action will fetch the results accordingly.
                    -   Query provided: Get Child Processes and Process Details\["parameter-1",
                        "parameter-2", "parameter-3"\] from all machines
                    -   Query that will be executed because of API limitations: Get Child
                        Processes\["parameter-1"\] and Process Details\["parameter-2",
                        "parameter-3"\] from all machines
                4.  If the Child Processes sensor expects 1 parameter and Process Details expects 2
                    parameters. But if the user provides 2 parameters in Child Processes sensor and
                    1 parameter in Process Details sensor, then the second parameter from Child
                    Processes sensor will be considered as the first parameter of the Process
                    Details sensor and the only parameter of the Process Details sensor will be
                    considered as the second parameter of the same. The action will fetch the
                    results accordingly.
                    -   Query provided: Get Child Processes\["parameter-1", "parameter-2"\] and
                        Process Details\["parameter-3"\] from all machines
                    -   Query that will be executed because of API limitations: Get Child
                        Processes\["parameter-1"\] and Process Details\["parameter-2",
                        "parameter-3"\] from all machines

        -   Example Run 1 - Get Computer Name:

              

            -   `                             query text                            : Get Computer Name from all machines             `

            -   `                             is saved question                            : False             `

            -   `                             group name                            :             `

            -   `                             timeout seconds                            : 600             `

                  
                `                             `

        -   Example Run 2 - Get Computer Name for Specified Computer Group:

              

            -   `                             query text                            : Get Computer Name from all machines             `

            -   `                             is saved question                            : False             `

            -   `                             group name                            : centos-computers             `

            -   `                             timeout seconds                            : 600             `

                  
                `                             `

        -   Example Run 3 - A Complex Query:

              

            -   `                             query text                            : Get Trace Executed Processes[1 month,1522723342293|1522726941293,0,0,10,0,rar.exe,"",-hp,"","",""] from all machines             `

            -   `                             is saved question                            : False             `

            -   `                             group name                            :             `

            -   `                             timeout seconds                            : 600             `

                  
                `                             `

        -   Example Run 4 - List Process Details for a Specified Device:

              

            -   `                             query text                            : Get Process Details["",""] from all machines with Computer Name contains localhost             `

            -   `                             is saved question                            : False             `

            -   `                             group name                            : centos-computers             `

            -   `                             timeout seconds                            : 600             `

                  
                `                             `

          

    -   Saved Questions

          

        -   Users can create 'Saved Questions' on the Tanium UI under Content>Saved Questions and
            provide the name of that saved question in the **query_text** parameter to fetch
            appropriate results. For a guide on how to create/manage the Saved Questions on your
            Tanium instance, [click
            here.](https://docs.tanium.com/interact/interact/saving_questions.html)

        -   The **is_saved_question** box must be checked for this to work correctly.

              
              

        -   Example Run:

              

            -   `                               query text                              : My Computers              `

            -   `                               is saved question                              : True              `

            -   `                               timeout seconds                              : 600              `

                  
                `                               `

  

## How to use Terminate Process Action

-   Please follow the steps below to execute this action successfully:

      

    -   Create and save a package on the Tanium server with a meaningful package name and add a
        command to terminate the required process in the package's command section.
    -   To terminate the process of particular computers, users can create a computer group with the
        IP address/hostname of the target computers and can specify that group name in the
        **group_name** parameter.
    -   If the **group_name** parameter is not provided, then the terminate process action will be
        executed on all the registered IP addresses/hostnames.

  

## How to use Execute Action

-   The 'Execute Action' action will cause a specified Tanium Package to be executed on the
    specified group.

      

    -   Create and save a package on the Tanium server with a meaningful package name and add a
        command in the package's command section, or just use an existing package.

    -   Any parameters required by the specified package must be supplied with a valid JSON via the
        **package_parameters** parameter. For example,
        `         {"$1":"Standard_Collection", "$2":"SCP"}        `

    -   To execute this action on particular computers, users can create a computer group with the
        IP address/hostname of the target computers and can specify that group name in the
        **group_name** parameter.

    -   If the **group_name** parameter is not provided, then the action will be executed on all the
        registered IP addresses/hostnames.

    -   Example Run:

          

        -   `                         action name                        : Splunk Live Response Test           `

        -   `                         action group                        : Default           `

        -   `                         package name                        : Live Response - Linux           `

        -   `                         package parameters                        : {"$1":"Standard_Collection", "$2":"SCP"}           `

        -   `                         group name                        : centos-computers           `

              
            `                         `

  
