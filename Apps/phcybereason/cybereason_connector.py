#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from cybereason_consts import *
import requests
import json
import traceback
from cybereason_session import CybereasonSession
from cybereason_poller import CybereasonPoller
from cybereason_query_actions import CybereasonQueryActions


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CybereasonConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CybereasonConnector, self).__init__()

        self._state = {}

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _get_string_param(self, param):
        return param

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # Set up a session by logging in to the Cybereason console.
        cr_session = CybereasonSession(self)
        self.save_progress('CybereasonSession created')
        cookies = cr_session.get_session_cookies()
        if (cookies.get("JSESSIONID")):
            # We have a session id cookie, so the authentication succeeded
            self.save_progress('Successfully connected to the Cybereason console and verified session cookie')
            return action_result.set_status(phantom.APP_SUCCESS, 'Successfully connected to the Cybereason console and verified session cookie')
        else:
            self.save_progress('Connectivity failed. Unable to get session cookie from Cybereason console')
            return action_result.set_status(phantom.APP_ERROR, 'Connectivity failed. Unable to get session cookie from Cybereason console')

    def _get_delete_registry_key_body(self, cr_session, malop_id, machine_name):
        query = {
            "queryPath": [
                {
                    "requestedType": "MalopProcess",
                    "filters": [],
                    "guidList": [malop_id],
                    "connectionFeature": { "elementInstanceType": "MalopProcess", "featureName": "suspects" }
                },
                {
                    "requestedType": "Process",
                    "filter": [],
                    "isResult": True
                }
            ],
            "totalResultLimit": 100,
            "perGroupLimit": 100,
            "perFeatureLimit": 100,
            "templateContext": "SPECIFIC",
            "queryTimeout": 120000,
            "customFields": [ "ownerMachine", "hasAutorunEvidence" ]
        }
        headers = { "Content-Type": "application/json" }
        url = self._base_url + "/rest/visualsearch/query/simple"
        res = cr_session.post(url=url, json=query, headers=headers)
        results = res.json()
        remediate_body = {
            "malopId": malop_id,
            "actionsByMachine": {},
            "initiatorUserName": ""
        }
        target_ids_added = set()
        for process_id, process_data in results["data"]["resultIdToElementDataMap"].items():
            if process_data["elementValues"].get("hasAutorunEvidence"):
                target_id = process_data["elementValues"]["hasAutorunEvidence"]["elementValues"][0]["guid"]
                matching_machines = list(filter(lambda machine: machine["name"].lower() == machine_name, process_data["elementValues"]["ownerMachine"]["elementValues"]))
                if len(matching_machines) > 0:
                    machine_id = matching_machines[0]["guid"]
                    if not remediate_body["actionsByMachine"].get(machine_id):
                        remediate_body["actionsByMachine"][machine_id] = []
                    if target_id not in target_ids_added:
                        remediate_body["actionsByMachine"][machine_id].append({
                            "targetId": target_id,
                            "actionType": "DELETE_REGISTRY_KEY"
                        })
                        target_ids_added.add(target_id)
        return remediate_body

    def _handle_delete_registry_key(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        malop_id = self._get_string_param(param['malop_id'])
        machine_name = param["machine_name"].lower()

        # Get the remediation target
        cr_session = CybereasonSession(self).get_session()
        remediate_body = self._get_delete_registry_key_body(cr_session, malop_id, machine_name)

        # Make the call to remediate the action
        headers = { "Content-Type": "application/json" }
        res = cr_session.post(self._base_url + "/rest/remediate", json=remediate_body, headers=headers)

        if res.status_code != 200:
            action_result.set_status(phantom.APP_ERROR, res.text)

        # Add a dictionary that is made up of the most important values from data into the summary
        result = res.json()
        action_result.add_data({
            "remediation_id": result["remediationId"],
            "initiating_user": result["initiatingUser"]
        })

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_sensor_status(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        malop_id = self._get_string_param(param.get('malop_id'))

        try:
            # Set up a session by logging in to the Cybereason console.
            cr_session = CybereasonSession(self).get_session()
            url = self._base_url + "/rest/visualsearch/query/simple"
            headers = { "Content-Type": "application/json" }
            post_data = {
                "queryPath": [
                    {
                        "requestedType": "MalopProcess",
                        "filters": [],
                        "guidList": [
                            malop_id
                        ],
                        "connectionFeature": {
                            "elementInstanceType": "MalopProcess",
                            "featureName": "suspects"
                        }
                    },
                    {
                        "requestedType": "Process",
                        "filters": [],
                        "connectionFeature": {
                            "elementInstanceType": "Process",
                            "featureName": "ownerMachine"
                        }
                    },
                    {
                        "requestedType": "Machine",
                        "filters": [],
                        "isResult": True
                    }
                ],
                "totalResultLimit": 1000,
                "perGroupLimit": 1200,
                "perFeatureLimit": 1200,
                "templateContext": "SPECIFIC",
                "queryTimeout": 30,
                "customFields": [
                    "isConnected",
                    "elementDisplayName"
                ]
            }
            res = cr_session.post(url=url, headers=headers, json=post_data)
            self.save_progress("Successfully fetched machine details from Cybereason console")
            machines_dict = res.json()["data"]["resultIdToElementDataMap"]
            for machine_id, machine_details in machines_dict.items():
                action_result.add_data({
                    "machine_id": machine_id,
                    "machine_name": machine_details["simpleValues"]["elementDisplayName"]["values"][0],
                    "status": "Online" if (machine_details["simpleValues"]["isConnected"]["values"][0] == "true") else "Offline"
                })
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, e)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_malop_comment(self, param):
        self.save_progress("In _handle_add_malop_comment function")
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        malop_id = self._get_string_param(param.get('malop_id'))
        self.save_progress("MALOP ID  :" + malop_id)

        comment = param.get('comment', "")
        self.save_progress("COMMENT  :" + comment)

        try:
            cr_session = CybereasonSession(self).get_session()

            endpoint_url = "/rest/crimes/comment/"
            url = self._base_url + endpoint_url + str(malop_id)
            self.save_progress(url)
            api_headers = {'Content-Type': 'application/json'}

            cr_session.post(url, data=comment.encode('utf-8'), headers=api_headers)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, e)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_malop_status(self, param):
        self.save_progress("In _handle_update_malop_status function")
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        malop_id = self._get_string_param(param.get('malop_id'))

        status = param.get('status')

        if status == 'Unread':
            status = "UNREAD"
        elif status == 'To Review':
            status = "TODO"
        elif status == 'Not Relevant':
            status = "FP"
        elif status == 'Remediated':
            status = "CLOSE"
        elif status == 'Reopend':
            status = "REOPEN"
        elif status == 'Under Investigation':
            status = "OPEN"
        else:
            self.save_progress("Invalid status selected ")
            self.finalize()

        try:
            cr_session = CybereasonSession(self).get_session()

            endpoint_url = "/rest/crimes/status"
            url = self._base_url + endpoint_url
            self.save_progress(url)
            api_headers = {'Content-Type': 'application/json'}
            query = json.dumps({malop_id: status})
            cr_session.post(url, data=query, headers=api_headers)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, e)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_isolate_machine(self, param):
        # Implement the handler here
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        malop_id = self._get_string_param(param.get('malop_id'))

        sensor_ids = self._get_malop_sensor_ids(malop_id)

        try:
            cr_session = CybereasonSession(self).get_session()

            endpoint_url = "/rest/monitor/global/commands/isolate"
            url = self._base_url + endpoint_url
            self.save_progress(url)
            api_headers = {'Content-Type': 'application/json'}
            query = json.dumps({"pylumIds": sensor_ids, "malopId": malop_id})

            cr_session.post(url, data=query, headers=api_headers)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, e)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unisolate_machine(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        malop_id = self._get_string_param(param.get('malop_id'))

        sensor_ids = self._get_malop_sensor_ids(malop_id)

        try:
            cr_session = CybereasonSession(self).get_session()

            endpoint_url = "/rest/monitor/global/commands/un-isolate"
            url = self._base_url + endpoint_url
            self.save_progress(url)
            api_headers = {'Content-Type': 'application/json'}
            query = json.dumps({"pylumIds": sensor_ids, "malopId": malop_id})

            cr_session.post(url, data=query, headers=api_headers)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, e)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_kill_process(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        malop_id = self._get_string_param(param["malop_id"])
        machine_id = self._get_string_param(param["machine_id"])
        remediation_user = param["remediation_user"]
        process_id = self._get_string_param(param["process_id"])

        try:
            cr_session = CybereasonSession(self).get_session()
            endpoint_url = "/rest/remediate"
            url = self._base_url + endpoint_url
            api_headers = {'Content-Type': 'application/json'}
            query = {
                "malopId": malop_id,
                "initiatorUserName": remediation_user,
                "actionsByMachine": {
                    machine_id: [
                        {
                            "targetId": process_id,
                            "actionType": "KILL_PROCESS"
                        }
                    ]
                }
            }
            res = cr_session.post(url, json=query, headers=api_headers)
            result = res.json()
            if len(result["statusLog"]) > 0:
                action_result.add_data({
                    "remediation_id": result["remediationId"],
                    "remediation_status": result["statusLog"][0]["status"]
                })
        except Exception as e:
            self.debug_print(str(e))
            self.debug_print(traceback.format_exc())
            return action_result.set_status(phantom.APP_ERROR, e)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_remediation_status(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        malop_id = self._get_string_param(param["malop_id"])
        remediation_user = param["remediation_user"]
        remediation_id = param["remediation_id"]

        try:
            cr_session = CybereasonSession(self).get_session()
            endpoint_url = "/rest/remediate/progress/" + remediation_user + "/" + malop_id + "/" + remediation_id
            url = self._base_url + endpoint_url
            res = cr_session.get(url)
            self.debug_print(res.text)
            result = res.json()
            status_log_length = len(result["statusLog"])
            error_obj = result["statusLog"][status_log_length - 1]["error"]
            action_result.add_data({
                "remediation_status": result["statusLog"][status_log_length - 1]["status"],
                "remediation_message": error_obj.get("message", "Unknown error") if error_obj is not None else "No error message"
            })
        except Exception as e:
            self.debug_print(str(e))
            self.debug_print(traceback.format_exc())
            return action_result.set_status(phantom.APP_ERROR, e)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_set_reputation(self, param):
        self.save_progress("In _handle_set_reputation function")
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        reputation_item = self._get_string_param(param.get('reputation_item_hash'))
        custom_reputation = param.get('custom_reputation')

        try:
            cr_session = CybereasonSession(self).get_session()

            endpoint_url = "/rest/classification/update"
            url = self._base_url + endpoint_url
            self.save_progress(url)
            api_headers = {'Content-Type': 'application/json'}
            if custom_reputation == 'Remove':
                reputation = json.dumps([{"keys": [reputation_item], "maliciousType": None, "prevent": False, "remove": True}])
            else:
                reputation = json.dumps([{"keys": [reputation_item], "maliciousType": custom_reputation, "prevent": False, "remove": False}])

            cr_session.post(url, data=reputation, headers=api_headers)
            self.save_progress(custom_reputation + "ed...")

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, e)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_malop_sensor_ids(self, malop_id):
        sensor_ids = []
        try:
            cr_session = CybereasonSession(self).get_session()

            endpoint_url = "/rest/visualsearch/query/simple"
            url = self._base_url + endpoint_url
            self.save_progress(url)
            api_headers = {'Content-Type': 'application/json'}
            query_path = {
                "queryPath": [
                    {
                        "requestedType": "MalopProcess",
                        "filters": [],
                        "guidList": [
                            malop_id
                        ],
                        "connectionFeature": {
                            "elementInstanceType": "MalopProcess",
                            "featureName": "suspects"
                        }
                    },
                    {
                        "requestedType": "Process",
                        "filters": [],
                        "connectionFeature": {
                            "elementInstanceType": "Process",
                            "featureName": "ownerMachine"
                        }
                    },
                    {
                        "requestedType": "Machine",
                        "filters": [],
                        "isResult": True
                    }
                ],
                "totalResultLimit": 1000,
                "perGroupLimit": 1200,
                "perFeatureLimit": 1200,
                "templateContext": "SPECIFIC",
                "queryTimeout": None,
                "customFields": [
                    "pylumId",
                    "elementDisplayName"
                ]
            }
            self.save_progress(str(query_path))
            res = cr_session.post(url, json=query_path, headers=api_headers)
            self.save_progress("Got result from /rest/visualsearch/query/simple")
            machines_dict = res.json()["data"]["resultIdToElementDataMap"]
            for machine_id, machine_details in machines_dict.items():
                sensor_ids.append(str(machine_details['simpleValues']['pylumId']['values'][0]))

        except Exception as e:
            self.save_progress(str(e))
        return sensor_ids

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'delete_registry_key':
            ret_val = self._handle_delete_registry_key(param)

        elif action_id == 'get_sensor_status':
            ret_val = self._handle_get_sensor_status(param)

        elif action_id == 'on_poll':
            poller = CybereasonPoller()
            ret_val = poller.do_poll(self, param)

        elif action_id == 'add_malop_comment':
            ret_val = self._handle_add_malop_comment(param)

        elif action_id == 'update_malop_status':
            ret_val = self._handle_update_malop_status(param)

        elif action_id == 'isolate_machine':
            ret_val = self._handle_isolate_machine(param)

        elif action_id == 'unisolate_machine':
            ret_val = self._handle_unisolate_machine(param)

        elif action_id == 'kill_process':
            ret_val = self._handle_kill_process(param)

        elif action_id == 'get_remediation_status':
            ret_val = self._handle_get_remediation_status(param)

        elif action_id == 'set_reputation':
            ret_val = self._handle_set_reputation(param)

        elif action_id == 'query_processes':
            query_action = CybereasonQueryActions()
            ret_val = query_action._handle_query_processes(self, param)

        elif action_id == 'query_machine':
            query_action = CybereasonQueryActions()
            ret_val = query_action._handle_query_machine(self, param)

        elif action_id == 'query_users':
            query_action = CybereasonQueryActions()
            ret_val = query_action._handle_query_users(self, param)

        elif action_id == 'query_files':
            query_action = CybereasonQueryActions()
            ret_val = query_action._handle_query_files(self, param)

        elif action_id == 'query_domain':
            query_action = CybereasonQueryActions()
            ret_val = query_action._handle_query_domain(self, param)

        elif action_id == 'query_connections':
            query_action = CybereasonQueryActions()
            ret_val = query_action._handle_query_connections(self, param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if not self._state:
            self._state = {}

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')
        self._username = config.get('username')
        self._password = config.get('password')

        return phantom.APP_SUCCESS

    def get_state(self):
        return self._state

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = CybereasonConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CybereasonConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
