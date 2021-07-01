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
from phantom import vault

# Usage of the consts file is recommended
# from oletools_consts import *
import requests
import json
import oletools.oleid
from oletools.mraptor import MacroRaptor
from oletools import olevba


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class OletoolsConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(OletoolsConnector, self).__init__()

        self._state = None

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_mraptor_scan(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        summary = action_result.update_summary({})

        vault_id = param['vault_id']

        success, message, info = vault.vault_info(vault_id=vault_id, container_id=self.get_container_id(), trace=True)

        if phantom.is_fail(success):
            return action_result.set_status(phantom.APP_ERROR, message)

        vault_path = info[0]["path"]
        oid = oletools.oleid.OleID(vault_path)
        indicators = oid.check()

        result = {
            "oleid": {},
            "mraptor": {}
        }

        for i in indicators:
            result["oleid"][i.id] = {"id": i.id, "name": i.name, "value": str(i.value)}

        summary["ftype"] = result["oleid"]["ftype"]["value"]

        vba_parser = olevba.VBA_Parser(filename=vault_path)
        if vba_parser.detect_vba_macros():
            vba_code_all_modules = ''
            vba_code_all_modules = vba_parser.get_vba_code_all_modules()

            mraptor = MacroRaptor(vba_code_all_modules)
            mraptor.scan()
            result["mraptor"] = mraptor.__dict__
            summary['suspicious'] = mraptor.suspicious

        action_result.add_data(result)

        # Add a dictionary that is made up of the most important values from data into the summary
        if not summary.get('suspicious'):
            summary["suspicious"] = False

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'mraptor_scan':
            ret_val = self._handle_mraptor_scan(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

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

        return phantom.APP_SUCCESS

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
            login_url = OletoolsConnector._get_phantom_base_url() + '/login'

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

        connector = OletoolsConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
