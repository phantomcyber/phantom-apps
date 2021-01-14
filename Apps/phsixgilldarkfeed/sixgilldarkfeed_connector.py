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

# Usage of the consts file is recommended
from sixgilldarkfeed_consts import *

# Importing Test Connectivity Connector
from sixgill_test_connectivity_connector import SixgillTestConnectivityConnector
from sixgill_on_poll_connector import SixgillOnPollConnector
from sixgill_reputation import SixgillReputation

import json


class SixgillDarkfeedConnector(BaseConnector):
    def __init__(self):

        # Call the BaseConnectors init first
        super(SixgillDarkfeedConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def handle_action(self, param):
        action_id = self.get_action_identifier()
        self.save_progress("Connecting to Sixgill Darkfeed...")
        if action_id == "test_connectivity":
            test_connectivity_connector = SixgillTestConnectivityConnector(self)
            return test_connectivity_connector.test_connectivity()
        elif action_id == "on_poll":
            on_poll_connector = SixgillOnPollConnector(self)
            return on_poll_connector.on_poll(param)
        elif action_id == "enrich_ip":
            ip_reputation_connector = SixgillReputation(self)
            return ip_reputation_connector.ip_reputation(param)
        elif action_id == "enrich_url":
            url_reputation_connector = SixgillReputation(self)
            return url_reputation_connector.url_reputation(param)
        elif action_id == "enrich_domain":
            domain_reputation_connector = SixgillReputation(self)
            return domain_reputation_connector.domain_reputation(param)
        elif action_id == "enrich_hash":
            hash_reputation_connector = SixgillReputation(self)
            return hash_reputation_connector.hash_reputation(param)
        elif action_id == "enrich_post_id":
            postid_reputation_connector = SixgillReputation(self)
            return postid_reputation_connector.postid_reputation(param)
        elif action_id == "enrich_threat_actor":
            actor_reputation_connector = SixgillReputation(self)
            return actor_reputation_connector.actor_reputation(param)
        else:
            return self.set_status_save_progress(phantom.APP_ERROR, SIXGILL_ACTION_NOT_SUPPORTED.format(action_id))


def main():
    import pudb
    import argparse
    import requests

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        # disable certificate warnings for self signed certificates
        requests.packages.urllib3.disable_warnings()
        try:
            login_url = SixgillDarkfeedConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)
    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SixgillDarkfeedConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
