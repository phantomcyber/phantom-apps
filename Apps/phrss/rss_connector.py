# File: rss_connector.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.vault import Vault
import phantom.rules as ph_rules
import rss_consts as rc

# Local Import
from parser_helper import parse_link_contents

# Usage of the consts file is recommended
# from rss_consts import *
import os
import json
import hashlib
import urllib.request
import tempfile
import feedparser
from time import mktime


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class RssConnector(BaseConnector):

    def __init__(self):
        super(RssConnector, self).__init__()
        self._state = None
        self._feed = None
        self._max_containers = None
        self._max_artifacts = None
        self._ignore_perrors = False
        self._feed_url = None
        self.save_html = False

    def _init_feed(self):
        self._feed = feedparser.parse(self._feed_url)
        if self._feed.bozo == 1:
            ex_type = type(self._feed.bozo_exception)
            if self._ignore_perrors and ex_type is feedparser.CharacterEncodingOverride:
                return phantom.APP_SUCCESS
            error_msg = self._feed.bozo_exception
            self.save_progress("Error reading feed: {}".format(error_msg))
            self.save_progress("Is this an RSS Feed?")
            self.is_test_connectivity()
            return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def is_test_connectivity(self):
        """

        Check the test connectivity action and append the failed status
        accordingly
        :return:
        """
        if self.get_action_identifier() == "test_connectivity":
            self.save_progress(rc.RSS_TEST_CONNECTIVITY_FAILED)

    def is_positive_int(self, value):
        """

        :param value: any integer/non-integer value
        :return boolean: if positive integer or not
        """
        try:
            value = int(value)
            return True if value >= 0 else False
        except ValueError:
            return False

    def _handle_test_connectivity(self, param):
        return self.set_status_save_progress(phantom.APP_SUCCESS, rc.RSS_TEST_CONNECTIVITY_PASSED)

    def _cmp_with_last_checked_entry(self, entry, last_checked_entry):
        if mktime(entry.published_parsed) <= last_checked_entry['timestamp']:
            return True
        return False

    def _save_html(self, html_file, name, container_id):
        if hasattr(Vault, 'get_vault_tmp_dir'):
            fd, path = tempfile.mkstemp(dir=Vault.get_vault_tmp_dir(), text=True)
        else:
            fd, path = tempfile.mkstemp(dir='/opt/phantom/vault/tmp', text=True)
        os.write(fd, html_file)
        os.close(fd)
        success, message, vault_id = ph_rules.vault_add(container_id, path, name)
        if success:
            return phantom.APP_SUCCESS, None
        return phantom.APP_ERROR, message

    def _handle_on_poll(self, param):
        if self.is_poll_now():
            self._max_containers = param.get('container_count', 1)
            self._max_artifacts = param.get('artifact_count', 10)

            if not (self.is_positive_int(self._max_containers) and self.is_positive_int(self._max_artifacts)):
                return self.set_status(phantom.APP_ERROR, rc.RSS_ARTIFACTS_CONTAINERS_VALIDATION_FAILED)

            self._max_containers = int(self._max_containers)
            self._max_artifacts = int(self._max_artifacts)

        self.save_progress(
            "Parsing {} entries from {}".format(
                'all' if self._max_containers == 0 else 'latest {}'.format(self._max_containers),
                self._feed['feed']['title']
            )
        )
        self.save_progress(
            "Saving {} artifacts per entry".format(
                'all' if self._max_artifacts == 0 else self._max_artifacts
            )
        )

        if self._max_containers:
            entries = self._feed.entries[0:self._max_containers]
        else:
            entries = self._feed.entries

        try:
            last_checked_entry = self._state['last_checked_entry']
        except KeyError:
            last_checked_entry = {
                'timestamp': 0.0,
                'feed_url': self._feed_url
            }
        else:
            # Feed URL has changed, reset the state
            if last_checked_entry['feed_url'] != self._feed_url:
                last_checked_entry = {
                    'timestamp': 0.0,
                    'feed_url': self._feed_url
                }

        new_entries = []
        for entry in entries:
            if self._cmp_with_last_checked_entry(entry, last_checked_entry):
                break
            new_entries.append(entry)

        # Reverse so latest article shows up first
        new_entries = list(reversed(new_entries))

        for entry in new_entries:
            container = {
                'name': entry.title
            }

            try:
                # Get html page
                request = urllib.request.Request(entry.link, headers={'User-Agent': 'Chrome 41.0.2227.0'})
                resp_content = urllib.request.urlopen(request).read()
            except Exception as e:
                self.debug_print("Cannot read: {}".format(entry.link))
                self.debug_print("Exception: {}".format(str(e)))
                continue

            ret_val, msg, artifacts = parse_link_contents(self, resp_content)
            if phantom.is_fail(ret_val):
                self.save_progress("Error processing link: {}".format(entry.link))
                self.save_progress("Error: {}".format(msg))
                continue

            if self._max_artifacts:
                # We are also going to add the link as an artifact
                artifacts = artifacts[0:self._max_artifacts - 1]

            artifacts.append({
                'cef': {
                    'requestURL': entry.link
                },
                'name': 'Entry URL'
            })

            title = entry.title[0] if type(entry.title) == list else entry.title
            title = title.encode('ascii', 'ignore')
            source_data_identifier = hashlib.sha256(
                title + str(mktime(entry.published_parsed)).encode('ascii')).hexdigest()

            container['artifacts'] = artifacts
            container['source_data_identifier'] = source_data_identifier

            ret_val, msg, cid = self.save_container(container)
            if phantom.is_fail(ret_val):
                return self.set_status(phantom.APP_ERROR, "Error saving container: {}".format(msg))

            if self.save_html:
                resp, msg = self._save_html(resp_content, entry.title, cid)
                if phantom.is_fail(resp):
                    return self.set_status(
                        phantom.APP_ERROR, "Error saving file to vault: {}".format(msg)
                    )

        if not self.is_poll_now():
            if len(new_entries) > 0:
                last_checked_entry['timestamp'] = mktime(new_entries[-1].published_parsed)
                self._state['last_checked_entry'] = last_checked_entry

        return self.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == rc.ACTION_ID_TEST_CONNECTIVITY:
            ret_val = self._handle_test_connectivity(param)

        elif action_id == rc.ACTION_ID_ON_POLL:
            ret_val = self._handle_on_poll(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        config = self.get_config()
        self._state = self.load_state()
        self._feed_url = config.get("rss_feed")
        self._max_containers = config.get('container_count', 0)
        self._max_artifacts = config.get('artifact_count', 0)
        self._ignore_perrors = config.get('ignore_perrors', False)
        self.save_html = config.get("save_file", False)

        if not (self.is_positive_int(self._max_containers) and self.is_positive_int(self._max_artifacts)):
            self.is_test_connectivity()
            return self.set_status(phantom.APP_ERROR, rc.RSS_ARTIFACTS_CONTAINERS_VALIDATION_FAILED)

        self._max_containers = int(self._max_containers)
        self._max_artifacts = int(self._max_artifacts)

        return self._init_feed()

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb
    import argparse
    import requests

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = RssConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
