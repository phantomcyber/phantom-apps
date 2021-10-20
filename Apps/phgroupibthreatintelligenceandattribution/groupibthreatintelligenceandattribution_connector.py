# File: groupibthreatintelligenceandattribution_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from groupibthreatintelligenceandattribution_consts import *
import requests
from pytia import TIAPoller
from dateparser import parse
import json


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class GroupIbThreatIntelligenceAndAttributionConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(GroupIbThreatIntelligenceAndAttributionConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._gib_tia_connector = TIAPoller("", "", "")
        self._collections = {}

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = ERR_CODE_MSG
        error_msg = ERR_MSG_UNAVAILABLE

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
        except:
            pass

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _setup_generator(self, collection_name, date_start, date_end=None, last_fetch=None):
        collection_info = INCIDENT_COLLECTIONS_INFO.get(collection_name, {})
        keys = {**BASE_MAPPING_CONTAINER, **collection_info.get("container", {})}
        self._gib_tia_connector.set_keys(collection_name, keys)

        if collection_name == "compromised/breached":
            if not last_fetch:
                last_fetch = date_start
            generator = self._gib_tia_connector.create_search_generator(collection_name=collection_name,
                                                                        date_from=last_fetch,
                                                                        date_to=date_end)
        else:
            generator = self._gib_tia_connector.create_update_generator(collection_name=collection_name,
                                                                        sequpdate=last_fetch,
                                                                        date_from=date_start,
                                                                        date_to=date_end)
        return generator, collection_info

    def _transform_severity(self, feed):
        severity = None
        if feed["severity"] == "green":
            severity = "low"
        elif feed["severity"] == "orange":
            severity = "medium"
        elif feed["severity"] == "red":
            severity = "high"
        return severity

    def _parse_artifacts(self, chunk, collection_info, collection_name):
        artifact_keys_list = collection_info.get("artifacts", [])
        artifacts_list = chunk.bulk_parse_portion([{**BASE_MAPPING_ARTIFACT, **a} for a in artifact_keys_list])

        if collection_name == "osi/public_leak":
            for i, item in enumerate(chunk.raw_dict.get("items")):
                additional_artifacts = []
                for link in item.get("linkList", []):
                    cef = {
                        "deviceCustomString1": link.get("author"),
                        "deviceCustomString1label": "author",
                        "deviceCustomString2": link.get("source"),
                        "deviceCustomString2label": "source",
                        "deviceCustomDate1": link.get("dateDetected"),
                        "deviceCustomDate1label": "dateDetected",
                        "deviceCustomDate2": link.get("datePublished"),
                        "deviceCustomDate2label": "datePublished",
                        "fileHash": link.get("hash"),
                        "requestUrl": link.get("link"),
                    }
                    artifact = {
                        "name": "Link list",
                        "type": "other",
                        "cef": cef
                    }
                    additional_artifacts.append(artifact)

                artifacts_list[i].extend(additional_artifacts)

        elif collection_name == "osi/git_leak":
            for i, item in enumerate(chunk.raw_dict.get("items")):
                additional_artifacts = []
                for revision in item.get("revisions", []):
                    info = revision.get("info")
                    cef = {
                        "deviceCustomString1": info.get("authorEmail"),
                        "deviceCustomString1label": "authorEmail",
                        "deviceCustomString2": info.get("authorName"),
                        "deviceCustomString2label": "authorName",
                        "deviceCustomDate1": info.get("dateCreated"),
                        "deviceCustomDate1label": "dateCreated",
                        "requestUrl": revision.get("fileDiff")
                    }
                    artifact = {
                        "name": "Revisions",
                        "type": "other",
                        "cef": cef
                    }
                    additional_artifacts.append(artifact)

                artifacts_list[i].extend(additional_artifacts)

        return artifacts_list

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        action_result.set_status(phantom.APP_SUCCESS)

        self.save_progress("Connecting to endpoint")
        # make rest call
        try:
            self._gib_tia_connector.get_seq_update_dict()
        except Exception as e:
            err_msg = self._get_error_message_from_exception(e)
            action_result.set_status(phantom.APP_ERROR, "{0}".format(err_msg))

        if phantom.is_fail(action_result.get_status()):
            self.save_progress("Test Connectivity Failed")
            self.debug_print("Test Connectivity Failed: ", action_result.get_status())
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):
        is_manual_poll = self.is_poll_now()
        action_result = self.add_action_result(ActionResult(dict(param)))
        action_result.set_status(phantom.APP_SUCCESS)
        container_count = 0
        artifacts_count = 0
        flag = 0

        for collection_name, date_start in self._collections.items():
            self.debug_print('Starting polling process for {0} collection'.format(collection_name))
            self.save_progress('Starting polling process for {0} collection'.format(collection_name))

            last_fetch = self._state.get(collection_name)
            try:
                if is_manual_poll:
                    start_time = parse(
                        str(param.get('start_time'))).strftime(GIB_DATE_FORMAT) if param.get('start_time') else None
                    end_time = parse(
                        str(param.get('end_time'))).strftime(GIB_DATE_FORMAT) if param.get('end_time') else None
                    generator, collection_info = self._setup_generator(collection_name, start_time, end_time)
                else:
                    generator, collection_info = self._setup_generator(collection_name, date_start,
                                                                       last_fetch=last_fetch)

                for chunk in generator:
                    portion = chunk.parse_portion()
                    artifacts_list = self._parse_artifacts(chunk, collection_info, collection_name)

                    for i, feed in enumerate(portion):
                        feed["name"] = "{0}: {1}".format(collection_info.get("prefix", ''), feed.get("name"))

                        severity = self._transform_severity(feed)
                        feed["severity"] = severity

                        last_fetch = feed.pop("last_fetch")
                        if feed.get('start_time'):
                            feed['start_time'] = parse(feed.get('start_time')).strftime(SPLUNK_DATE_FORMAT)
                        if feed.get('end_time'):
                            feed['end_time'] = parse(feed.get('end_time')).strftime(SPLUNK_DATE_FORMAT)

                        container = {**feed, **BASE_CONTAINER}
                        ret_val, message, container_id = self.save_container(container)
                        base_artifact = BASE_ARTIFACT
                        if message == 'Duplicate container found':
                            duplication_container_info = self.get_container_info(container_id)
                            status = duplication_container_info[1].get('status')
                            if status in ["resolved", "closed"]:
                                self.debug_print("Skipping adding artifacts to {0} container".format(status))
                                continue

                            base_artifact['label'] = "gib update indicator"
                            message = """
                            Container for feed with id: {0} already exists, updating data.
                            ret_val: {1}, message: {2}, container_id: {3}
                            """.format(container.get("source_data_identifier"), ret_val, message, container_id)
                        elif phantom.is_fail(ret_val):
                            message = """
                            Error occurred while ingesting feed with id: {0} for {1} collection.
                            Error: {2}. Aborting the polling process
                            """.format(container.get("source_data_identifier"), collection_name, message)
                            action_result.set_status(phantom.APP_ERROR, message)
                        else:
                            message = """
                            Container for feed with id: {0} saved. ret_val: {1}, message: {2}, container_id: {3}.
                            """.format(container.get("source_data_identifier"), ret_val, message, container_id)
                            if is_manual_poll:
                                container_count += 1
                                if container_count >= param.get('container_count', BASE_MAX_CONTAINERS_COUNT):
                                    flag = 1

                        self.debug_print(message)
                        self.save_progress(message)
                        if phantom.is_fail(action_result.get_status()):
                            return action_result.get_status()

                        if not is_manual_poll:
                            self._state[collection_name] = last_fetch

                        artifacts = []
                        for artifact in artifacts_list[i]:
                            if artifact.get('start_time'):
                                artifact['start_time'] = parse(artifact.get('start_time')).strftime(SPLUNK_DATE_FORMAT)
                            if artifact.get('end_time'):
                                artifact['end_time'] = parse(artifact.get('end_time')).strftime(SPLUNK_DATE_FORMAT)
                            artifacts.append({**artifact, **base_artifact,
                                              "container_id": container_id, "severity": severity})

                            if is_manual_poll:
                                artifacts_count += 1
                                if artifacts_count >= param.get('artifact_count', BASE_MAX_ARTIFACTS_COUNT):
                                    flag = 1
                                    break

                        if artifacts:
                            ret_val, message, _ = self.save_artifacts(artifacts)
                            message = """
                            Status {0} for ingesting artifacts for container with id: {1} for {2} collection.
                            Message: {3}""".format(ret_val, container_id, collection_name, message)
                            self.debug_print(message)
                            self.save_progress(message)

                        if flag:
                            break

                    if flag:
                        break

                self.debug_print('Polling process for {0} collection has finished'.format(collection_name))
                self.save_progress('Polling process for {0} collection has finished'.format(collection_name))
                if flag:
                    break
            except Exception as e:
                err_msg = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, err_msg)
        else:
            self.debug_print('No collections have been configured for on_poll action.'
                             'Please set up the proper configuration parameters')
            self.save_progress('No collections have been configured for on_poll action.'
                               'Please set up the proper configuration parameters')
            return action_result.set_status(phantom.APP_SUCCESS)

        self.debug_print('Polling process for all collections has finished')
        self.save_progress('Polling process for all collections has finished')
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == "on_poll":
            ret_val = self._on_poll(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Reseting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            return self.set_status(phantom.APP_ERROR, GIB_STATE_FILE_CORRUPT_ERR)

        # get the asset config
        config = self.get_config()

        self._gib_tia_connector = TIAPoller(username=config.get('username'),
                                            api_key=config.get('api_key'),
                                            api_url=config.get('base_url'))
        self._gib_tia_connector.set_verify(verify=not config.get('insecure', False))
        for collection in INCIDENT_COLLECTIONS_INFO.keys():
            modified_collection = collection.replace('/', '_')
            if config.get(modified_collection):
                try:
                    parsed_date = parse(config.get(modified_collection + "_start")).strftime(GIB_DATE_FORMAT)
                except Exception as e:
                    message = 'Inappropriate first_fetch format, ' \
                              'please use something like this: 2020-01-01 or January 1 2020 or 3 days'
                    err_msg = self._get_error_message_from_exception(e)
                    self.set_status(phantom.APP_ERROR, "{0}. Error message: {1}".format(message, err_msg))
                    return phantom.APP_ERROR
                self._collections.update({collection: parsed_date})

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self._gib_tia_connector.close_session()
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def handle_exception(self, e):
        self._gib_tia_connector.close_session()
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
            login_url = GroupIbThreatIntelligenceAndAttributionConnector._get_phantom_base_url(
            ) + '/login'

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

        connector = GroupIbThreatIntelligenceAndAttributionConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
