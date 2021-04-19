# File: cybereason_poller.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


import datetime
import requests
import hashlib
import traceback
import json

# Phantom App imports
import phantom.app as phantom
from phantom.action_result import ActionResult

from cybereason_session import CybereasonSession
from cybereason_consts import *


class CybereasonPoller:
    def __init__(self):
        return None

    def do_poll(self, connector, param):
        action_result = connector.add_action_result(ActionResult(dict(param)))
        success = True
        try:
            # Declare data that will be lazy-loaded if required
            self.feature_translation = None
            config = connector.get_config()
            state = connector.get_state()
            current_time = datetime.datetime.now()
            is_first_poll = state.get("is_first_poll", True)

            ret_val, malop_historical_days = connector._validate_integer(action_result, config["malop_historical_days"], MALOP_HISTORICAL_DAYS_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            ret_val, malware_historical_days = connector._validate_integer(action_result, config["malware_historical_days"], MALWARE_HISTORICAL_DAYS_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if is_first_poll:
                connector.save_progress("This is a first time poll. We will poll for malops from the last {days} days", days=malop_historical_days)
                malop_start_time = current_time + datetime.timedelta(days=-malop_historical_days)
                connector.save_progress("This is a first time poll. We will poll for malware from the last {days} days", days=malware_historical_days)
                malware_millisec_since_last_poll = malware_historical_days * 60 * 60 * 24 * 1000
                state["is_first_poll"] = False
            else:
                last_poll_timestamp = datetime.datetime.fromtimestamp(state["last_poll_timestamp"])
                malop_start_time = last_poll_timestamp
                malware_millisec_since_last_poll = round((current_time - last_poll_timestamp).total_seconds() * 1000)
            state["last_poll_timestamp"] = current_time.timestamp()
            connector.save_progress("Getting malops between {start_time} and {current_time}", start_time=malop_start_time, current_time=current_time)
            connector.save_progress("Getting malware for the last {msec} milliseconds", msec=malware_millisec_since_last_poll)

            # Initialize the session that will be used throughout the poller
            self.cr_session = CybereasonSession(connector).get_session()
            malop_start_time_microsec_timestamp = round(malop_start_time.timestamp() * 1000)
            # When called as a scheduled poll, max_container count comes as 4294967295 which causes a Cybereason API error.
            container_count = min(int(param.get(phantom.APP_JSON_CONTAINER_COUNT)), 5000)
            success = success & self._fetch_and_ingest_malops(connector, config, malop_start_time_microsec_timestamp, container_count)
            success = success & self._fetch_and_ingest_malwares(connector, config, malware_millisec_since_last_poll, container_count)
        except Exception as e:
            success = False
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Exception when polling")
            connector.debug_print(err)
            connector.debug_print(traceback.format_exc())
        finally:
            connector.save_state(state)

        if success:
            connector.save_progress("Successfully completed polling for Malop and Malware events")
            return action_result.set_status(phantom.APP_SUCCESS, "Malop and Malware ingestion completed successfully")
        else:
            return action_result.set_status(phantom.APP_ERROR, "Error when polling for Malop and Malware. Please refer the logs for more details")

    def _fetch_and_ingest_malops(self, connector, config, start_time_microsec_timestamp, container_count):
        # Fetch Malops
        success = True
        malops_dict = self._get_malops(connector, start_time_microsec_timestamp, container_count)
        malop_ids = list(malops_dict.keys())
        connector.save_progress("Fetched {number_of_malops} malops from Cybereason console", number_of_malops=len(malop_ids))

        # Ingest Malops
        connector.save_progress("Ingesting malops...")
        ingested_count = 0
        percent_complete = 0
        show_progress_after = max(int(len(malop_ids) / 10), 1)
        for malop_id, malop_data in malops_dict.items():
            success = success & self._ingest_malop(connector, config, malop_id, malop_data)
            ingested_count = ingested_count + 1
            if ingested_count % show_progress_after == 0:
                percent_complete = round(float(ingested_count) / len(malop_ids) * 100)
                connector.save_progress("{percent_complete}% complete", percent_complete=percent_complete)
        if percent_complete != 100:
            connector.save_progress("100% complete")
        return success

    def _fetch_and_ingest_malwares(self, connector, config, malware_millisec_since_last_poll, container_count):
        # Fetch Malwares
        success = True
        malwares_array = self._get_malware(connector, malware_millisec_since_last_poll, container_count)
        connector.save_progress("Fetched {number_of_malwares} malwares from Cybereason console", number_of_malwares=len(malwares_array))

        # Ingest malware
        connector.save_progress("Ingesting malware...")
        ingested_count = 0
        percent_complete = 0
        show_progress_after = max(int(len(malwares_array) / 10), 1)
        for malware in malwares_array:
            success = success & self._ingest_malware(connector, config, malware)
            ingested_count = ingested_count + 1
            if ingested_count % show_progress_after == 0:
                percent_complete = round(float(ingested_count) / len(malwares_array) * 100)
                connector.save_progress("{percent_complete}% complete", percent_complete=percent_complete)
        if percent_complete != 100:
            connector.save_progress("100% complete")
        return success

    def _get_decision_feature_translation(self, connector, decision_feature):
        connector.debug_print("Getting decision feature translation table")
        feature_description = decision_feature  # Default to the name of the decision feature
        try:
            if not self.feature_translation:
                url = "{0}/rest/translate/features/all".format(connector._base_url)
                self.feature_translation = self.cr_session.get(url).json()
            # At this point we are guaranteed to have a feature translation
            (decision_feature_type, decision_feature_key) = self._get_decision_feature_details(decision_feature)
            feature_description = self.feature_translation[decision_feature_type][decision_feature_key]["translatedName"]
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Warning: Exception when getting feature translation table. {0}".format(err))

        return feature_description

    def _get_decision_feature_details(self, decision_feature):
        # Sample decision_feature is "Process.lsassMemoryAccessMalop(Malop decision)".
        decision_feature_type = decision_feature.split(".")[0]  # "Process" in our example
        decision_feature_key = decision_feature.split(".")[1].split("(")[0]  # "lsassMemoryAccessMalop" in our example
        return (decision_feature_type, decision_feature_key)

    def _get_sensor_details(self, connector, machine_name):
        url = "{0}/rest/sensors/query".format(connector._base_url)
        query = {
            "filters": [
                {
                    "fieldName": "machineName",
                    "operator": "ContainsIgnoreCase",
                    "values": [machine_name]
                },
                {
                    "fieldName": "status",
                    "operator": "NotEquals",
                    "values": ["Archived"]
                }
            ],
            "sortingFieldName": "machineName",
            "sortDirection": "ASC",
            "limit": 500,
            "offset": 0,
            "batchId": None
        }
        sensors = []
        hasMoreSensors = True
        iterCount = 0
        try:
            while hasMoreSensors and iterCount < 100:
                response = self.cr_session.post(url=url, json=query, headers=connector._headers)
                result = response.json()
                sensors = sensors + result["sensors"]
                hasMoreSensors = result["hasMoreResults"]
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Unable to fetch sensor details: {0}".format(err))

        return sensors

    def _get_process_details(self, connector, malop_id):
        url = "{0}/rest/visualsearch/query/simple".format(connector._base_url)
        query = {
            "queryPath": [
                {
                    "requestedType": "MalopProcess",
                    "filters": [],
                    "guidList": [malop_id],
                    "connectionFeature": {
                        "elementInstanceType": "MalopProcess",
                        "featureName": "suspects"
                    }
                },
                {
                    "requestedType": "Process",
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
                "imageFile.sha1String",
                "imageFile.md5String",
                "imageFile.isSigned",
                "imageFile.productName",
                "calculatedUser",
                "commandLine",
                "ownerMachine",
                "creationTime",
                "elementDisplayName"
            ]
        }
        process_details = {}
        try:
            res = self.cr_session.post(url=url, json=query, headers=connector._headers)
            process_details = res.json()["data"]["resultIdToElementDataMap"]
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Error occurred while fetching process details. {}".format(err))

        return process_details

    def _get_connection_details_for_malop(self, connector, malop_id):
        connector.debug_print("Getting connection details for malop {0}".format(malop_id))
        url = "{0}/rest/visualsearch/query/simple".format(connector._base_url)
        query = {
            "queryPath": [
                {
                    "requestedType": "MalopProcess",
                    "filters": [],
                    "guidList": [malop_id],
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
                        "featureName": "connections"
                    }
                },
                {
                    "requestedType": "Connection",
                    "filters": [],
                    "isResult": True
                }
            ],
            "totalResultLimit": 1000,
            "perGroupLimit": 1200,
            "perFeatureLimit": 1200,
            "templateContext": "MALOP",
            "queryTimeout": None,
            "customFields": [
                "ownerMachine",
                "ownerProcess.user",
                "localPort",
                "remotePort",
                "transportProtocol",
                "state",
                "calculatedCreationTime",
                "endTime",
                "elementDisplayName"
            ]
        }
        connection_details = {}
        try:
            res = self.cr_session.post(url=url, json=query, headers=connector._headers)
            connection_details = res.json()["data"]["resultIdToElementDataMap"]
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Error occurred while fetching connection details. {}".format(err))

        return connection_details

    def _get_user_details_for_malop(self, connector, malop_id):
        connector.debug_print("Getting user details for malop {0}".format(malop_id))
        url = "{0}/rest/visualsearch/query/simple".format(connector._base_url)
        query = {
            "queryPath": [
                {
                    "requestedType": "MalopProcess",
                    "filters": [],
                    "guidList": [malop_id],
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
                        "featureName": "calculatedUser"
                    }
                },
                {
                    "requestedType": "User",
                    "filters": [],
                    "isResult": True
                }
            ],
            "totalResultLimit": 1000,
            "perGroupLimit": 1200,
            "perFeatureLimit": 1200,
            "templateContext": "MALOP",
            "queryTimeout": None,
            "customFields": [
                "isAdmin",
                "passwordAgeDays",
                "elementDisplayName"
            ]
        }
        user_details = {}
        try:
            res = self.cr_session.post(url=url, json=query, headers=connector._headers)
            user_details = res.json()["data"]["resultIdToElementDataMap"]
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Error occurred while fetching user details. {}".format(err))

        return user_details

    def _ingest_malop(self, connector, config, malop_id, malop_data):
        success = phantom.APP_ERROR
        container = self._get_container_dict_for_malop(connector, config, malop_id, malop_data)
        existing_container_id = self._does_container_exist_for_malop_malware(connector, malop_id)
        if not existing_container_id:
            # Container does not exist. Go ahead and save it
            connector.debug_print("Saving container for Malop with id {0}".format(malop_id))
            success = connector.save_container(container)
        else:
            # Container exists, which means this Malop has been ingested before. Update it.
            success = self._update_container_for_malop_malware(connector, config, existing_container_id, container)

        return phantom.APP_SUCCESS if success else phantom.APP_ERROR

    def _does_container_exist_for_malop_malware(self, connector, malop_id):
        url = '{0}rest/container?_filter_source_data_identifier="{1}"&_filter_asset={2}'.format(connector.get_phantom_base_url(), malop_id, connector.get_asset_id())

        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Unable to query Cybereason Malop container: {0}".format(err))
            return False

        if resp_json.get("count", 0) <= 0:
            connector.debug_print("No container matched, creating a new one.")
            return False

        try:
            existing_container_id = resp_json.get('data', [])[0]['id']
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Container results are not proper: {0}".format(err))
            return False

        return existing_container_id

    def _update_container_for_malop_malware(self, connector, config, existing_container_id, container):
        # First, update the container without updating any artifacts
        try:
            connector.debug_print("Updating container for Malop id {0}".format(container["source_data_identifier"]))
            update_json = container.copy()
            del update_json["artifacts"]
            url = '{0}rest/container/{1}'.format(connector.get_phantom_base_url(), existing_container_id)
            r = requests.post(url, json=update_json, verify=False)
            resp_json = r.json()

            for artifact in container["artifacts"]:
                self._save_or_update_artifact(connector, config, existing_container_id, artifact)
            if r.status_code != 200 or resp_json.get('failed'):
                connector.debug_print("Error while updating the container. Error is: ", resp_json.get('failed'))
                return False
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Error occurred while updating the container. {}".format(err))
            return False

        return True

    def _save_or_update_artifact(self, connector, config, container_id, artifact):
        existing_artifact = self._get_artifact(connector, config, artifact["source_data_identifier"], container_id)
        if existing_artifact:
            # We have an existing artifact. Update it.
            artifact["container_id"] = existing_artifact["container"]
            artifact["id"] = existing_artifact["id"]
            connector.debug_print('Updating artifact {0}'.format(artifact["name"]), artifact)
            connector.save_artifacts([artifact])
        else:
            # This is a new artifact. Save it directly.
            connector.debug_print('Saving new artifact {0}'.format(artifact["name"]), artifact)
            artifact["container_id"] = container_id
            connector.save_artifact(artifact)

    def _get_artifact(self, connector, config, source_data_identifier, container_id):
        url = '{0}rest/artifact?_filter_source_data_identifier="{1}"&_filter_container_id={2}&sort=id&order=desc'.format(
                        connector.get_phantom_base_url(), source_data_identifier, container_id)
        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Exception when querying for artifact ID: {0}".format(err))
            return None

        if resp_json.get('count', 0) <= 0:
            connector.debug_print("No artifact matched the source_data_identifier {0} and container id {1}".format(source_data_identifier, container_id))
            return None

        try:
            return resp_json.get('data', [])[0]
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Exception when parsing artifact results: {0}".format(err))
            return None

    def _get_malops(self, connector, malop_timestamp, max_number_malops):
        malops_dict = {}
        url = "{0}/rest/crimes/unified".format(connector._base_url)
        query = {
            "templateContext": "OVERVIEW",
            "queryPath": [
                {
                    "requestedType": "MalopProcess",
                    "guidList": [],
                    "filters": [
                        {
                            "values": [malop_timestamp],
                            "filterType": "GreaterThan",
                            "facetName": "malopLastUpdateTime"
                        }
                    ],
                    "result": True
                }
            ],
            "totalResultLimit": max_number_malops,
            "perGroupLimit": max_number_malops,
            "perFeatureLimit": max_number_malops
        }
        res = self.cr_session.post(url=url, json=query, headers=connector._headers)
        malops_dict = res.json()["data"]["resultIdToElementDataMap"]
        return malops_dict

    def _get_container_dict_for_malop(self, connector, config, malop_id, malop_data):
        connector.debug_print("Building container for malop {0}".format(malop_id))
        # Build the container JSON
        container_json = {}
        container_json["name"] = malop_data["elementValues"]["primaryRootCauseElements"]["elementValues"][0]["name"]
        container_json["data"] = malop_data
        decision_feature = malop_data["simpleValues"]["decisionFeature"]["values"][0]
        container_json["description"] = self._get_decision_feature_translation(connector, decision_feature)
        container_json["source_data_identifier"] = malop_id
        container_json["label"] = config.get("ingest", {}).get("container_label")
        status_map = self._get_status_map_malop()
        container_json["status"] = status_map.get(malop_data["simpleValues"]["managementStatus"]["values"][0], "New")
        severity_map = self._get_severity_map_malop(connector, config)
        (_, decision_feature_key) = self._get_decision_feature_details(decision_feature)
        container_json["start_time"] = self._phtimestamp_from_crtimestamp(malop_data["simpleValues"]["malopStartTime"]["values"][0])
        container_json["severity"] = severity_map.get(decision_feature_key, "High")
        container_json["artifacts"] = self._get_artifacts_for_malop(connector, malop_id, malop_data)

        return container_json

    def _get_artifacts_for_malop(self, connector, malop_id, malop_data):
        connector.debug_print("Building artifacts for malop {0}".format(malop_id))
        artifacts = []
        artifacts = artifacts + self._get_affected_machines_artifacts(connector, malop_data)
        artifacts = artifacts + self._get_affected_users_artifacts(connector, malop_id)
        artifacts = artifacts + self._get_suspicious_processes_artifacts(connector, malop_id, malop_data)
        artifacts = artifacts + self._get_connection_artifacts(connector, malop_id)
        artifacts = artifacts + self._get_comments_artifacts(connector, malop_id)
        artifacts = artifacts + self._get_link_to_cr_artifacts(connector, malop_id)
        artifacts = artifacts + self._get_last_updated_time_artifact(connector, malop_id, malop_data)
        self._add_cef_types_to_artifacts(artifacts)
        return artifacts

    def _get_affected_machines_artifacts(self, connector, malop_data):
        connector.debug_print("Building affected machines artifacts")
        artifacts = []
        for machine in malop_data["elementValues"]["affectedMachines"]["elementValues"]:
            affected_machine_artifact = {
                "source_data_identifier": machine["guid"],
                "name": machine["name"],
                "description": "Details of the machine affected by the Malop",
                "type": "machine",
                "label": "machine",
                "cef": {}
            }
            sensors = self._get_sensor_details(connector, machine["name"])
            matching_sensors = [s for s in sensors if s["guid"] == machine["guid"]]
            if len(matching_sensors) == 1:
                matching_sensor = matching_sensors[0]
                cef = { }
                cef["osVersion"] = matching_sensor["osVersionType"].replace("_", " ")
                cef["isolated"] = "Isolated" if matching_sensor["isolated"] else "Unisolated"
                cef["connectionStatus"] = matching_sensor["status"]
                cef["internalIpAddress"] = matching_sensor["internalIpAddress"]
                affected_machine_artifact["cef"] = cef
            else:
                connector.debug_print("Unable to get sensor details for machine {0}".format(machine["name"]))
            artifacts.append(affected_machine_artifact)
        return artifacts

    def _get_affected_users_artifacts(self, connector, malop_id):
        connector.debug_print("Building affected users artifacts")
        artifacts = []
        all_user_details = self._get_user_details_for_malop(connector, malop_id)
        for _, user_details in all_user_details.items():
            cef = { }
            is_admin_map = {
                "true": "Admin",
                "false": "Non-Admin"
            }
            self._add_simple_value_if_exists(cef, "userType", user_details, "isAdmin", is_admin_map)
            self._add_simple_value_if_exists(cef, "privileges", user_details, "privileges")
            self._add_simple_value_if_exists(cef, "passwordAgeDays", user_details, "passwordAgeDays")

            affected_user_artifact = {
                "source_data_identifier": user_details["guidString"],
                "name": user_details["simpleValues"]["elementDisplayName"]["values"][0],
                "description": "Details of the user affected by the Malop",
                "type": "user",
                "label": "user",
                "cef": cef
            }
            artifacts.append(affected_user_artifact)
        return artifacts

    def _get_suspicious_processes_artifacts(self, connector, malop_id, malop_data):
        connector.debug_print("Building suspicious processes artifacts")
        artifacts = []
        if not malop_data["elementValues"].get("primaryRootCauseElements"):
            return artifacts

        all_process_details = self._get_process_details(connector, malop_id)
        for _, process_details in all_process_details.items():
            cef = { }
            is_signed_map = {
                "true": "Signed",
                "false": "Unsigned"
            }
            self._add_simple_value_if_exists(cef, "fileHashSha1", process_details, "imageFile.sha1String")
            self._add_simple_value_if_exists(cef, "fileHashMD5", process_details, "imageFile.md5String")
            self._add_simple_value_if_exists(cef, "signingStatus", process_details, "imageFile.isSigned", is_signed_map)
            self._add_simple_value_if_exists(cef, "productName", process_details, "imageFile.productName")
            self._add_element_value_if_exists(cef, "ownerMachineName", process_details, "ownerMachine", "name")
            self._add_element_value_if_exists(cef, "ownerMachineGuid", process_details, "ownerMachine", "guid")
            self._add_element_value_if_exists(cef, "calculatedUserName", process_details, "calculatedUser", "name")
            self._add_element_value_if_exists(cef, "calculatedUserGuid", process_details, "calculatedUser", "guid")
            self._add_simple_value_if_exists(cef, "commandLine", process_details, "commandLine")
            self._add_simple_value_if_exists(cef, "creationTime", process_details, "creationTime")

            process_artifact = {
                "source_data_identifier": process_details["guidString"],
                "name": process_details["simpleValues"]["elementDisplayName"]["values"][0],
                "description": "Details of the process",
                "type": "process",
                "label": "process",
                "cef": cef
            }

            artifacts.append(process_artifact)
        return artifacts

    def _get_connection_artifacts(self, connector, malop_id):
        connector.debug_print("Building connection artifacts")
        artifacts = []

        for _, connection_details in self._get_connection_details_for_malop(connector, malop_id).items():
            cef = { }
            connection_type_map = { "true": "External", "false": "Internal" }
            connection_direction_map = { "true": "Incoming", "false": "Outgoing" }
            connection_process_map = { "true": "Live", "false": "Dead" }

            self._add_simple_value_if_exists(cef, "transportProtocol", connection_details, "transportProtocol")
            self._add_simple_value_if_exists(cef, "portType", connection_details, "portType")
            self._add_simple_value_if_exists(cef, "portDescription", connection_details, "portDescription")
            self._add_simple_value_if_exists(cef, "localPort", connection_details, "localPort")
            self._add_simple_value_if_exists(cef, "remotePort", connection_details, "remotePort")
            self._add_simple_value_if_exists(cef, "state", connection_details, "state")
            self._add_simple_value_if_exists(cef, "receivedBytesCount", connection_details, "receivedBytesCount")
            self._add_simple_value_if_exists(cef, "transmittedBytesCount", connection_details, "transmittedBytesCount")
            self._add_simple_value_if_exists(cef, "remoteAddressCountryName", connection_details, "remoteAddressCountryName")
            self._add_simple_value_if_exists(cef, "connectionType", connection_details, "isExternalConnection", connection_type_map)
            self._add_simple_value_if_exists(cef, "direction", connection_details, "isIncoming", connection_direction_map)
            self._add_simple_value_if_exists(cef, "connectionStatus", connection_details, "isLiveProcess", connection_process_map)

            # Add remote connection details
            for remote_connection in connection_details["elementValues"]["remoteAddress"]["elementValues"]:
                if remote_connection["elementType"] == "IpAddress":
                    cef["destinationAddress"] = remote_connection["name"]

            connection_artifact = {
                "source_data_identifier": connection_details["guidString"],
                "name": connection_details["simpleValues"]["elementDisplayName"]["values"][0],
                "description": "Details of the connections",
                "type": "connection",
                "label": "connection",
                "cef": cef
            }

            artifacts.append(connection_artifact)
        return artifacts

    def _add_simple_value_if_exists(self, cef, cef_key, obj, simple_value_key, transform=None):
        if obj["simpleValues"].get(simple_value_key):
            raw_value = obj["simpleValues"][simple_value_key]["values"][0]
            if transform is None:
                cef[cef_key] = raw_value
            else:
                cef[cef_key] = transform.get(raw_value, 'Undefined')

    def _add_element_value_if_exists(self, cef, cef_key, obj, element_value_key1, element_value_key2):
        if obj["elementValues"].get(element_value_key1):
            cef[cef_key] = obj["elementValues"][element_value_key1]["elementValues"][0][element_value_key2]

    def _get_comments_artifacts(self, connector, malop_id):
        connector.debug_print("Building comments artifacts")
        artifacts = []
        url = "{0}/rest/crimes/get-comments".format(connector._base_url)
        query = malop_id
        try:
            res = self.cr_session.post(url=url, data=query, headers=connector._headers)
            comments = res.json()
            for comment in comments:
                cef = {
                    "message": comment["message"],
                    "timestamp": comment["timestamp"]
                }
                comment_artifact = {
                    "source_data_identifier": comment["commentId"],
                    "name": comment["message"],
                    "description": "User comments",
                    "type": "comment",
                    "label": "comment",
                    "cef": cef
                }
                artifacts.append(comment_artifact)
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print("Error occurred while fetching comment details. {}".format(err))

        return artifacts

    def _get_link_to_cr_artifacts(self, connector, malop_id):
        connector.debug_print("Building link-to-Cybereason-console artifacts")
        artifacts = []
        url = "{0}/#/malop/{1}".format(connector._base_url.rstrip("/"), malop_id)
        link_artifact = {
            "source_data_identifier": hashlib.sha1(url.encode()).hexdigest(),  # Just using the URL does not work for some reason
            "name": url,
            "description": "Link to view the Malop in the Cybereason console",
            "type": "malop_link",
            "label": "malop_link",
            "cef": {
                "hyperlink": url
            }
        }
        artifacts.append(link_artifact)
        return artifacts

    def _get_last_updated_time_artifact(self, connector, malop_id, malop_data):
        connector.debug_print("Building last updated time artifacts")
        artifacts = []
        link_artifact = {
            "source_data_identifier": malop_id,
            "name": "Last Updated",
            "description": "The time at which this malop was last updated",
            "type": "timestamp",
            "label": "timestamp",
            "cef": {
                "timestamp": malop_data["simpleValues"]["malopLastUpdateTime"]["values"][0]
            }
        }
        artifacts.append(link_artifact)
        return artifacts

    def _add_cef_types_to_artifacts(self, artifacts):
        cef_type_map = self._get_cef_type_map()
        for artifact in artifacts:
            cef_keys = list(artifact["cef"].keys())
            artifact["cef_types"] = {}
            for cef_key in cef_keys:
                artifact["cef_types"][cef_key] = cef_type_map.get(cef_key, [])

    def _get_malware(self, connector, malware_millisec_since_last_poll, max_number_malware):
        malwares_array = []
        has_more_malware = True
        offset = 0
        max_malwares_in_each_fetch = min(1000, max_number_malware)
        while has_more_malware and len(malwares_array) < max_number_malware:
            res = self._get_malware_with_offset(connector, malware_millisec_since_last_poll, max_malwares_in_each_fetch, offset)
            malware_result = res.json()
            malwares_array = malwares_array + malware_result["data"]["malwares"]
            offset = offset + 1
            has_more_malware = malware_result["data"]["hasMoreResults"]
        return malwares_array

    def _get_malware_with_offset(self, connector, malware_millisec_since_last_poll, max_malwares_in_each_fetch, offset):
        url = "{0}/rest/malware/query".format(connector._base_url)
        query = {
            "filters": [{
                "fieldName": "timestamp",
                "operator": "FromTimeOp",
                "values": [malware_millisec_since_last_poll]
            }],
            "sortingFieldName": "timestamp",
            "sortDirection": "ASC",
            "limit": max_malwares_in_each_fetch,
            "offset": offset
        }
        return self.cr_session.post(url=url, json=query, headers=connector._headers, verify=connector._verify_server_cert)

    def _ingest_malware(self, connector, config, malware):
        success = phantom.APP_ERROR
        container = self._get_container_dict_for_malware(connector, config, malware)
        existing_container_id = self._does_container_exist_for_malop_malware(connector, malware["guid"])
        if not existing_container_id:
            # Container does not exist. Go ahead and save it
            connector.debug_print("Saving container for Malware with id {}".format(malware["guid"]))
            success = connector.save_container(container)
        else:
            # Container exists, which means this Malop has been ingested before. Update it.
            success = self._update_container_for_malop_malware(connector, config, existing_container_id, container)
        return phantom.APP_SUCCESS if success else phantom.APP_ERROR

    def _get_container_dict_for_malware(self, connector, config, malware):
        connector.debug_print("Building container for malware {0}".format(malware["guid"]))

        # Build the container JSON
        container_json = {}
        container_json["name"] = "{0}: {1}".format(self._get_malware_type_map().get(malware["type"], malware["type"]), malware["name"])
        container_json["data"] = malware
        container_json["description"] = malware["name"]
        container_json["source_data_identifier"] = malware["guid"]
        container_json["label"] = config.get("ingest", {}).get("container_label")
        status_map = self._get_status_map_malware()
        container_json["status"] = status_map.get(malware["status"], "New")
        container_json["start_time"] = self._phtimestamp_from_crtimestamp(malware["timestamp"])
        container_json["severity"] = config.get("malware_severity", "High")
        container_json["artifacts"] = [self._get_affected_host_artifact_for_malware(connector, malware)]

        return container_json

    def _get_affected_host_artifact_for_malware(self, connector, malware):
        connector.debug_print("Building affected host artifacts")
        cef = {
            "name": malware["machineName"]
        }
        composite_uid = "{0} {1}".format(malware["guid"], malware["machineName"])
        affected_machine_artifact = {
            "source_data_identifier": hashlib.sha1(composite_uid.encode()).hexdigest(),
            "name": malware["machineName"],
            "description": "Details of the machine affected by the Malop",
            "type": "machine",
            "label": "machine",
            "cef": cef
        }
        return affected_machine_artifact

    def _get_status_map_malop(self):
        return {
            "TODO": "New",
            "UNREAD": "New",
            "OPEN": "Open",
            "CLOSED": "Closed",
            "FP": "Closed",
            "REOPEN": "Closed"
        }

    def _get_status_map_malware(self):
        return {
            "Unremediated": "New",
            "Detected": "New",
            "Remediated": "Closed"
        }

    def _get_malware_type_map(self):
        return {
            "KnownMalware": "Known Malware",
            "UnknownMalware": "Unknown Malware",
            "FilelessMalware": "Fileless Malware",
            "ApplicationControlMalware": "Application Control Malware",
            "RansomwareMalware": "Ransomware Malware"
        }

    def _get_severity_map_malop(self, connector, config):
        severity_map = {
            "ransomwareByHashReputation": "High",
            "maliciousHiddenModule": "High",
            "maliciousWebShellExecution": "High",
            "maliciousByCodeInjection": "High",
            "blackListedFileHash": "High",
            "lsassMemoryAccessMalop": "High",
            "maliciousExecutionOfPowerShell": "High",
            "connectionToBlackListAddressByAddressRootCause": "High",
            "maliciousShadowCopyDeletion": "High",
            "connectionToBlackListDomainByDomainRootCause": "High",
            "filelessMalware": "High",
            "credentialTheftMalop": "High",
            "abusingWindowsAccessibilityFeatures": "High",
            "maliciousUseOfOSProcess": "High",
            "jscriptRATMalop": "High",
            "malwareByHashReputation": "Medium",
            "maliciousByOpeningMaliciousFile": "Medium",
            "connectionToMaliciousDomainByDomainRootCause": "Medium",
            "connectionToMaliciousAddressByAddressRootCause": "Medium",
            "maliciousByMalwareModule": "Medium",
            "maliciousByAccessingAddressUsedByMalwares": "Medium",
            "maliciousByDgaDetection": "Medium",
            "maliciousExecutionOfShellProcess": "Medium",
            "maliciousByDualExtensionByFileRootCause": "Low",
            "unwantedByHashReputation": "Low",
            "maliciousByUnwantedModule": "Low"
        }
        try:
            overriden_severity_map = json.loads(config.get("override_malop_severity_map", "{}"))
            # If any severities have been overriden, merge them into the default and return that map.
            severity_map.update(overriden_severity_map)
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.save_progress("Error when merging updated severity map. Proceeding with default map")
            connector.save_progress(err)

        return severity_map

    def _get_cef_type_map(self):
        return {
            "adDNSHostName": ["hostname", "host name"],
            "hash": ["hash"],
            "calculatedUserName": ["user name"],
            "transportProtocol": ["protocol"],
            "localPort": ["port"],
            "remotePort": ["port"],
            "hyperlink": ["url"],
            "internalIpAddress": ["ip"],
            "fileHashSha1": ["hash"],
            "fileHashMD5": ["hash"]
        }

    # Converts timestamps from Cybereason API (e.g. string "1585270873770") to Phantom/ISO 8601 format (e.g. 2020-03-27T01:01:13.770Z)
    def _phtimestamp_from_crtimestamp(self, cybereason_timestamp):
        timestamp = datetime.datetime.fromtimestamp(int(cybereason_timestamp) / 1000.0)  # Timestamp is in epoch-milliseconds
        return timestamp.isoformat()[:-3] + "Z"  # Remove the microsecond accuracy, add "Z" for UTC timezone
