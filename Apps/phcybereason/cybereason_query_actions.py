# File: cybereason_query_actions.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


import traceback

# Phantom App imports
import phantom.app as phantom
from phantom.action_result import ActionResult
from cybereason_session import CybereasonSession


class CybereasonQueryActions:
    def __init__(self):
        return None

    def _handle_query_processes(self, connector, param):
        connector.save_progress("In action handler for: {0}".format(connector.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = connector.add_action_result(ActionResult(dict(param)))

        malop_id = connector._get_string_param(param.get('malop_id'))
        try:
            cr_session = CybereasonSession(connector).get_session()
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
                "perGroupLimit": 100,
                "perFeatureLimit": 100,
                "templateContext": "SPECIFIC",
                "queryTimeout": 120000,
                "customFields": [
                    "ownerMachine",
                    "elementDisplayName"
                ]
            }
            url = "{0}/rest/visualsearch/query/simple".format(connector._base_url)

            res = cr_session.post(url, json=query, headers=connector._headers)

            if res.status_code < 200 or res.status_code >= 399:
                connector._process_response(res, action_result)
                return action_result.get_status()

            processes_dict = res.json()["data"]["resultIdToElementDataMap"]
            for process_id, process_data in processes_dict.items():
                data = {
                    "process_id": process_id,
                    "process_name": process_data["simpleValues"]["elementDisplayName"]["values"][0]
                }
                self._add_element_value_if_exists(data, "owner_machine_id", process_data, "ownerMachine", "guid")
                self._add_element_value_if_exists(data, "owner_machine_name", process_data, "ownerMachine", "name")
                action_result.add_data(data)

            summary = action_result.update_summary({})
            summary['total_processes'] = len(processes_dict)

        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print(err)
            connector.debug_print(traceback.format_exc())
            return action_result.set_status(phantom.APP_ERROR, "Error occurred. {}".format(err))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_query_machine(self, connector, param):
        connector.save_progress("In action handler for: {0}".format(connector.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = connector.add_action_result(ActionResult(dict(param)))

        name = connector._get_string_param(param.get('name'))
        try:
            self._query_machine_details(connector, action_result, name)

        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print(err)
            connector.debug_print(traceback.format_exc())
            return action_result.set_status(phantom.APP_ERROR, "Error occurred. {}".format(err))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_query_machine_ip(self, connector, param):
        connector.save_progress("In action handler for: {0}".format(connector.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = connector.add_action_result(ActionResult(dict(param)))

        machine_ip = connector._get_string_param(param.get('machine_ip'))

        ret_val, machine_names = connector._get_machine_name_by_machine_ip(machine_ip, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            self._query_machine_details(connector, action_result, machine_names[0])

        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print(err)
            connector.debug_print(traceback.format_exc())
            return action_result.set_status(phantom.APP_ERROR, "Error occurred. {}".format(err))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_query_users(self, connector, param):
        connector.save_progress("In action handler for: {0}".format(connector.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = connector.add_action_result(ActionResult(dict(param)))

        user = connector._get_string_param(param.get('user'))
        malops_dict = {}
        try:
            cr_session = CybereasonSession(connector).get_session()

            query = {
                "queryPath": [
                    {
                        "requestedType": "User",
                        "filters": [
                            {
                                "facetName": "elementDisplayName",
                                "values": [user],
                                "filterType": "MatchesWildcard"
                            }
                        ],
                        "isResult": True
                    }
                ],
                "totalResultLimit": 1000,
                "perGroupLimit": 100,
                "perFeatureLimit": 100,
                "templateContext": "SPECIFIC",
                "queryTimeout": 120000,
                "customFields": [
                    "domain",
                    "ownerMachine",
                    "ownerOrganization.name",
                    "isLocalSystem",
                    "emailAddress",
                    "elementDisplayName"
                ]
            }
            url = "{0}/rest/visualsearch/query/simple".format(connector._base_url)

            res = cr_session.post(url, json=query, headers=connector._headers)

            if res.status_code < 200 or res.status_code >= 399:
                connector._process_response(res, action_result)
                return action_result.get_status()

            malops_dict = res.json()["data"]["resultIdToElementDataMap"]

            for _, user_data in malops_dict.items():
                data = {
                    "element_name": user_data["simpleValues"]["elementDisplayName"]["values"][0]
                }
                self._add_simple_value_if_exists(data, "domain", user_data, "domain")
                self._add_simple_value_if_exists(data, "organization", user_data, "ownerOrganization.name")
                self._add_simple_value_if_exists(data, "local_system", user_data, "isLocalSystem")
                self._add_element_value_if_exists(data, "last_machine_logged_into", user_data, "ownerMachine", "name")
                action_result.add_data(data)

            summary = action_result.update_summary({})
            summary['total_results'] = len(malops_dict)
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print(err)
            connector.debug_print(traceback.format_exc())
            return action_result.set_status(phantom.APP_ERROR, "Error occurred. {}".format(err))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_query_files(self, connector, param):
        connector.save_progress("In action handler for: {0}".format(connector.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = connector.add_action_result(ActionResult(dict(param)))

        file_name = connector._get_string_param(param.get('file_name'))
        malops_dict = {}
        try:
            cr_session = CybereasonSession(connector).get_session()

            query = {
                "queryPath": [
                    {
                        "requestedType": "File",
                        "filters": [
                            {
                                "facetName": "elementDisplayName",
                                "values": [file_name],
                                "filterType": "ContainsIgnoreCase"
                            }
                        ],
                        "isResult": True
                    }
                ],
                "totalResultLimit": 1000,
                "perGroupLimit": 100,
                "perFeatureLimit": 100,
                "templateContext": "SPECIFIC",
                "queryTimeout": 120000,
                "customFields": [
                    "ownerMachine",
                    "avRemediationStatus",
                    "isSigned",
                    "signatureVerified",
                    "sha1String",
                    "maliciousClassificationType",
                    "createdTime",
                    "modifiedTime",
                    "size",
                    "correctedPath",
                    "productName",
                    "productVersion",
                    "companyName",
                    "internalName",
                    "elementDisplayName"
                ]
            }
            url = "{0}/rest/visualsearch/query/simple".format(connector._base_url)

            res = cr_session.post(url, json=query, headers=connector._headers)

            if res.status_code < 200 or res.status_code >= 399:
                connector._process_response(res, action_result)
                return action_result.get_status()

            malops_dict = res.json()["data"]["resultIdToElementDataMap"]

            for file_id, file_data in malops_dict.items():
                connector.save_progress(str(file_id))
                data = {
                    "element_name": file_data["simpleValues"]["elementDisplayName"]["values"][0],
                    "suspicion_count": file_data.get("suspicionCount")
                }
                self._add_simple_value_if_exists(data, "signed", file_data, "isSigned")
                self._add_simple_value_if_exists(data, "SHA1_signature", file_data, "sha1String")
                self._add_simple_value_if_exists(data, "size", file_data, "size")
                self._add_simple_value_if_exists(data, "path", file_data, "correctedPath")
                self._add_simple_value_if_exists(data, "product_name", file_data, "productName")
                self._add_simple_value_if_exists(data, "company_name", file_data, "companyName")
                action_result.add_data(data)

            summary = action_result.update_summary({})
            summary['total_results'] = len(malops_dict)
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print(err)
            connector.debug_print(traceback.format_exc())
            return action_result.set_status(phantom.APP_ERROR, "Error occurred. {}".format(err))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_query_domain(self, connector, param):
        connector.save_progress("In action handler for: {0}".format(connector.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = connector.add_action_result(ActionResult(dict(param)))

        domain_name = connector._get_string_param(param.get('domain_name'))
        malops_dict = {}
        try:
            cr_session = CybereasonSession(connector).get_session()

            query = {
                "queryPath": [
                    {
                        "requestedType": "DomainName",
                        "filters": [
                            {
                                "facetName": "elementDisplayName",
                                "values": [domain_name],
                                "filterType": "MatchesWildcard"
                            }
                        ],
                        "isResult": True
                    }
                ],
                "totalResultLimit": 1000,
                "perGroupLimit": 100,
                "perFeatureLimit": 100,
                "templateContext": "SPECIFIC",
                "queryTimeout": 120000,
                "customFields": [
                    "maliciousClassificationType",
                    "isInternalDomain",
                    "everResolvedDomain",
                    "everResolvedSecondLevelDomain",
                    "elementDisplayName"
                ]
            }
            url = "{0}/rest/visualsearch/query/simple".format(connector._base_url)

            res = cr_session.post(url, json=query, headers=connector._headers)

            if res.status_code < 200 or res.status_code >= 399:
                connector._process_response(res, action_result)
                return action_result.get_status()

            malops_dict = res.json()["data"]["resultIdToElementDataMap"]

            for _, domain_data in malops_dict.items():
                data = {
                    "element_name": domain_data["simpleValues"]["elementDisplayName"]["values"][0]
                }
                self._add_simple_value_if_exists(data, "malicious_classification_type", domain_data, "maliciousClassificationType")
                self._add_simple_value_if_exists(data, "is_internal_domain", domain_data, "isInternalDomain")
                self._add_simple_value_if_exists(data, "was_ever_resolved", domain_data, "everResolvedDomain")
                self._add_simple_value_if_exists(data, "was_ever_resolved_as_second_level_domain", domain_data, "everResolvedSecondLevelDomain")
                action_result.add_data(data)

            summary = action_result.update_summary({})
            summary['total_results'] = len(malops_dict)
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print(err)
            connector.debug_print(traceback.format_exc())
            return action_result.set_status(phantom.APP_ERROR, "Error occurred. {}".format(err))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_query_connections(self, connector, param):
        connector.save_progress("In action handler for: {0}".format(connector.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = connector.add_action_result(ActionResult(dict(param)))

        connection_name = connector._get_string_param(param.get('connection_name'))
        malops_dict = {}
        try:
            cr_session = CybereasonSession(connector).get_session()

            query = {
                "queryPath": [
                    {
                        "requestedType": "Connection",
                        "filters": [
                            {
                                "facetName": "elementDisplayName",
                                "values": [connection_name],
                                "filterType": "MatchesWildcard"
                            }
                        ],
                        "isResult": True
                    }
                ],
                "totalResultLimit": 1000,
                "perGroupLimit": 100,
                "perFeatureLimit": 100,
                "templateContext": "SPECIFIC",
                "queryTimeout": 120000,
                "customFields": [
                    "direction",
                    "serverAddress",
                    "serverPort",
                    "portType",
                    "aggregatedReceivedBytesCount",
                    "aggregatedTransmittedBytesCount",
                    "remoteAddressCountryName",
                    "accessedByMalwareEvidence",
                    "ownerMachine",
                    "ownerProcess",
                    "dnsQuery",
                    "calculatedCreationTime",
                    "endTime",
                    "elementDisplayName"
                ]
            }
            url = "{0}/rest/visualsearch/query/simple".format(connector._base_url)

            res = cr_session.post(url, json=query, headers=connector._headers)

            if res.status_code < 200 or res.status_code >= 399:
                connector._process_response(res, action_result)
                return action_result.get_status()

            malops_dict = res.json()["data"]["resultIdToElementDataMap"]
            for _, connection_data in malops_dict.items():
                # Name contains characters like ">" which will be escaped to "&gt;" when showing in the output table
                name = connection_data["simpleValues"]["elementDisplayName"]["values"][0]
                name = name.replace('>', ' [to] ')
                name = name.replace('<', ' [from] ')
                data = {
                    "element_name": name
                }
                self._add_simple_value_if_exists(data, "direction", connection_data, "direction")
                self._add_simple_value_if_exists(data, "server_address", connection_data, "serverAddress")
                self._add_simple_value_if_exists(data, "server_port", connection_data, "serverPort")
                self._add_simple_value_if_exists(data, "port_type", connection_data, "portType")
                self._add_simple_value_if_exists(data, "received_bytes", connection_data, "aggregatedReceivedBytesCount")
                self._add_simple_value_if_exists(data, "transmitted_bytes", connection_data, "aggregatedTransmittedBytesCount")
                self._add_simple_value_if_exists(data, "remote_address", connection_data, "remoteAddressCountryName")

                self._add_element_value_if_exists(data, "owner_machine", connection_data, "ownerMachine", "name")
                self._add_element_value_if_exists(data, "owner_process", connection_data, "ownerProcess", "name")
                self._add_element_value_if_exists(data, "dns_query", connection_data, "dnsQuery", "name")
                action_result.add_data(data)

            summary = action_result.update_summary({})
            summary['total_results'] = len(malops_dict)
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print(err)
            connector.debug_print(traceback.format_exc())
            return action_result.set_status(phantom.APP_ERROR, "Error occurred. {}".format(err))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_simple_value_if_exists(self, target, target_key, obj, simple_value_key):
        if obj["simpleValues"].get(simple_value_key):
            target[target_key] = obj["simpleValues"][simple_value_key]["values"][0]

    def _add_element_value_if_exists(self, target, target_key, obj, element_value_key1, element_value_key2):
        if obj["elementValues"].get(element_value_key1):
            target[target_key] = obj["elementValues"][element_value_key1]["elementValues"][0][element_value_key2]

    def _query_machine_details(self, connector, action_result, machine_name):
        malops_dict = {}
        try:
            cr_session = CybereasonSession(connector).get_session()

            query = {
                "queryPath": [
                    {
                        "requestedType": "Machine",
                        "filters": [
                            {
                                "facetName": "elementDisplayName",
                                "values": [machine_name],
                                "filterType": "MatchesWildcard"
                            }
                        ],
                        "isResult": True
                    }
                ],
                "totalResultLimit": 1000,
                "perGroupLimit": 100,
                "perFeatureLimit": 100,
                "templateContext": "SPECIFIC",
                "queryTimeout": 120000,
                "customFields": [
                    "osVersionType",
                    "platformArchitecture",
                    "uptime",
                    "isActiveProbeConnected",
                    "lastSeenTimeStamp",
                    "timeStampSinceLastConnectionTime",
                    "activeUsers",
                    "mountPoints",
                    "processes",
                    "services",
                    "elementDisplayName"
                ]
            }
            url = "{0}/rest/visualsearch/query/simple".format(connector._base_url)

            res = cr_session.post(url, json=query, headers=connector._headers)

            if res.status_code < 200 or res.status_code >= 399:
                connector._process_response(res, action_result)
                return action_result.get_status()

            malops_dict = res.json()["data"]["resultIdToElementDataMap"]
            for machine_id, machine_data in malops_dict.items():
                data = {
                    "machine_id": machine_id,
                    "machine_name": machine_data["simpleValues"]["elementDisplayName"]["values"][0]
                }
                self._add_simple_value_if_exists(data, "os_version", machine_data, "osVersionType")
                self._add_simple_value_if_exists(data, "platform_architecture", machine_data, "platformArchitecture")
                self._add_simple_value_if_exists(data, "is_connected_to_cybereason", machine_data, "isActiveProbeConnected")
                action_result.add_data(data)

            summary = action_result.update_summary({})
            summary['total_machines'] = len(malops_dict)

        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.debug_print(err)
            connector.debug_print(traceback.format_exc())
            return action_result.set_status(phantom.APP_ERROR, "Error occurred. {}".format(err))
