# File: arcsight_connector.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from arcsight_consts import *

from datetime import datetime
import requests
import re
import socket
import struct
from bs4 import BeautifulSoup
import json


_container_common = {}
_artifact_common = {}


class ArcsightConnector(BaseConnector):

    ACTION_ID_CREATE_TICKET = "create_ticket"
    ACTION_ID_UPDATE_TICKET = "update_ticket"
    ACTION_ID_GET_TICKET = "get_ticket"
    ACTION_ID_RUN_QUERY = "run_query"

    def __init__(self):

        # Call the BaseConnectors init first
        super(ArcsightConnector, self).__init__()

        self._base_url = None
        self._auth_token = None

    def initialize(self):

        # Base URL
        config = self.get_config()

        self._base_url = config[ARCSIGHT_JSON_BASE_URL]

        return phantom.APP_SUCCESS

    def _validate_version(self, action_result):

        # get the version from the device
        ret_val, version = self._get_version(action_result)

        if (phantom.is_fail(ret_val)):
            action_result.append_to_message("Product version validation failed.")
            return action_result.get_status()

        # get the version of the device
        device_version = version.get('cas.getESMVersionResponse', {}).get('cas.return')

        if (not device_version):
            return action_result.set_status(phantom.APP_ERROR, "Unable to get version from the device")

        self.save_progress("Got device version: {0}".format(device_version))

        # get the configured version regex
        version_regex = self.get_product_version_regex()
        if (not version_regex):
            # assume that it matches
            return phantom.APP_SUCCESS

        match = re.match(version_regex, device_version)

        if (not match):
            message = "Version validation failed for App supported version '{0}'".format(version_regex)
            # self.save_progress(message)
            return action_result.set_status(phantom.APP_ERROR, message)

        self.save_progress("Version validation done")

        return phantom.APP_SUCCESS

    def _login(self, action_result):

        if (self._auth_token is not None):
            return phantom.APP_SUCCESS

        config = self.get_config()

        self.save_progress('Logging into device/server')

        request_data = {"log.login": {"log.login": config[ARCSIGHT_JSON_USERNAME], "log.password": config[ARCSIGHT_JSON_PASSWORD]}}

        ret_val, resp = self._make_rest_call(ACRSIGHT_LOGIN_ENDPOINT, action_result, json=request_data, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # parse the response and set the auth key
        try:
            self._auth_token = resp['log.loginResponse']['log.return']
        except Exception as e:
            self.debug_print("Handled exception while parsing auth token", e)
            return action_result.set_status(phantom.APP_ERROR, "Error parsing login response")

        # validate the version
        ret_val = self._validate_version(action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _get_version(self, action_result):

        endpoint = "{0}/getESMVersion".format(ARCSIGHT_CASESERVICE_ENDPOINT)

        params = {'authToken': self._auth_token}

        ret_val, resp = self._make_rest_call(endpoint, action_result, params)

        if (phantom.is_fail(ret_val)):
            return (phantom.APP_ERROR, resp)

        self.debug_print(resp)

        return (phantom.APP_SUCCESS, resp)

    def _parse_error(self, response):

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            pres = soup.findAll('pre')
            error_text = '\r\n'.join([str(x) for x in pres])
        except:
            error_text = "Cannot parse error details"

        # Try to parse some more
        try:
            error_text = str(pres[0]).split('\n')[0].replace('<pre>', '')
        except:
            pass

        message = ARCSIGHT_ERR_FROM_SERVER.format(status=response.status_code, message=error_text)

        return message

    def _make_rest_call(self, endpoint, action_result, params=None, data=None, json=None, headers=None, method="get"):

        config = self.get_config()

        request_func = getattr(requests, method)

        if (not request_func):
            action_result.set_status(phantom.APP_ERROR, ARCSIGHT_ERR_API_UNSUPPORTED_METHOD, method=method)

        # self.save_progress("Connecting to {0}...".format(self._base_url))
        url = self._base_url + endpoint

        self.debug_print("Making REST Call {0} on {1}".format(method.upper(), url))

        _headers = {'Accept': 'application/json'}

        if (headers):
            _headers.update(headers)

        try:
            response = request_func(url, params=params, data=data, json=json, headers=_headers, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            self.debug_print("REST call Failed: ", e)
            return (action_result.set_status(phantom.APP_ERROR, ARCSIGHT_ERR_SERVER_CONNECTION, e), None)

        # self.debug_print('REST url: {0}'.format(response.url))

        if (response.status_code != requests.codes.ok):  # pylint: disable=E1101
            message = self._parse_error(response)
            self.debug_print(message)
            return (action_result.set_status(phantom.APP_ERROR, message), None)

        reply = response.text

        action_result.add_debug_data(reply)

        try:
            response_dict = response.json()
        except Exception as e:
            self.save_progress(ARCSIGHT_ERR_UNABLE_TO_PARSE_REPLY)
            return (action_result.set_status(phantom.APP_ERROR, ARCSIGHT_ERR_UNABLE_TO_PARSE_REPLY, e), None)

        return (phantom.APP_SUCCESS, response_dict)

    def _get_case_events(self, event_ids, action_result):

        if (type(event_ids) is not list):
            event_ids = [event_ids]

        ret_val, events_details = self._get_events_details(event_ids, action_result)

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        if (type(events_details) is not list):
            events_details = [events_details]

        return (phantom.APP_SUCCESS, events_details)

    def _get_events_details(self, event_ids, action_result):

        endpoint = "{0}/getSecurityEvents".format(ARCSIGHT_SECURITYEVENTSERVICE_ENDPOINT)

        # params = {'authToken': self._auth_token, 'ids': event_id, 'startMillis': '-1', 'endMillis': '-1'}
        request_data = {
                "sev.getSecurityEvents": {
                    "sev.authToken": self._auth_token,
                    "sev.ids": event_ids,
                    "sev.startMillis": "-1",
                    "sev.endMillis": "-1"}}

        ret_val, resp = self._make_rest_call(endpoint, action_result, params=None, data=None, json=request_data, headers=None, method="post")

        if (phantom.is_fail(ret_val)):
            return (phantom.APP_ERROR, None)

        # parse the response and get the ids of all the cases
        self.debug_print(resp)

        events_details = resp.get('sev.getSecurityEventsResponse', {}).get('sev.return', {})

        return (phantom.APP_SUCCESS, events_details)

    def _get_case_details(self, case_id, action_result):

        endpoint = "{0}/getResourceById".format(ARCSIGHT_CASESERVICE_ENDPOINT)

        params = {'authToken': self._auth_token, 'resourceId': case_id}

        ret_val, resp = self._make_rest_call(endpoint, action_result, params)

        if (phantom.is_fail(ret_val)):
            return (phantom.APP_ERROR, {})

        # parse the response and get the ids of all the cases
        self.debug_print(resp)
        case_details = resp.get('cas.getResourceByIdResponse', {}).get('cas.return', {})

        return (phantom.APP_SUCCESS, case_details)

    def _get_all_case_ids(self, param, action_result):

        endpoint = "{0}/findAllIds".format(ARCSIGHT_CASESERVICE_ENDPOINT)

        params = {'authToken': self._auth_token}

        ret_val, resp = self._make_rest_call(endpoint, action_result, params)

        if (phantom.is_fail(ret_val)):
            return (phantom.APP_ERROR, [])

        # parse the response and get the ids of all the cases
        self.debug_print(resp)

        case_ids = resp.get('cas.findAllIdsResponse', {}).get('cas.return', [])

        if (type(case_ids) is not list):
            case_ids = [case_ids]

        return (phantom.APP_SUCCESS, case_ids)

    def _get_str_from_epoch(self, epoch_milli):

        if (epoch_milli is None):
            return ''

        if (not str(epoch_milli).strip()):
            return ''

        # 2015-07-21T00:27:59Z
        return datetime.fromtimestamp(long(epoch_milli) / 1000.0).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    def _get_case(self, case_id, action_result):

        ret_val, case_details = self._get_case_details(case_id, action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Ignoring Case ID: {0}, could not get details.".format(case_id))
            return (action_result.get_status(), None, None)

        self.send_progress("Processing Case ID: {0}".format(case_id))

        # create a container
        container = {}
        container['source_data_identifier'] = case_id
        container['name'] = case_details['name']
        container['description'] = case_details.get('description')
        container['data'] = {'case_detail': case_details}
        container['start_time'] = self._get_str_from_epoch(case_details.get('createdTimestamp'))

        event_ids = case_details.get('eventIDs')

        if (not event_ids):
            self.save_progress("Ignoring Case: {0}({1}) since it has no events".format(case_details['name'], case_id))
            return (action_result.get_status(), container, None)

        # now get the events for this container
        ret_val, events = self._get_case_events(case_details['eventIDs'], action_result)

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), container, None)

        artifacts = []

        for i, event in enumerate(events):
            self.send_progress("Processing Event ID: {0}".format(event['eventId']))
            artifact = {}
            artifact['source_data_identifier'] = event['eventId']
            artifact['name'] = event.get('name', 'Artifact # {0}'.format(i))
            artifact['data'] = event
            artifact['start_time'] = self._get_str_from_epoch(event.get('startTime'))
            artifact['end_time'] = self._get_str_from_epoch(event.get('endTime'))

            cef = {}

            # source details
            source = event.get('source')
            if (source):
                cef['sourceUserName'] = source.get('userName')
                cef['sourceAddress'] = self._to_ip(source.get('address'))
                cef['sourceMacAddress'] = self._to_mac(source.get('maxAddress'))
                cef['sourcePort'] = self._to_port(source.get('port'))
                cef['sourceHostName'] = source.get('hostName')

            # destination details
            destination = event.get('destination')
            if (destination):
                cef['destinationUserName'] = destination.get('userName')
                cef['destinationAddress'] = self._to_ip(destination.get('address'))
                cef['destinationMacAddress'] = self._to_mac(destination.get('maxAddress'))
                cef['destinationPort'] = self._to_port(destination.get('port'))
                cef['destinationHostName'] = destination.get('hostName')

            cef = {k: v for k, v in cef.iteritems() if v}

            if (not cef):
                continue

            artifact['cef'] = cef

            artifacts.append(artifact)

        return (phantom.APP_SUCCESS, container, artifacts)

    def _to_port(self, port):

        if (not port):
            return ''

        port = int(port)

        if (port == ARCSIGHT_32VAL_NOT_FILLED):
            return ''

        return port

    def _to_ip(self, input_ip):

        if (not input_ip):
            return ''

        input_ip = long(input_ip)

        if (input_ip == ARCSIGHT_64VAL_NOT_FILLED):
            return ''

        return socket.inet_ntoa(struct.pack('!L', input_ip))

    def _to_mac(self, input_mac):

        if (not input_mac):
            return ''

        input_mac = long(input_mac)

        if (input_mac == ARCSIGHT_64VAL_NOT_FILLED):
            return ''

        hex_str = "%x" % input_mac

        hex_str = hex_str[:12]

        return ':'.join(s.encode('hex') for s in hex_str.decode('hex'))

    def _parse_results(self, results, param):

        container_count = param.get(phantom.APP_JSON_CONTAINER_COUNT, ARCSIGHT_DEFAULT_CONTAINER_COUNT)
        artifact_count = param.get(phantom.APP_JSON_ARTIFACT_COUNT, ARCSIGHT_DEFAULT_ARTIFACT_COUNT)

        results = results[:container_count]

        for i, result in enumerate(results):

            container = result.get('container')

            if (not container):
                continue

            container.update(_container_common)

            (ret_val, message, container_id) = self.save_container(container)
            self.debug_print("save_container returns, value: {0}, reason: {1}, id: {2}".format(ret_val, message, container_id))

            artifacts = result.get('artifacts')
            if (not artifacts):
                continue

            artifacts = artifacts[:artifact_count]

            len_artifacts = len(artifacts)

            for j, artifact in enumerate(artifacts):

                if (not artifact):
                    continue

                # add the container id to the artifact
                artifact['container_id'] = container_id
                artifact.update(_artifact_common)

                # if it is the last artifact of the last container
                if ((j + 1) == len_artifacts):
                    # mark it such that active playbooks get executed
                    artifact['run_automation'] = True

                ret_val, status_string, artifact_id = self.save_artifact(artifact)
                self.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))

        return self.set_status(phantom.APP_SUCCESS)

    def _ingest_cases(self, case_ids, param):

        results = []

        for case_id in case_ids:

            case_act_res = ActionResult()

            ret_val, container, artifacts = self._get_case(case_id, case_act_res)

            if (phantom.is_fail(ret_val)):
                continue

            if (container and artifacts):
                results.append({'container': container, 'artifacts': artifacts})

        self.send_progress("Done Processing Cases and Events")

        self.save_progress("Ingesting results into Containers and Artifacts")

        self._parse_results(results, param)

        return phantom.APP_SUCCESS

    def _poll_now(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._login(action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        container_id = param.get(phantom.APP_JSON_CONTAINER_ID)

        if (container_id):
            case_ids = param[phantom.APP_JSON_CONTAINER_ID]
            case_ids = case_ids.split(',')
        else:
            ret_val, case_ids = self._get_all_case_ids(param, action_result)
            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

        self.debug_print("Case IDS:", case_ids)

        self._ingest_cases(case_ids, param)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._login(action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        return self.set_status(phantom.APP_ERROR)

    def _test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._login(action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_group_details(self, group_uri, action_result):

        endpoint = "{0}/getGroupByURI".format(ARCSIGHT_GROUPSERVICE_ENDPOINT)

        request_data = {
                "gro.getGroupByURI": {
                    "gro.authToken": self._auth_token,
                    "gro.uri": group_uri}}

        ret_val, resp = self._make_rest_call(endpoint, action_result, json=request_data, method="post")

        if (phantom.is_fail(ret_val)):
            return (phantom.APP_ERROR, {})

        group_details = resp.get('gro.getGroupByURIResponse', {}).get('gro.return', {})

        return (phantom.APP_SUCCESS, group_details)

    def _get_child_id_by_name(self, parent_group_id, case_name, action_result):

        # Child not present, let's insert it
        endpoint = "{0}/getChildIDByChildNameOrAlias".format(ARCSIGHT_GROUPSERVICE_ENDPOINT)

        request_data = {
                "gro.getChildIDByChildNameOrAlias": {
                    "gro.authToken": self._auth_token,
                    "gro.groupId": parent_group_id,
                    "gro.name": case_name}}

        ret_val, resp = self._make_rest_call(endpoint, action_result, json=request_data, method="post")

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        try:
            case_id = resp.get('gro.getChildIDByChildNameOrAliasResponse', {}).get('gro.return', {})
        except:
            # If the case is not present, the response ....Response is not a dict
            case_id = None

        return (phantom.APP_SUCCESS, case_id)

    def _create_ticket(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._login(action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Unable to Login")
            return action_result.get_status()

        parent_group = param.get(ARCSIGHT_JSON_PARENT_GROUP, ARCSIGHT_DEFAULT_PARENT_GROUP)

        if (not parent_group.startswith('/')):
            parent_group = '/' + parent_group

        parent_group = parent_group.rstrip('/')

        case_name = param[ARCSIGHT_JSON_CASE_NAME]

        # First get the id of the group
        ret_val, group_details = self._get_group_details(parent_group, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        group_id = group_details.get('resourceid')

        if (not group_id):
            return action_result.set_status(phantom.APP_ERROR, "Unable to get the group id of Group: '{0}'".format(parent_group))

        self.save_progress('Got parent group ID: {0}'.format(group_id))

        # init the summary as if the case was created
        summary = action_result.set_summary({'case_created': True})

        # Try to see if there is already a case with that name

        ret_val, case_id = self._get_child_id_by_name(group_id, case_name, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (case_id):
            # Child is already present
            summary['case_created'] = False
            ret_val, case_details = self._get_case_details(case_id, action_result)
            if (phantom.is_fail(ret_val)):
                action_result.append_to_message("Unable to get case information, cannot continue")
                return action_result.get_status()
            case_id = case_details.get('resourceid')

            if (case_id):
                summary['case_id'] = case_id

            action_result.add_data(case_details)
            return action_result.set_status(phantom.APP_SUCCESS, "Case already existed")

        # Child not present, let's insert it
        endpoint = "{0}/insertResource".format(ARCSIGHT_CASESERVICE_ENDPOINT)

        request_data = {
                "cas.insertResource": {
                    "cas.authToken": self._auth_token,
                    "cas.resource": {'name': case_name},
                    "cas.parentId": group_id}}

        ret_val, resp = self._make_rest_call(endpoint, action_result, json=request_data, method="post")

        if (phantom.is_fail(ret_val)):
            summary['case_created'] = False
            return action_result.get_status()

        summary['case_created'] = True

        case_details = resp.get('cas.insertResourceResponse', {}).get('cas.return', {})

        case_id = case_details.get('resourceid')

        if (case_id):
            summary['case_id'] = case_id

        action_result.add_data(case_details)

        return action_result.set_status(phantom.APP_SUCCESS, "New case created")

    def _update_ticket(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._login(action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Unable to Login")
            return action_result.get_status()

        # Validate the fields param json
        update_fields = param[ARCSIGHT_JSON_UPDATE_FIELDS]

        # try to load it up
        try:
            update_fields = json.loads(update_fields)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                    "Unable to load the input update_fields json. Error: {0}".format(str(e)))

        # Get the case info
        case_id = param[ARCSIGHT_JSON_CASE_ID]
        ret_val, case_details = self._get_case_details(case_id, action_result)

        if (phantom.is_fail(ret_val)):
            action_result.append_to_message("Unable to get case information, cannot continue")
            return action_result.get_status()

        # update the dictionary that we got with the one that was inputted
        case_details.update(update_fields)

        request_data = {
                "cas.update": {
                    "cas.authToken": self._auth_token,
                    "cas.resource": case_details}}

        endpoint = "{0}/update".format(ARCSIGHT_CASESERVICE_ENDPOINT)

        ret_val, resp = self._make_rest_call(endpoint, action_result, json=request_data, method="post")

        if (phantom.is_fail(ret_val)):
            return (phantom.APP_ERROR, {})

        case_details = resp.get('cas.updateResponse', {}).get('cas.return', {})

        action_result.add_data(case_details)

        action_result.update_summary({'case_id': case_details.get('resourceid')})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_ticket(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._login(action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Unable to Login")
            return action_result.get_status()

        # Get the case info
        case_id = param[ARCSIGHT_JSON_CASE_ID]
        ret_val, case_details = self._get_case_details(case_id, action_result)

        if (phantom.is_fail(ret_val)):
            action_result.append_to_message("Unable to get case information, cannot continue")
            return action_result.get_status()

        action_result.add_data(case_details)

        action_result.update_summary({'case_id': case_details.get('resourceid')})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_range(self, input_range, action_result):

        try:
            mini, maxi = (int(x) for x in input_range.split('-'))
        except:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse the range. Please specify the range as min_offset-max_offset")

        if (mini < 0) or (maxi < 0):
            return action_result.set_status(phantom.APP_ERROR, "Invalid min or max offset value specified in range", )

        if (mini > maxi):
            return action_result.set_status(phantom.APP_ERROR, "Invalid range value, min_offset greater than max_offset")

        """
        if (maxi > ARCSIGHT_MAX_END_OFFSET_VAL):
            return action_result.set_status(phantom.APP_ERROR, "Invalid range value. The max_offset value cannot be greater than {0}".format(EWSONPREM_MAX_END_OFFSET_VAL))
        """

        return (phantom.APP_SUCCESS)

    def _run_query(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val = self._login(action_result)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Unable to Login")
            return action_result.get_status()

        query_string = param[ARCSIGHT_JSON_QUERY]

        query_type = param.get(ARCSIGHT_JSON_TYPE, "all").lower()

        if (query_type != 'all'):
            query_string = "type:{0} and {1}".format(query_type, query_string)

        result_range = param.get(ARCSIGHT_JSON_RANGE, "0-10")

        ret_val = self._validate_range(result_range, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Range
        mini, maxi = (int(x) for x in result_range.split('-'))
        request_data = {
                "mss.search": {
                    "mss.authToken": self._auth_token,
                    "mss.queryStr": query_string,
                    "mss.startPosition": mini,
                    "mss.pageSize": (maxi - mini) + 1}}

        endpoint = "{0}/search".format(ARCSIGHT_MANAGERSEARCHSERVICE_ENDPOINT)

        ret_val, resp = self._make_rest_call(endpoint, action_result, json=request_data, method="post")

        if (phantom.is_fail(ret_val)):
            return (phantom.APP_ERROR, {})

        search_result = resp.get('mss.searchResponse', {}).get('mss.return', {})

        search_hits = search_result.get('searchHits', [])

        if (type(search_hits) != list):
            search_result['searchHits'] = [search_hits]
            # this variable is used downstream, so set it up again
            search_hits = search_result.get('searchHits', [])

        action_result.add_data(search_result)

        action_result.update_summary({'total_items': search_result.get('hitCount'), 'total_items_returned': len(search_hits)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()

        if (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            result = self._test_connectivity(param)
        elif (action == self.ACTION_ID_CREATE_TICKET):
            result = self._create_ticket(param)
        elif (action == self.ACTION_ID_UPDATE_TICKET):
            result = self._update_ticket(param)
        elif (action == self.ACTION_ID_GET_TICKET):
            result = self._get_ticket(param)
        elif (action == self.ACTION_ID_RUN_QUERY):
            result = self._run_query(param)

        return result


if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ArcsightConnector()
        connector.print_progress_message = True
        result = connector._handle_action(json.dumps(in_json), None)

        print result

    exit(0)
