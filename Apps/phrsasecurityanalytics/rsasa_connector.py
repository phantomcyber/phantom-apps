# --
# File: rsasa_connector.py
#
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --

# Phantom imports
import phantom.app as phantom

# THIS Connector imports
import rsasa_consts as consts

import re
import time
import json
import hashlib
import requests
import calendar
import parse_incidents as pi

from bs4 import BeautifulSoup
from datetime import datetime
from datetime import timedelta


class RetVal(tuple):
    def __new__(cls, status, data):
        return tuple.__new__(RetVal, (status, data))


class RSASAConnector(phantom.BaseConnector):

    ACTION_ID_TEST_ASSET_CONNECTIVITY = "test_connectivity"
    ACTION_ID_RESTART_SERVICE = "restart_service"
    ACTION_ID_LIST_INCIDENTS = "list_incidents"
    ACTION_ID_LIST_DEVICES = "list_devices"
    ACTION_ID_LIST_ALERTS = "list_alerts"
    ACTION_ID_LIST_EVENTS = "list_events"
    ACTION_ID_ON_POLL = "on_poll"

    def __init__(self):

        # Call the BaseConnectors init first
        super(RSASAConnector, self).__init__()

        self._state = {}
        self._csrf = None
        self._session = None
        self._cookies = None
        self._base_url = None
        self._inc_mgnt_id = None

    def initialize(self):
        '''
        Initializes the authentication tuple that the REST call needs

        :return:
        '''
        config = self.get_config()

        self._base_url = config[consts.RSASA_JSON_URL].strip('/')

        self._session = requests.Session()

        self._state = self.load_state()

        if not self._state:
            return phantom.APP_ERROR

        ret_val = self._login()

        return ret_val

    def _login(self):

        config = self.get_config()

        url = "{0}/j_spring_security_check".format(config[consts.RSASA_JSON_URL])

        data = {'j_username': config[consts.RSASA_JSON_USERNAME], 'j_password': config[consts.RSASA_JSON_PASSWORD]}

        try:
            r = self._session.post(url, data=data, verify=config[consts.RSASA_JSON_VERIFY_SERVER_CERT])
        except Exception as e:
            if self.get_action_identifier() == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
                self.save_progress(consts.RSASA_ERR_TEST_CONNECTIVITY)
            return self.set_status(phantom.APP_ERROR, "Unable to connect to server. Error: {0}".format(str(e)))

        search_token = '"csrf-token" content="'

        if search_token not in r.text:
            if self.get_action_identifier() == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
                self.save_progress(consts.RSASA_ERR_TEST_CONNECTIVITY)
            return self.set_status(phantom.APP_ERROR, "Could not find csrf token in response text.")

        csrf_index = re.search(search_token, r.text).end()

        self._csrf = r.text[csrf_index: csrf_index + 36]

        session_id = self._session.cookies.get('JSESSIONID')

        if session_id is None:
            if self.get_action_identifier() == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
                self.save_progress(consts.RSASA_ERR_TEST_CONNECTIVITY)
            return self.set_status(phantom.APP_ERROR, "Required Cookie value missing in response")

        self._cookies = self._session.cookies

        inc_man_name = config.get(consts.RSASA_JSON_INCIDENT_MANAGER)

        # make the call to get the device manager, to verify the cookie
        query_params = {'page': 1, 'start': 0, 'limit': 100, 'sort': [{"property": "displayType", "direction": "ASC"}]}

        endpoint = '/common/devices/types/INCIDENT_MANAGEMENT'

        ret_val, data = self._make_rest_call(endpoint, self, params=query_params)

        if phantom.is_fail(ret_val):
            if self.get_action_identifier() == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
                self.save_progress(consts.RSASA_ERR_TEST_CONNECTIVITY)
            return self.get_status()

        data = data.get('data')

        if not data:
            if self.get_action_identifier() == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
                self.save_progress(consts.RSASA_ERR_TEST_CONNECTIVITY)
            return self.set_status(phantom.APP_ERROR,
                                   "Could not find INCIDENT_MANAGEMENT type devices configured, can't continue")

        matched_index = None

        names = [x['displayName'] for x in data]

        try:
            matched_index = names.index(inc_man_name)
        except:
            if self.get_action_identifier() == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
                self.save_progress(consts.RSASA_ERR_TEST_CONNECTIVITY)
            return self.set_status(phantom.APP_ERROR,
                                   "Could not find INCIDENT_MANAGEMENT type device named '{0}'. Can't continue".format(
                                       config[consts.RSASA_JSON_INCIDENT_MANAGER]))

        self._inc_mgnt_id = data[matched_index].get('id')

        if self._inc_mgnt_id is None:
            if self.get_action_identifier() == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
                self.save_progress(consts.RSASA_ERR_TEST_CONNECTIVITY)
            return self.set_status(phantom.APP_ERROR,
                                   "Could not get ID of device named '{0}'. Can't continue".format(
                                       config[consts.RSASA_JSON_INCIDENT_MANAGER]))

        return phantom.APP_SUCCESS

    def _logout(self):

        if self._cookies is None:
            return phantom.APP_SUCCESS

        config = self.get_config()

        url = "{0}/j_spring_security_logout".format(config[consts.RSASA_JSON_URL])

        try:
            self._session.get(url, verify=config[consts.RSASA_JSON_VERIFY_SERVER_CERT])
        except Exception as e:
            self.debug_print("Logout failed: {0}".format(str(e)))

        return phantom.APP_SUCCESS

    def finalize(self):

        self._logout()

        self.save_state(self._state)

        return phantom.APP_SUCCESS

    def _get_http_error_details(self, r):

        if 'text/html' in r.headers.get('Content-Type', ''):

            # Try BeautifulSoup
            try:
                soup = BeautifulSoup(r.text, 'html.parser')
                return soup.text
            except:
                pass

        return ""

    def _make_rest_call(self, endpoint, result, params={}, headers={}):
        """ Will query the endpoint, parses the response and returns status and data,
        BEWARE data can be None"""

        # Get the config
        config = self.get_config()

        resp_json = None

        url = "{0}{1}".format(self._base_url, endpoint)
        if params:
            params.update({'_dc': int(time.time()) * 1000})

        # Make the call
        try:
            r = self._session.get(url, params=params, verify=config[consts.RSASA_JSON_VERIFY_SERVER_CERT], headers=headers)
        except Exception as e:
            return RetVal(result.set_status(phantom.APP_ERROR, consts.RSASA_ERR_SERVER_CONNECTION, e), resp_json)

        if hasattr(result, 'add_debug_data'):
            result.add_debug_data({'r_text': r.text if r else 'r is None'})

        if not (200 <= r.status_code <= 399):
            # error
            detail = self._get_http_error_details(r)
            return RetVal(result.set_status(phantom.APP_ERROR,
                                            "Call failed with HTTP Code: {0}. Reason: {1}. Details: {2}".format(r.status_code, r.reason, detail)), None)

        # Try a json load
        try:
            resp_json = r.json()
        except:
            # r.text is guaranteed to be NON None, it will be empty, but not None
            # TODO the error returned is in HTML need to parse it
            return RetVal(result.set_status(phantom.APP_ERROR, "Server returned a response that was not a JSON. Please check your credentials"),
                          resp_json)

        success = resp_json.get('success')

        if success is None:
            return RetVal(result.set_status(phantom.APP_ERROR, "Status info not found in response"), resp_json)

        if success is not True:
            message = resp_json.get('message', "Not specified")
            self.save_progress(message)
            return RetVal(result.set_status(phantom.APP_ERROR, "Call failed, details: {0}".format(message)), resp_json)

        return RetVal(phantom.APP_SUCCESS, resp_json)

    def _test_connectivity(self, param):
        """ Function that handles the test connectivity action, it is much simpler than other action handlers.
        """

        # Login and query for the device happens in the initialize function,
        # which calls self._login(...)
        # If everything went fine, _test_connectivity gets called
        # If something went wrong, initialize(...) will return an error
        # and the BaseConnector will not call any actions, so the fact
        # that _test_connectivity got called means everything is fine.
        #
        self.save_progress("Test Connectivity Successful")
        return self.set_status(phantom.APP_SUCCESS, "Test Connectivity Successful")

    def _restart_service(self, param):

        action_result = self.add_action_result(phantom.ActionResult(param))
        return action_result.set_status(phantom.APP_ERROR, "This action has been deprecated. Please use the NetWitness Logs and Packets 'restart device' action instead.")

    def _list_incidents(self, param):

        self.debug_print(param)
        action_result = self.add_action_result(phantom.ActionResult(param))

        max_incidents = param.get('limit', consts.RSASA_DEFAULT_INCIDENT_LIMIT)
        start_time = param.get('start_time')
        end_time = param.get('end_time')

        epoch = datetime.utcfromtimestamp(0)

        end_epoch = 0
        start_epoch = 0
        if start_time or end_time:

            try:

                if start_time:
                    start_epoch = int((datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S") - epoch).total_seconds() * 1000)
                else:
                    start_epoch = consts.RSASA_DEFAULT_START_TIME

                if end_time:
                    end_epoch = int((datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S") - epoch).total_seconds() * 1000)
                else:
                    end_epoch = int(time.time() * 1000)

            except ValueError as e:
                return action_result.set_status(phantom.APP_ERROR, str(e))

        ret_val, incidents = self._get_incidents(action_result, max_incidents, start_epoch, end_epoch, sort='DESC')

        if not ret_val:
            return ret_val

        action_result.add_data(incidents)
        action_result.set_summary({"num_incidents": len(incidents)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_alerts(self, param):

        self.debug_print(param)
        action_result = self.add_action_result(phantom.ActionResult(param))
        incident_id = param.get('id')
        limit = int(param.get('limit', consts.RSASA_DEFAULT_ALERT_LIMIT))

        ret_val, alerts = self._get_alerts(action_result, incident_id, limit)

        if not ret_val:
            return ret_val

        action_result.add_data(alerts)
        action_result.set_summary({"num_alerts": len(alerts)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_events(self, param):

        self.debug_print(param)
        action_result = self.add_action_result(phantom.ActionResult(param))
        alert_id = param['id']
        limit = int(param.get('limit', consts.RSASA_DEFAULT_EVENT_LIMIT))

        ret_val, events = self._get_events(action_result, alert_id, limit)

        if not ret_val:
            return ret_val

        for event in events:
            if event['data'][0]['filename'] and not event['data'][0]['hash']:
                self._extract_device_and_hash(event)

        action_result.add_data(events)
        action_result.set_summary({"num_events": len(events)})

        for event in events:
            for link in event['related_links']:
                if link['type'] == 'investigate_original_event':
                    event['id'] = link['url'].split('/')[-1]

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_incidents(self, action_result, limit, start_time, end_time, sort='ASC'):
        """get all incidents in a time range"""

        query_params = {'limit': limit, 'start': 0, 'sort': '[{{"property": "created", "direction": "{0}"}}]'.format(sort)}

        if start_time and end_time:
            query_params['filter'] = '[{{"property": "created", "value": [{0}, {1}]}}]'.format(start_time, end_time)

        endpoint = "/ajax/incidents/{0}".format(self._inc_mgnt_id)

        ret_val, data = self._make_rest_call(endpoint, action_result, params=query_params)

        if not ret_val:
            return RetVal(action_result.get_status(), [])

        return RetVal(phantom.APP_SUCCESS, data.get('data'))

    def _get_alerts(self, action_result, incident, limit):
        """get all alerts for an incident"""

        endpoint = "/ajax/alerts/{0}".format(self._inc_mgnt_id)
        query_params = {'start': 0, 'limit': limit if limit is not None else consts.RSASA_DEFAULT_PAGE_SIZE, 'sort': '[{"property": "alert.timestamp", "direction": "DESC"}]'}

        if incident:
            query_params['filter'] = '[{{"property": "incidentId", "value": "{0}"}}]'.format(incident)
        else:
            query_params['filter'] = '[{{"property": "alert.timestamp", "value": [{0}, {1}]}}]'.format(consts.RSASA_DEFAULT_START_TIME, int(time.time()) * 1000)

        alerts = []
        page = 1
        total = 0
        while True:

            query_params['page'] = page

            ret_val, data = self._make_rest_call(endpoint, action_result, params=query_params)

            if not ret_val:
                return RetVal(action_result.get_status(), [])

            if not total:
                total = data['total']

            alerts += data.get('data')

            len_alerts = len(alerts)
            if len_alerts == total or (limit and len_alerts == limit):
                break

            page += 1

        return RetVal(phantom.APP_SUCCESS, alerts)

    def _get_events(self, action_result, alert, limit):
        """get all events for an alert"""

        endpoint = "/ajax/alerts/events/{0}/{1}".format(self._inc_mgnt_id, alert)
        query_params = {'start': 0, 'limit': limit if limit is not None else consts.RSASA_DEFAULT_PAGE_SIZE, 'sort': '[{"property": "timestamp", "direction": "DESC"}]'}

        events = []
        page = 1
        total = 0
        while True:

            query_params['page'] = page

            ret_val, data = self._make_rest_call(endpoint, action_result, params=query_params)

            if not ret_val:
                return RetVal(action_result.get_status(), [])

            if not total:
                total = data['total']

            events += data.get('data')

            len_events = len(events)
            if len(events) == total or (limit and len_events == limit):
                break

            page += 1

        return RetVal(phantom.APP_SUCCESS, events)

    def _extract_device_and_hash(self, event):

        investigate_url = ''
        for link in event['related_links']:
            if link['type'] == 'investigate_original_event':
                investigate_url = '{0}{1}'.format(self._base_url, link['url'])
                event_id = link['url'].split('/')[-1]

        if not investigate_url or not event_id:
            return RetVal(phantom.APP_ERROR, "Could not extract file hash. Could not find investigate URL.")

        try:
            r = self._session.get(investigate_url, verify=self.get_config()[consts.RSASA_JSON_VERIFY_SERVER_CERT])
        except Exception as e:
            return RetVal(phantom.APP_ERROR, "Unable to connect to server. Error: {0}".format(str(e)))

        search_token = "deviceName: '"

        if search_token not in r.text:
            return RetVal(phantom.APP_ERROR, "Could not find device ID in response text.")

        device_name_index = re.search(search_token, r.text).end()
        device_name = r.text[device_name_index:].split("'")[0]
        event['device'] = device_name

        if event['data'][0]['filename'] and not event['data'][0]['hash']:

            search_token = 'deviceId: '

            if search_token not in r.text:
                return RetVal(phantom.APP_ERROR, "Could not find device ID in response text.")

            device_id_index = re.search(search_token, r.text).end()
            device_id = r.text[device_id_index:].split(',')[0]

            url = '{0}/investigation/{1}/reconstruction/{2}/fileview'.format(self._base_url, device_id, event_id)

            try:
                r = self._session.post(url, data={'ctoken': self._csrf}, verify=self.get_config()[consts.RSASA_JSON_VERIFY_SERVER_CERT])
            except Exception as e:
                return RetVal(phantom.APP_ERROR, "Unable to connect to server. Error: {0}".format(str(e)))

            for entry in r.json()['data'].get('fileList')[0]:

                if 'MD5' not in entry:
                    continue

                spl_entry = entry.split(',')
                event['fileHash'] = event['fileHashMd5'] = spl_entry[0].split(':')[1].strip()
                event['fileHashSha1'] = spl_entry[1].split(':')[1].strip()

    def _set_sdi(self, default_id, input_dict):

        if 'source_data_identifier' in input_dict:
            del input_dict['source_data_identifier']

        input_dict['source_data_identifier'] = self._create_dict_hash(input_dict)

        return phantom.APP_SUCCESS

    def _create_dict_hash(self, input_dict):

        input_dict_str = None

        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True)
        except Exception as e:
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str.encode()).hexdigest()

    def _parse_results(self, action_result, param, results):

        container_count = consts.RSASA_DEFAULT_CONTAINER_COUNT

        if param:
            container_count = param.get(phantom.APP_JSON_CONTAINER_COUNT, consts.RSASA_DEFAULT_CONTAINER_COUNT)

        results = results[:container_count]

        for i, result in enumerate(results):

            container = result.get('container')

            if not container:
                continue

            self.send_progress("Saving Container # {0}".format(i + 1))

            try:
                (ret_val, message, container_id) = self.save_container(container)
            except Exception as e:
                self.debug_print("Handled Exception while saving container", e)
                continue

            self.debug_print("save_container returns, value: {0}, reason: {1}, id: {2}".format(ret_val, message, container_id))

            if phantom.is_fail(ret_val):
                self.save_progress(message)
                message = "Failed to add Container for id: {0}, error msg: {1}".format(container.get('source_data_identifier', 'N/A'), message)
                self.debug_print(message)
                continue

            if not container_id:
                message = "save_container did not return a container_id"
                self.debug_print(message)
                continue

            artifacts = result.get('artifacts')
            if not artifacts:
                continue

            len_artifacts = len(artifacts)

            for j, artifact in enumerate(artifacts):

                if not artifact:
                    continue

                # add the container id to the artifact
                artifact['container_id'] = container_id
                self._set_sdi(j, artifact)

                # if it is the last artifact of the last container
                if (j + 1) == len_artifacts:
                    # mark it such that active playbooks get executed
                    artifact['run_automation'] = True

                ret_val, status_string, artifact_id = self.save_artifact(artifact)
                self.debug_print("save_artifact returns, value: {0}, reason: {1}, id: {2}".format(ret_val, status_string, artifact_id))

        return phantom.APP_SUCCESS

    def _get_time_range(self):

        # function to separate on poll and poll now
        config = self.get_config()
        last_time = self._state.get(consts.RSASA_JSON_LAST_DATE_TIME)
        utc_now = datetime.utcnow()
        end_time = calendar.timegm(utc_now.timetuple()) * 1000

        if self.is_poll_now():
            dt_diff = utc_now - timedelta(days=int(config[consts.RSASA_JSON_POLL_NOW_DAYS]))
            start_time = calendar.timegm(dt_diff.timetuple())
            return (start_time * 1000, end_time)
        elif self._state.get('first_run', True):
            self._state['first_run'] = False
            dt_diff = utc_now - timedelta(days=int(config[consts.RSASA_JSON_SCHEDULED_POLL_DAYS]))
            start_time = calendar.timegm(dt_diff.timetuple())
            return (start_time * 1000, end_time)
        elif last_time:
            start_time = last_time
            return (start_time, end_time)

        # treat it as the same days past as first run
        dt_diff = utc_now - timedelta(days=int(config[consts.RSASA_JSON_SCHEDULED_POLL_DAYS]))
        start_time = calendar.timegm(dt_diff.timetuple())
        return (start_time * 1000, end_time)

    def _on_poll(self, param):

        action_result = self.add_action_result(phantom.ActionResult(param))

        config = self.get_config()

        # Get the maximum number of tickets that we can poll, same as container count
        if self.is_poll_now():
            try:
                max_containers = int(param[phantom.APP_JSON_CONTAINER_COUNT])
            except:
                return action_result.set_status(phantom.APP_ERROR, "Invalid Container count")

        else:
            max_containers = config['max_incidents']

        start_time, end_time = self._get_time_range()

        self.save_progress("Getting incident IDs generated\nFrom: {0}\nTo: {1}".format(
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time / 1000)),
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_time / 1000))))

        # get the incidents
        ret_val, incidents = self._get_incidents(action_result, max_containers, start_time, end_time)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not incidents:
            return action_result.set_status(phantom.APP_SUCCESS, consts.RSASA_NO_INCIDENTS)

        for incident in incidents:

            ret_val, alerts = self._get_alerts(action_result, incident.get('id'), 0)

            incident['alerts'] = alerts

            if phantom.is_fail(ret_val):
                self.debug_print("get alert failed with: {0}".format(action_result.get_message()))

            for alert in alerts:

                ret_val, events = self._get_events(action_result, alert.get('id'), 0)

                alert['events'] = events

                if phantom.is_fail(ret_val):
                    self.debug_print("get event failed with: {0}".format(action_result.get_message()))

                for event in events:

                    self._extract_device_and_hash(event)

        self.save_progress("Got {0} incidents".format(len(incidents)))

        if not self.is_poll_now():
            if len(incidents) == int(max_containers):
                self._state[consts.RSASA_JSON_LAST_DATE_TIME] = incidents[-1]['created'] + 1
            else:
                self._state[consts.RSASA_JSON_LAST_DATE_TIME] = end_time + 1

        results = pi.parse_incidents(incidents, self)

        self._parse_results(action_result, param, results)

        # blank line to update the last status message
        self.send_progress('')

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_devices(self, param):

        self.debug_print(param)
        action_result = self.add_action_result(phantom.ActionResult(param))

        endpoint = '/common/devices'

        query_params = {'page': 1, 'start': 0, 'limit': 0}

        ret_val, data = self._make_rest_call(endpoint, action_result, params=query_params)

        if not ret_val:
            return ret_val

        devices = data.get('data')

        if not data:
            return action_result.set_status(phantom.APP_ERROR, consts.RSASA_ERR_NO_DEVICES)

        action_result.add_data(devices)
        action_result.set_summary({'num_devices': len(devices)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS

        if action == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action == self.ACTION_ID_RESTART_SERVICE:
            ret_val = self._restart_service(param)
        elif action == self.ACTION_ID_LIST_INCIDENTS:
            ret_val = self._list_incidents(param)
        elif action == self.ACTION_ID_LIST_DEVICES:
            ret_val = self._list_devices(param)
        elif action == self.ACTION_ID_LIST_ALERTS:
            ret_val = self._list_alerts(param)
        elif action == self.ACTION_ID_LIST_EVENTS:
            ret_val = self._list_events(param)
        elif action == self.ACTION_ID_ON_POLL:
            ret_val = self._on_poll(param)

        return ret_val


if __name__ == '__main__':
    # Imports
    import sys
    # import pudb

    # Breakpoint at runtime
    # pudb.set_trace()

    # The first param is the input json file
    with open(sys.argv[1]) as f:
        # Load the input json file
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        # Create the connector class object
        connector = RSASAConnector()

        # Se the member vars
        connector.print_progress_message = True

        # Call BaseConnector::_handle_action(...) to kickoff action handling.
        ret_val = connector._handle_action(json.dumps(in_json), None)

        # Dump the return value
        print(ret_val)

    exit(0)
