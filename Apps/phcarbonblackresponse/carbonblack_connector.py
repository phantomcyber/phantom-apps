# File: carbonblack_connector.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# THIS Connector imports
from carbonblack_consts import *

# Other imports used by this connector
import os
import time
import re
import six.moves.urllib.parse
from parse import parse
import json
import zipfile
import uuid
import requests
import shutil
import magic
import socket
import struct
import ctypes
from bs4 import BeautifulSoup
import datetime


class CarbonblackConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_HUNT_FILE = "hunt_file"
    ACTION_ID_CREATE_ALERT = "create_alert"
    ACTION_ID_LIST_ALERTS = "list_alerts"
    ACTION_ID_LIST_ENDPOINTS = "list_endpoints"
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_QUARANTINE_DEVICE = "quarantine_device"
    ACTION_ID_UNQUARANTINE_DEVICE = "unquarantine_device"
    ACTION_ID_SYNC_EVENTS = "sync_events"
    ACTION_ID_GET_SYSTEM_INFO = "get_system_info"
    ACTION_ID_LIST_PROCESSES = "list_processes"
    ACTION_ID_GET_FILE = "get_file"
    ACTION_ID_GET_FILE_INFO = "get_file_info"
    ACTION_ID_BLOCK_HASH = "block_hash"
    ACTION_ID_UNBLOCK_HASH = "unblock_hash"
    ACTION_ID_TERMINATE_PROCESS = "terminate_process"
    ACTION_ID_LIST_CONNECTIONS = "list_connections"
    ACTION_ID_GET_LICENSE = "get_license"
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_PUT_FILE = "put_file"
    ACTION_ID_RUN_COMMAND = "run_command"
    ACTION_ID_EXECUTE_PROGRAM = "execute_program"
    ACTION_ID_RESET_SESSION = "reset_session"
    ACTION_ID_MEMORY_DUMP = "memory_dump"

    MAGIC_FORMATS = [
      (re.compile('^PE.* Windows'), ['pe file'], '.exe'),
      (re.compile('^MS-DOS executable'), ['pe file'], '.exe'),
      (re.compile('^PDF '), ['pdf'], '.pdf'),
      (re.compile('^MDMP crash'), ['process dump'], '.dmp'),
      (re.compile('^Macromedia Flash'), ['flash'], '.flv'),
      (re.compile('^tcpdump capture'), ['pcap'], '.pcap'),
    ]

    def __init__(self):

        # Call the BaseConnectors init first
        super(CarbonblackConnector, self).__init__()

        self._base_url = None
        self._api_token = None
        self._state_file_path = None
        self._state = {}

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def initialize(self):

        self._state = self.load_state()
        config = self.get_config()

        # Base URL
        self._base_url = config[CARBONBLACK_JSON_DEVICE_URL].rstrip('/')
        self._api_token = config[CARBONBLACK_JSON_API_TOKEN]
        self._headers = {'X-Auth-Token': self._api_token, 'Content-Type': 'application/json'}
        self._rest_uri = "{0}/api".format(self._base_url)

        return phantom.APP_SUCCESS

    def _normalize_reply(self, reply):

        try:
            soup = BeautifulSoup(reply, "html.parser")
            return soup.text
        except Exception as e:
            self.debug_print("Handled exception", e)
            return "Unparsable Reply. Please see the log files for the response text."

        return ''

    def _make_rest_call(self, endpoint, action_result, method="get", params={}, headers={}, files=None, data=None, parse_response_json=True, additional_succ_codes={}):
        """ treat_status_code is a way in which the caller tells the function, 'if you get a status code present in this dictionary,
        then treat this as a success and just return be this value'
        This was added to take care os changes Carbon Black made to their code base, with minimal amount of changes to the app _and_ to keep pylint happy.
        """

        url = "{0}{1}".format(self._rest_uri, endpoint)
        self.save_progress(url)
        headers.update(self._headers)

        if files is not None:
            del headers['Content-Type']

        config = self.get_config()

        request_func = getattr(requests, method)

        if (not request_func):
            return (action_result.set_status(phantom.APP_ERROR, "Invalid method call: {0} for requests module".format(method)), None)

        if (data is not None):
            data = json.dumps(data)

        try:
            r = request_func(url, headers=headers, params=params, files=files, data=data, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "REST Api to server failed", e), None)

        # It's ok if r.text is None, dump that
        # action_result.add_debug_data({'r_text': r.text if r else 'r is None'})

        if (r.status_code in additional_succ_codes):
            response = additional_succ_codes[r.status_code]
            return (phantom.APP_SUCCESS, response if response is not None else r.text)

        # Look for errors
        if (r.status_code != requests.codes.ok):  # pylint: disable=E1101
            # return (action_result.set_status(phantom.APP_ERROR, "REST Api Call returned error, status_code: {0}, data: {1}".format(r.status_code,
            #     self._normalize_reply(r.text))), r.text)

            return (action_result.set_status(phantom.APP_ERROR, "REST Api Call returned error, status_code: {0}".format(r.status_code)), None)

        resp_json = None

        if (parse_response_json):

            # Try a json parse
            try:
                resp_json = r.json()
            except:
                return (action_result.set_status(phantom.APP_ERROR, "Unable to parse response as a JSON status_code: {0}, data: {1}".format(r.status_code,
                    self._normalize_reply(r.text))), None)
        else:
            resp_json = r

        return (phantom.APP_SUCCESS, resp_json)

    def _get_system_info_from_cb(self, ip_hostname, action_result, sensor_id=None):

        endpoint = "/v1/sensor"
        query_parameters = None

        if (sensor_id is None):
            # first get the data, use ip if given
            if (phantom.is_ip(ip_hostname)):
                query_parameters = {'ip': ip_hostname}
            else:
                query_parameters = {'hostname': ip_hostname}
        else:
            endpoint += "/{0}".format(sensor_id)

        ret_val, sensors = self._make_rest_call(endpoint, action_result, params=query_parameters, additional_succ_codes={204: []})

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.update_summary({CARBONBLACK_JSON_TOTAL_ENDPOINTS: 0})

        if (not sensors):
            return action_result.set_status(phantom.APP_SUCCESS)

        if (type(sensors) != list):
            sensors = [sensors]

        action_result.update_summary({CARBONBLACK_JSON_TOTAL_ENDPOINTS: len(sensors)})

        for sensor in sensors:
            action_result.add_data(sensor)
            if ('network_adapters' not in sensor):
                continue

            adapters = sensor['network_adapters'].split('|')

            if (not adapters):
                continue

            ips = []
            for adapter in adapters:
                ip = adapter.split(',')[0].strip()
                if (not ip):
                    continue
                ips.append(ip)

            sensor[CARBONBLACK_JSON_IPS] = ','.join(ips)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_connections_for_process(self, params, action_result):
        """ Get a list of all processes matching the search parameters """
        """ This is the same API call that run query uses but it's a bit different
          " The search parameters are URL parameters instead of posted in because of reasons
          " This function will always get the entire list of results, no matter how large,
          "  so be careful.
          "
          " params sent for searching by pid/process_name
          " params = {'cb.q.process_name/pid': process_name/pid,
          "           ['cb.q.hostname': hostname]}
          "
          " params sent for searching by id
          " params = {'cb.q.id': carbonblack_id}
        """

        # get a list of all processes at an endpoint
        # First get a call with 0 results go get the total number of processes
        params['rows'] = 0
        ret_val, json_resp = self._make_rest_call('/v1/process', action_result, params=params)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Error finding processes")

        if (json_resp['total_results'] == 0):
            return action_result.set_status(phantom.APP_ERROR, "No connections found")
        # Make same call to get all of the processes
        params['rows'] = json_resp['total_results']
        ret_val, json_resp = self._make_rest_call('/v1/process', action_result, params=params)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        process_list = json_resp["results"]

        # Now we need to get the connections for each process
        total_processes = 0
        total_processes_to_process = len(process_list)
        printed_message = ""
        for i, process in enumerate(process_list):

            curr_message = CARBONBLACK_FINISHED_PROCESSESING.format(float(i) / float(total_processes_to_process))

            if (curr_message != printed_message):
                self.send_progress(curr_message)
                printed_message = curr_message

            # Process has no connections, don't need to waste time on rest call
            if (process['netconn_count'] == 0):
                continue
            total_processes += 1
            self._get_connections_for_process_event(process.get('id'), process.get('segment_id'),
                                                    action_result)

        action_result.update_summary({"total_processes": total_processes})
        action_result.update_summary({"total_connections": len(action_result.get_data())})
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved connections for process")

    def _get_connections_for_process_event(self, cb_id, segment_id, action_result):

        """ Get a process event and parse netconn """
        # What are the rest? Who knows
        protocol_dict = {"6": "TCP", "17": "UDP"}

        if (cb_id is None or segment_id is None):
            # Something has gone seriously wrong, don't panic
            return

        endpoint = "/v1/process/{}/{}/event".format(cb_id, segment_id)

        ret_val, event_json = self._make_rest_call(endpoint, action_result, params={'cb.legacy_5x_mode': False})
        if (phantom.is_fail(ret_val)):
            return

        if ('process' not in event_json or 'netconn_complete' not in event_json['process']):
            return

        netconns = event_json['process']['netconn_complete']  # noqa
        pid = event_json['process']['process_pid']
        name = event_json['process']['process_name']
        hostname = event_json['process']['hostname']
        connection_dict = {}

        # connection_dict['process_name'] = name
        # connection_dict['pid'] = pid
        # connection_dict['hostname'] = hostname
        # connection_dict['process_id'] = cb_id
        connection_dict['connections'] = []

        connection = {}
        connection['process_name'] = name
        connection['pid'] = pid
        connection['hostname'] = hostname
        connection['carbonblack_process_id'] = cb_id

        for netconn in netconns:
            fields = netconn.split('|')
            connection['event_time'] = fields[0]
            connection['ip_addr'] = self._to_ip(fields[1])
            connection['port'] = fields[2]
            connection['protocol'] = protocol_dict.get(fields[3], fields[3])
            connection['domain'] = fields[4]
            connection['direction'] = "outbound" if fields[5] == "true" else "inbound"
            action_result.add_data(connection.copy())
            # connection_dict['connections'].append(connection)
        # action_result.add_data(connection_dict)
        return

    def _to_ip(self, input_ip):
        """ Convert 32 bit unsigned int to IP """
        if (not input_ip):
            return ""

        # Convert to an unsigned int
        input_ip = long(input_ip)
        input_ip = ctypes.c_uint32(input_ip).value
        # long(input_ip) & 0xffffffff
        # input_ip = long(input_ip)
        return socket.inet_ntoa(struct.pack('!L', input_ip))

    def _get_existing_live_session_id(self, sensor_id, action_result):
        """ Uses "GET /session" to check for existing sessions with the specified sensor_id
          " and a status of "active" or "pending". Returns the first found session or None.
        """
        # get a list of all the sessions
        ret_val, sessions = self._make_rest_call('/v1/cblr/session', action_result)

        if (phantom.is_fail(ret_val)):
            return None

        # get sessions belonging to the sensor we are interested in
        sessions = [x for x in sessions if (x['sensor_id'] == int(sensor_id))]

        if (not sessions):
            return None

        valid_states = ['active', 'pending']

        session_ids = [x['id'] for x in sessions if (x['status'] in valid_states)]

        if (not session_ids):
            return None

        return session_ids[0]

    def _get_live_session_id(self, sensor_id, action_result):

        # Check for existing live sessions with the endpoint
        self.save_progress("Checking for existing live sessions that ca be reused.")
        session_id = self._get_existing_live_session_id(sensor_id, action_result)

        if not session_id:
            self.save_progress("No existing session was found; trying to start a new live session")

            # Make a new live session with the endpoint
            data = {'sensor_id': int(sensor_id)}
            ret_val, resp = self._make_rest_call('/v1/cblr/session', action_result, data=data, method='post')

            if phantom.is_fail(ret_val) or resp is None:
                action_result.append_to_message("Failed to create a new live session.")
                return (action_result.get_status(), None)

            session_id = resp.get('id')

            if not session_id:
                return (action_result.set_status(phantom.APP_ERROR, 'Did not get a session id in the response from a new session creation'), None)

        # Now we either have a newly created session id, an existing pending session id, or an existing active session id
        status = 'unknown'

        tries = 0
        url = '/v1/cblr/session/{0}'.format(session_id)

        while (status != 'active') and (tries <= MAX_POLL_TRIES):

            try:
                self.send_progress("Getting session id for sensor: {0} {1}".format(sensor_id, '.'.join(['' for x in xrange(tries + 1)])))
            except NameError:
                # Python 3, xrange renamed to range
                self.send_progress("Getting session id for sensor: {0} {1}".format(sensor_id, '.'.join(['' for x in range(tries + 1)])))
            time.sleep(CARBONBLACK_SLEEP_SECS)

            # try to get the status of the live session
            ret_val, resp = self._make_rest_call(url, action_result)

            tries += 1

            if (phantom.is_fail(ret_val)):
                if ((resp) and ('Session {} not found'.format(session_id) not in resp)):
                    continue
                else:
                    return (action_result.set_status(phantom.APP_ERROR, "Unable to find session on the server"), None)

            status = resp.get('status')

            if (status == 'active'):
                break

        if (status != 'active'):
            return (action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_POLL_TIMEOUT.format(max_tries=MAX_POLL_TRIES)), None)

        return (phantom.APP_SUCCESS, session_id)

    def _execute_live_session_command(self, session_id, action_result, command, additional_data={}):

        self.save_progress("Executing command {0}".format(command))

        # now execute a command to get the process list
        data = {'session_id': session_id, 'name': command}
        data.update(additional_data)

        url = '/v1/cblr/session/{0}/command'.format(session_id)

        ret_val, resp = self._make_rest_call(url, action_result, data=data, method='post')

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), resp)

        command_id = resp.get('id')

        if (command_id is None):
            return (action_result.set_status(phantom.APP_ERROR, "Did not get the command id from the server"), resp)

        # Now make the rest call to wait for the command to finish
        url = '{0}/{1}'.format(url, command_id)

        self.save_progress("Waiting for command completion")
        ret_val, resp = self._make_rest_call(url, action_result, params={'wait': 'true'})

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), resp)

        result_code = resp.get('result_code')

        if (result_code != 0):
            msg = CARBONBLACK_COMMAND_FAILED.format(command=command,
                code=resp.get('result_code', 'Not Specified'),
                desc=resp.get('result_desc', 'Not Specified'))
            if result_code == 2147942480:
                msg = CARBONBLACK_ERR_FILE_EXISTS + msg
            if result_code == 2147942403:
                msg = "Windows cannot find specified path " + msg
            return (action_result.set_status(phantom.APP_ERROR, msg), resp)

        return (phantom.APP_SUCCESS, resp)

    def _get_process_list(self, sensor_id, action_result):

        if (sensor_id is None):
            return action_result.set_status(phantom.APP_ERROR, "Sensor ID not found")

        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (not session_id):
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress("Got live session ID: {0}".format(session_id))

        data = {'session_id': session_id, 'object': ''}
        ret_val, resp = self._execute_live_session_command(session_id, action_result, 'process list', data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        processes = resp.get('processes')

        if (processes is None):
            return action_result.set_status(phantom.APP_ERROR, "Processes information missing from server response")

        for process in processes:
            try:
                name = process['path'].split('\\')[-1]
            except Exception as e:
                self.debug_print("Handled exceptions:", e)
                name = ''
            process['name'] = name
            action_result.add_data(process)

        action_result.update_summary({'total_processes': len(processes)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _terminate_process_on_endpoint(self, sensor_id, action_result, pid):

        if (sensor_id is None):
            return action_result.set_status(phantom.APP_ERROR, "Sensor ID not found")

        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (not session_id):
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress("Got live session ID: {0}".format(session_id))

        data = {'object': pid}

        ret_val, resp = self._execute_live_session_command(session_id, action_result, 'kill', data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(resp)

        try:
            action_result.update_summary({'status': resp['status']})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS)

    def _terminate_process(self, param):

        ip_hostname = param.get(phantom.APP_JSON_IP_HOSTNAME)
        sensor_id = param.get(CARBONBLACK_JSON_SENSOR_ID)
        pid = param[CARBONBLACK_JSON_PID]

        if ((not ip_hostname) and (sensor_id is None)):
            action_result = self.add_action_result(ActionResult(param))
            return action_result.set_status(phantom.APP_ERROR, "Neither {0} nor {1} specified. Please specify at-least one of them".format(phantom.APP_JSON_IP_HOSTNAME,
                CARBONBLACK_JSON_SENSOR_ID))

        if (sensor_id is not None):

            # set the param to _only_ contain the sensor_id, since that's the only one we are using
            action_result = self.add_action_result(ActionResult({CARBONBLACK_JSON_SENSOR_ID: sensor_id, CARBONBLACK_JSON_PID: pid}))

            if sensor_id and not self._is_valid_integer(sensor_id):
                return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_INTEGER_VALUE)

            self._terminate_process_on_endpoint(sensor_id, action_result, pid)
            return action_result.get_status()

        sys_info_ar = ActionResult(param)

        ret_val = self._get_system_info_from_cb(ip_hostname, sys_info_ar)

        if (phantom.is_fail(ret_val)):
            self.add_action_result(sys_info_ar)
            return sys_info_ar.get_status()

        systems = sys_info_ar.get_data()

        self.save_progress("Got {0} systems".format(len(systems)))

        if (not systems):
            self.add_action_result(sys_info_ar)
            return sys_info_ar.get_status()

        systems = [x for x in systems if x.get('status', 'Offline') == 'Online']

        if (len(systems) > 1):

            self.add_action_result(sys_info_ar)

            systems_error = "<ul>"

            for system in systems:
                systems_error += '<li>{0}</li>'.format(system.get('computer_name'))

            systems_error += "</ul>"
            return sys_info_ar.set_status(phantom.APP_ERROR, CARBONBLACK_MSG_MORE_THAN_ONE.format(systems_error=systems_error))

        system = systems[0]

        action_result = self.add_action_result(ActionResult({phantom.APP_JSON_IP_HOSTNAME: ip_hostname, CARBONBLACK_JSON_PID: pid}))

        self._terminate_process_on_endpoint(system.get('id'), action_result, pid)

        return phantom.APP_SUCCESS

    def _list_processes(self, param):

        ip_hostname = param.get(phantom.APP_JSON_IP_HOSTNAME)
        sensor_id = param.get(CARBONBLACK_JSON_SENSOR_ID)

        if ((not ip_hostname) and (sensor_id is None)):
            action_result = self.add_action_result(ActionResult(param))
            return action_result.set_status(phantom.APP_ERROR, "Neither {0} nor {1} specified. Please specify at-least one of them".format(phantom.APP_JSON_IP_HOSTNAME,
                CARBONBLACK_JSON_SENSOR_ID))

        if (sensor_id is not None):

            # set the param to _only_ contain the sensor_id, since that's the only one we are using
            action_result = self.add_action_result(ActionResult({CARBONBLACK_JSON_SENSOR_ID: sensor_id}))

            if sensor_id and not self._is_valid_integer(sensor_id):
                return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_INTEGER_VALUE)

            self._get_process_list(sensor_id, action_result)
            return action_result.get_status()

        sys_info_ar = ActionResult(param)

        ret_val = self._get_system_info_from_cb(ip_hostname, sys_info_ar)

        if (phantom.is_fail(ret_val)):
            self.add_action_result(sys_info_ar)
            return sys_info_ar.get_status()

        systems = sys_info_ar.get_data()

        self.save_progress("Got {0} systems".format(len(systems)))

        if (not systems):
            self.add_action_result(sys_info_ar)
            return sys_info_ar.get_status()

        for system in systems:
            action_result = self.add_action_result(ActionResult({phantom.APP_JSON_IP_HOSTNAME: system.get('computer_name')}))
            if (system.get('status') != 'Online'):
                action_result.set_status(phantom.APP_ERROR, "Ignoring Offline Endpoint")
                continue
            self._get_process_list(system.get('id'), action_result)

        return phantom.APP_SUCCESS

    def _get_file_summary(self, sample_hash, action_result=ActionResult(), additional_succ_codes={}):

        # get the file summary from the CB server
        url = '/v1/binary/{0}/summary'.format(sample_hash)

        ret_val, response = self._make_rest_call(url, action_result, additional_succ_codes=additional_succ_codes)

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        return (phantom.APP_SUCCESS, response)

    def _download_file_to_vault(self, action_result, file_summary, sample_hash):

        url = '/v1/binary/{0}'.format(sample_hash)

        ret_val, response = self._make_rest_call(url, action_result, parse_response_json=False)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Create a tmp directory on the vault partition
        guid = uuid.uuid4()

        if hasattr(Vault, 'get_vault_tmp_dir'):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = '/vault/tmp'

        local_dir = temp_dir + '/{}'.format(guid)
        self.save_progress("Using {0} directory: {1}".format(temp_dir, guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to create temporary folder {0}.".format(temp_dir), e)

        zip_file_path = "{0}/{1}.zip".format(local_dir, sample_hash)

        # open and download the file
        with open(zip_file_path, 'wb') as f:
            f.write(response.content)

        # Open the zip file
        zf = zipfile.ZipFile(zip_file_path)

        # zipped_file_names = zf.namelist()
        # zipped_file_names = zipped_file_names

        try:
            # extract them
            zf.extractall(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to extract the zip file", e)

        # create the file_path
        file_path = "{0}/filedata".format(local_dir)

        contains = []
        file_ext = ''
        magic_str = magic.from_file(file_path)
        for regex, cur_contains, extension in self.MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)
                if (not file_ext):
                    file_ext = extension

        file_name = '{}{}'.format(sample_hash, file_ext)

        observed_filename = file_summary.get('observed_filename')
        if (observed_filename):
            try:
                file_name = observed_filename[0].split('\\')[-1]
            except:
                pass

        # move the file to the vault
        vault_ret_dict = Vault.add_attachment(file_path, self.get_container_id(), file_name=file_name, metadata={'contains': contains})
        curr_data = action_result.get_data()[0]
        curr_data[CARBONBLACK_JSON_FILE_DETAILS] = file_summary

        if (vault_ret_dict['succeeded']):
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
            curr_data[phantom.APP_JSON_NAME] = file_name
            wanted_keys = [phantom.APP_JSON_VAULT_ID, phantom.APP_JSON_NAME]
            summary = {x: curr_data[x] for x in wanted_keys}
            if (contains):
                summary.update({'file_type': ','.join(contains)})
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])

        # remove the /tmp/<> temporary directory
        shutil.rmtree(local_dir)

        return phantom.APP_ERROR

    def _save_file_to_vault(self, action_result, response, sample_hash):

        # Create a tmp directory on the vault partition
        guid = uuid.uuid4()

        if hasattr(Vault, 'get_vault_tmp_dir'):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = '/vault/tmp'

        local_dir = temp_dir + '/{}'.format(guid)
        self.save_progress("Using {0} directory: {1}".format(temp_dir, guid))

        try:
            os.makedirs(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to create temporary folder {0}.".format(temp_dir), e)

        zip_file_path = "{0}/{1}.zip".format(local_dir, sample_hash)

        # open and download the file
        with open(zip_file_path, 'wb') as f:
            f.write(response.content)

        # Open the zip file
        zf = zipfile.ZipFile(zip_file_path)

        # zipped_file_names = zf.namelist()
        # zipped_file_names = zipped_file_names

        try:
            # extract them
            zf.extractall(local_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to extract the zip file", e)

        # create the file_path
        file_path = "{0}/filedata".format(local_dir)

        contains = []
        file_ext = ''
        magic_str = magic.from_file(file_path)
        for regex, cur_contains, extension in self.MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)
                if (not file_ext):
                    file_ext = extension

        file_name = '{}{}'.format(sample_hash, file_ext)

        # now try to get info about the file from CarbonBlack
        ret_val, file_summary = self._get_file_summary(sample_hash)

        if (phantom.is_success(ret_val)):
            observed_filename = file_summary.get('observed_filename')
            if (observed_filename):
                try:
                    file_name = observed_filename[0].split('\\')[-1]
                except:
                    pass

        # move the file to the vault
        vault_ret_dict = Vault.add_attachment(file_path, self.get_container_id(), file_name=file_name, metadata={'contains': contains})
        curr_data = action_result.add_data({})
        curr_data[CARBONBLACK_JSON_FILE_DETAILS] = file_summary

        if (vault_ret_dict['succeeded']):
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
            curr_data[phantom.APP_JSON_NAME] = file_name
            wanted_keys = [phantom.APP_JSON_VAULT_ID, phantom.APP_JSON_NAME]
            summary = {x: curr_data[x] for x in wanted_keys}
            if (contains):
                summary.update({'file_type': ','.join(contains)})
            summary.update({CARBONBLACK_JSON_FILE_CB_URL: '{0}/#/binary/{1}'.format(self._base_url, sample_hash)})
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(vault_ret_dict['message'])

        # remove the /tmp/<> temporary directory
        shutil.rmtree(local_dir)

        return action_result.get_status()

    def _run_command(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sensor_id = param[CARBONBLACK_JSON_SENSOR_ID]
        command = param['command'].lower()
        try:
            data = json.loads(param['data'])
        except:
            return action_result.set_status(phantom.APP_ERROR,
                    'Error while parsing json string provided in data parameter. Please provide a valid JSON string.')

        if sensor_id and not self._is_valid_integer(sensor_id):
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_INTEGER_VALUE)

        # First get a session id
        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if not session_id:
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress("Got live session ID: {0}".format(session_id))

        ret_val, resp = self._execute_live_session_command(session_id, action_result, command, data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(resp)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _execute_program(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sensor_id = param[CARBONBLACK_JSON_SENSOR_ID]

        if sensor_id and not self._is_valid_integer(sensor_id):
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_INTEGER_VALUE)

        data = {
            'object': param['entire_executable_path'],
            'wait': param.get('wait', False)
        }
        if param.get('working_directory'):
            data.update({ 'working_directory': param.get('working_directory') })
        if param.get('output_file'):
            data.update({ 'output_file': param.get('output_file') })

        # First get a session id
        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if not session_id:
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress("Got live session ID: {0}".format(session_id))

        ret_val, resp = self._execute_live_session_command(session_id, action_result, 'create process', data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(resp)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _memory_dump(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sensor_id = param[CARBONBLACK_JSON_SENSOR_ID]

        if sensor_id and not self._is_valid_integer(sensor_id):
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_INTEGER_VALUE)

        data = {
            'object': param['destination_path'],
            'compress': param.get('compress', False)
        }

        # First get a session id
        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if not session_id:
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress("Got live session ID: {0}".format(session_id))

        ret_val, resp = self._execute_live_session_command(session_id, action_result, 'memdump', data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(resp)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _put_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_id = param[CARBONBLACK_JSON_VAULT_ID]
        destination = param[CARBONBLACK_JSON_DESTINATION_PATH]
        sensor_id = param[CARBONBLACK_JSON_SENSOR_ID]

        if sensor_id and not self._is_valid_integer(sensor_id):
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_INTEGER_VALUE)

        # First get a session id
        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if not session_id:
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress("Got live session ID: {0}".format(session_id))

        # Upload File to Server
        vault_path = str(Vault.get_file_path(vault_id))
        url = '/v1/cblr/session/{session_id}/file'.format(session_id=session_id)
        data = { 'file': open(vault_path, 'rb') }

        ret_val, response = self._make_rest_call(url, action_result, files=data, method='post')

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Get the file_id from the Upload File to Server response
        file_id = response.get('id')

        # Post the file to the host
        data = {'object': destination, 'file_id': file_id}

        ret_val, resp = self._execute_live_session_command(session_id, action_result, 'put file', data)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(resp)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sample_hash = param.get(CARBONBLACK_JSON_HASH)

        if sample_hash:
            self.save_progress("Querying Carbon Black Response for hash")
            url = '/v1/binary/{0}'.format(sample_hash)

            ret_val, response = self._make_rest_call(url, action_result, parse_response_json=False, additional_succ_codes={404: CARBONBLACK_MSG_FILE_NOT_FOUND})

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            if (response == CARBONBLACK_MSG_FILE_NOT_FOUND):
                return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_MSG_FILE_NOT_FOUND)

            return self._save_file_to_vault(action_result, response, sample_hash)
        else:
            self.save_progress("Querying Carbon Black Response for file")

            file_source = param.get('file_source')
            offset = param.get('offset')
            get_count = param.get('get_count')
            sensor_id = param.get(CARBONBLACK_JSON_SENSOR_ID)

            if sensor_id and not self._is_valid_integer(sensor_id):
                return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_INTEGER_VALUE)

            if not file_source:
                return action_result.set_status(phantom.APP_ERROR,
                        'Please provide either hash or file_source parameter value')
            elif not sensor_id:
                return action_result.set_status(phantom.APP_ERROR,
                        'Please provide sensor_id if file is fetched using file_source parameter value')

            # First get a session id
            ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            if not session_id:
                return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

            self.save_progress("Got live session ID: {0}".format(session_id))

            data = {'object': file_source}
            if offset:
                data.update({'offset': offset})
            if get_count:
                data.update({'get_count': get_count})

            # Get file and file id
            ret_val, response = self._execute_live_session_command(session_id, action_result, 'get file', data)

            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            file_id = response.get('id')

            # Download file from server
            url = '/v1/cblr/session/{session_id}/file/{file_id}/content'.format(session_id=session_id, file_id=file_id)

            response = requests.get(self._rest_uri + url, headers={'X-Auth-Token': self._api_token}, stream=True, verify=False)

            guid = uuid.uuid4()

            if hasattr(Vault, 'get_vault_tmp_dir'):
                temp_dir = Vault.get_vault_tmp_dir()
            else:
                temp_dir = '/vault/tmp'

            local_dir = temp_dir + '/{}'.format(guid)
            self.save_progress("Using {0} directory: {1}".format(temp_dir, guid))

            try:
                os.makedirs(local_dir)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Unable to create temporary folder {0}.".format(temp_dir), e)

            zip_file_path = "{0}/{1}.zip".format(local_dir, file_source)

            # open and download the file
            with open(zip_file_path, 'wb') as fd:
                for chunk in response.iter_content(chunk_size=128):
                    fd.write(chunk)

            file_name = file_source.replace('\\\\', '\\')

            vault_ret_dict = Vault.add_attachment(zip_file_path, self.get_container_id(), file_name=file_name)

            curr_data = action_result.add_data({ 'session_id': session_id, 'file_id': file_id })

            if (vault_ret_dict['succeeded']):
                curr_data[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
                curr_data[phantom.APP_JSON_NAME] = file_name
                wanted_keys = [phantom.APP_JSON_VAULT_ID, phantom.APP_JSON_NAME]
                summary = {x: curr_data[x] for x in wanted_keys}
                action_result.update_summary(summary)
                action_result.set_status(phantom.APP_SUCCESS)
            else:
                action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)
                action_result.append_to_message(vault_ret_dict['message'])

            # remove the /tmp/<> temporary directory
            shutil.rmtree(local_dir)

            return action_result.get_status()

    def _get_file_info(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sample_hash = param[CARBONBLACK_JSON_HASH]

        # now try to get info about the file from CarbonBlack
        ret_val, file_summary = self._get_file_summary(sample_hash, action_result, additional_succ_codes={404: CARBONBLACK_MSG_FILE_NOT_FOUND})

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (file_summary == CARBONBLACK_MSG_FILE_NOT_FOUND):
            return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_MSG_FILE_NOT_FOUND)

        curr_data = action_result.add_data({})
        curr_data[CARBONBLACK_JSON_FILE_DETAILS] = file_summary

        summary = {'name': file_summary.get('original_filename'),
                'os_type': file_summary.get('os_type'),
                'architecture': '64 bit' if file_summary.get('is_64bit', False) else '32 bit',
                'size': file_summary.get('orig_mod_len'),
                CARBONBLACK_JSON_FILE_CB_URL: '{0}/#/binary/{1}'.format(self._base_url, sample_hash)}

        action_result.update_summary(summary)

        download = param.get(CARBONBLACK_JSON_DOWNLOAD, False)

        if (not download):
            return action_result.set_status(phantom.APP_SUCCESS)

        return self._download_file_to_vault(action_result, file_summary, sample_hash)

    def _sync_sensor_events(self, sensor_id, action_result):
        """ Called when a sensor_id has been determined and the events need to be flushed to the server
        """

        if (sensor_id is None):
            return action_result.set_status(phantom.APP_ERROR, "Sensor ID not found")

        ret_val, sensor = self._make_rest_call("/v1/sensor/{0}".format(sensor_id), action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if not sensor or 'status' not in sensor or sensor['status'] != 'Online':
            return (action_result.set_status(phantom.APP_ERROR, "Unable to find valid sensor to sync"), None)

        # any time in the future should work, but the official API uses now + 24h, so we will use that as well
        # the timezone is hard-coded to match what was seen in the web interface
        sensor['event_log_flush_time'] = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime('%a, %d %b %Y %H:%M:%S GMT')

        ret_val, body = self._make_rest_call("/v1/sensor/{0}".format(sensor_id), action_result, data=sensor, method="put", additional_succ_codes={204: []})

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_SYNC_EVENTS)

    def _is_valid_integer(self, input_value):
        try:
            if not str(input_value).isdigit():
                raise ValueError
        except ValueError:
            return False
        return True

    def _sync_events(self, param):
        """ Force the sensor with the given sensor_id or ip_hostname to flush all its recorded events to the server.
          " If the sensor_id is specified it will be used, otherwise the ip_hostname will be used to query for the sensor_id
          "
          " The flush is done by writing a future datetime to the sensor's event_log_flush_time and PUTing the new sensor data
        """

        ip_hostname = param.get(phantom.APP_JSON_IP_HOSTNAME)
        sensor_id = param.get(CARBONBLACK_JSON_SENSOR_ID)

        if ((not ip_hostname) and (sensor_id is None)):
            action_result = self.add_action_result(ActionResult(param))
            return action_result.set_status(phantom.APP_ERROR, "Neither {0} nor {1} specified. Please specify at-least one of them".format(phantom.APP_JSON_IP_HOSTNAME,
                CARBONBLACK_JSON_SENSOR_ID))

        if (sensor_id is not None):

            # set the param to _only_ contain the sensor_id, since that's the only one we are using
            action_result = self.add_action_result(ActionResult({CARBONBLACK_JSON_SENSOR_ID: sensor_id}))

            if sensor_id and not self._is_valid_integer(sensor_id):
                return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_INTEGER_VALUE)

            self._sync_sensor_events(sensor_id, action_result)
            return action_result.get_status()

        sys_info_ar = ActionResult(param)

        ret_val = self._get_system_info_from_cb(ip_hostname, sys_info_ar)

        if (phantom.is_fail(ret_val) or not sys_info_ar.get_data()):
            self.add_action_result(sys_info_ar)
            return sys_info_ar.get_status()

        systems = sys_info_ar.get_data()

        self.save_progress("Got {0} systems".format(len(systems)))

        for system in systems:
            action_result = self.add_action_result(ActionResult({phantom.APP_JSON_IP_HOSTNAME: system.get('computer_name')}))
            if (system.get('status') != 'Online'):
                action_result.set_status(phantom.APP_ERROR, "Ignoring Offline Endpoint")
                continue
            self._sync_sensor_events(system.get('id'), action_result)

        return phantom.APP_SUCCESS

    def _get_system_info(self, param):

        action_result = self.add_action_result(ActionResult(param))

        sensor_id = param.get(CARBONBLACK_JSON_SENSOR_ID)
        ip_hostname = param.get(phantom.APP_JSON_IP_HOSTNAME)

        if sensor_id and not self._is_valid_integer(sensor_id):
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_INTEGER_VALUE)

        if ((not ip_hostname) and (sensor_id is None)):
            return action_result.set_status(phantom.APP_ERROR, "Neither {0} nor {1} specified. Please specify at-least one of them".format(phantom.APP_JSON_IP_HOSTNAME,
                CARBONBLACK_JSON_SENSOR_ID))

        return self._get_system_info_from_cb(ip_hostname, action_result, sensor_id)

    def _quarantine_device(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ip_hostname = param[phantom.APP_JSON_IP_HOSTNAME]

        ret_val, response = self._set_isolate_state(ip_hostname, action_result, True)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_QUARANTINE)

    def _unquarantine_device(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ip_hostname = param[phantom.APP_JSON_IP_HOSTNAME]

        ret_val, response = self._set_isolate_state(ip_hostname, action_result, False)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_UNQUARANTINE)

    def _set_isolate_state(self, ip_hostname, action_result, state=True):

        if (phantom.is_ip(ip_hostname)):
            query_parameters = {'ip': ip_hostname}
        else:
            query_parameters = {'hostname': ip_hostname}

        # make a rest call to get the sensors
        ret_val, sensors = self._make_rest_call("/v1/sensor", action_result, params=query_parameters, additional_succ_codes={204: []})

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        if (not sensors):
            return (action_result.set_status(phantom.APP_ERROR, "Unable to find endpoint, sensor list was empty"), None)

        sensors = [x for x in sensors if x.get('status') == 'Online']

        if (not sensors):
            return (action_result.set_status(phantom.APP_ERROR, "Unable to find an online endpoint, sensor list was empty"), None)

        num_endpoints = len(sensors)

        if (num_endpoints > 1):
            # add the sensors found in the action_result
            self._add_sensor_info_to_result(sensors, action_result)
            return (action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_MULTI_ENDPOINTS.format(num_endpoints=num_endpoints)), None)

        # get the id, of the 1st one, that's what we will be working on
        data = sensors[0]

        if ('id' not in data):
            return (action_result.set_status(phantom.APP_ERROR, "Unable to find endpoint id in response"), None)

        endpoint_id = data['id']

        # set the isolation status
        data['network_isolation_enabled'] = state

        # make a rest call to set the endpoint state
        ret_val, response = self._make_rest_call("/v1/sensor/{0}".format(endpoint_id), action_result, method="put",
                data=data, params=query_parameters, parse_response_json=False, additional_succ_codes={204: []})

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        return (phantom.APP_SUCCESS, sensors)

    def _unblock_hash(self, param):

        action_result = self.add_action_result(ActionResult(param))

        unblock_hash = param[CARBONBLACK_JSON_HASH]

        url = "/v1/banning/blacklist/{0}".format(unblock_hash)

        # make a rest call to unblock the hash
        ret_val, response = self._make_rest_call(url, action_result, method="delete", parse_response_json=False,
                additional_succ_codes={409: None})

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if ('does not exist' in response):
            return action_result.set_status(phantom.APP_ERROR, 'Supplied MD5 is not currently banned/blocked.')

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_UNBLOCK if (not response or type(response) != str) else response)

    def _get_license(self, param):

        action_result = self.add_action_result(ActionResult(param))

        url = "/v1/license"

        # make a rest call
        ret_val, response = self._make_rest_call(url, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        try:
            action_result.update_summary({'license_valid': response['license_valid']})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS)

    def _block_hash(self, param):

        action_result = self.add_action_result(ActionResult(param))

        block_hash = param[CARBONBLACK_JSON_HASH]

        data = {'md5hash': block_hash,
                'text': 'Blocked by Phantom for container {0}'.format(self.get_container_id()),
                'last_ban_time': '0',
                'ban_count': '0',
                'last_ban_host': '0',
                'enabled': True}

        comment = param.get(CARBONBLACK_JSON_COMMENT)

        if (comment):
            data.update({'text': comment})

        # set the isolation status
        data['enabled'] = True

        # make a rest call to set the hash state
        ret_val, response = self._make_rest_call("/v1/banning/blacklist", action_result, method="post",
                data=data, parse_response_json=False, additional_succ_codes={409: None})

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_BLOCK if (not response or type(response) != str) else response)

    def _add_sensor_info_to_result(self, sensors, action_result):

        for sensor in sensors:
            action_result.add_data(sensor)
            if ('network_adapters' not in sensor):
                continue

            adapters = sensor['network_adapters'].split('|')

            if (not adapters):
                continue

            ips = []
            for adapter in adapters:
                ip = adapter.split(',')[0].strip()
                if (not ip):
                    continue
                ips.append(ip)

            sensor[CARBONBLACK_JSON_IPS] = ','.join(ips)

    def _list_endpoints(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val, sensors = self._make_rest_call("/v1/sensor", action_result, additional_succ_codes={204: []})

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.set_summary({CARBONBLACK_JSON_TOTAL_ENDPOINTS: len(sensors)})

        if (not sensors):
            return action_result.set_status(phantom.APP_SUCCESS)

        self._add_sensor_info_to_result(sensors, action_result)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_watchlists(self, action_result, wl_id=None):

        endpoint = "/v1/watchlist"

        if (wl_id):
            endpoint += "/{0}".format(wl_id)

        ret_val, watchlists = self._make_rest_call(endpoint, action_result, additional_succ_codes={204: []})

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        return (phantom.APP_SUCCESS, watchlists)

    def _list_alerts(self, param):

        action_result = self.add_action_result(ActionResult(param))

        ret_val, watchlists = self._get_watchlists(action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.set_summary({CARBONBLACK_JSON_TOTAL_WATCHLISTS: len(watchlists)})

        for watchlist in watchlists:
            try:
                watchlist['quoted_query'] = six.moves.urllib.parse.unquote(watchlist['search_query'][2:].replace('cb.urlver=1&', ''))
                watchlist['query_type'] = CARBONBLACK_QUERY_TYPE_BINARY if watchlist['index_type'] == 'modules' else CARBONBLACK_QUERY_TYPE_PROCESS
            except:
                pass
            action_result.add_data(watchlist)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _run_query(self, param):

        action_result = self.add_action_result(ActionResult(param))

        query_type = param[CARBONBLACK_JSON_QUERY_TYPE]

        if query_type not in VALID_QUERY_TYPE:
            return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_ERR_INVALID_QUERY_TYPE, types=', '.join(VALID_QUERY_TYPE))

        query = param[CARBONBLACK_JSON_QUERY]

        ret_val, start, rows = self._parse_range(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress(CARBONBLACK_RUNNING_QUERY)

        ret_val, search_results = self._search(query_type, action_result, query, start=start, rows=rows)

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_PROCESS_SEARCH)

        action_result.add_data(search_results)

        action_result.set_summary({CARBONBLACK_JSON_NUM_RESULTS: len(search_results.get('results', []))})

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_DISPLAYING_RESULTS_TOTAL,
                displaying=len(search_results.get('results', [])), query_type=query_type, total=search_results.get('total_results', 'Unknown'))

    def _create_alert(self, param):

        action_result = self.add_action_result(ActionResult(param))

        query_type = param[CARBONBLACK_JSON_ALERT_TYPE]

        if query_type not in VALID_QUERY_TYPE:
            return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_ERR_INVALID_QUERY_TYPE, types=', '.join(VALID_QUERY_TYPE))

        query = param[CARBONBLACK_JSON_QUERY]

        query = six.moves.urllib.parse.quote(query)

        if "cb.urlver=1&" not in query:
            query = "cb.urlver=1&" + query

        if "q=" not in query:
            query = "q=" + query

        name = param[CARBONBLACK_JSON_NAME]
        read_only = param.get(CARBONBLACK_JSON_READONLY, False)

        self.save_progress(CARBONBLACK_ADDING_WATCHLIST)

        # default to binary/modules
        index_type = 'modules'
        if (query_type == CARBONBLACK_QUERY_TYPE_PROCESS):
            index_type = 'events'

        for kvpair in query.split('&'):
            # print kvpair
            if len(kvpair.split('=')) != 2:
                continue
            if kvpair.split('=')[0] != 'q':
                continue

            # the query itself must be percent-encoded
            # verify there are only non-reserved characters present
            # no logic to detect unescaped '%' characters
            for c in kvpair.split('=')[1]:
                if c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~%":
                    return action_result.set_status(phantom.APP_ERROR, "Unescaped non-reserved character '{0}' found in query; use percent-encoding".format(c))

        request = {
                'index_type': index_type,
                'name': name,
                'search_query': query,
                'readonly': read_only}

        ret_val, watchlist = self._make_rest_call("/v1/watchlist", action_result, method="post", data=request)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        self.save_progress(CARBONBLACK_ADDED_WATCHLIST)

        self.save_progress(CARBONBLACK_FETCHING_WATCHLIST_INFO)

        if ('id' not in watchlist):
            return action_result.set_status(phantom.APP_ERROR, "Watchlist ID not found in the recently added watchlist")

        ret_val, watchlist = self._get_watchlists(action_result, watchlist['id'])

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        try:
            watchlist['quoted_query'] = six.moves.urllib.parse.unquote(watchlist['search_query'][2:].replace('cb.urlver=1&', ''))
            watchlist['query_type'] = CARBONBLACK_QUERY_TYPE_BINARY if watchlist['index_type'] == 'modules' else CARBONBLACK_QUERY_TYPE_PROCESS
        except:
            pass

        action_result.add_data(watchlist)

        action_result.set_summary({CARBONBLACK_JSON_ADDED_WL_ID: watchlist['id']})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _parse_range(self, param, action_result):

        range = param.get(CARBONBLACK_JSON_RANGE, "0-10")

        p = parse("{start}-{end}", range)

        # Check if the format of the range is correct
        if (p is None):
            return (action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_RANGE), None, None)

        if not self._is_valid_integer(p['start']):
            return (action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_RANGE), None, None)

        if not self._is_valid_integer(p['end']):
            return (action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_RANGE), None, None)

        # get the values in int
        start = int(p['start'])
        end = int(p['end'])

        # Validate the range set
        if (end < start):
            return (action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_INVALID_RANGE), None, None)

        # get the rows
        rows = end - start

        # if the number of rows is zero, that means the user wants just one entry
        if (rows == 0):
            rows = 1

        return (phantom.APP_SUCCESS, start, rows)

    def _search(self, search_type, action_result, query, start, rows):

        data = {
                "params": "server_added_timestamp desc",
                "start": start,
                "rows": rows,
                "facet": ['true', 'true'],
                "cb.urlver": ['1'],
                "q": [query]}

        # Search results are returned as lists
        ret_val, response = self._make_rest_call("/v1/{0}".format(search_type), action_result, method="post", data=data, additional_succ_codes={204: []})

        if (phantom.is_fail(ret_val)):
            return (action_result.get_status(), None)

        return (phantom.APP_SUCCESS, response)

    def _hunt_file(self, param):

        query_type = param.get(CARBONBLACK_JSON_QUERY_TYPE, CARBONBLACK_QUERY_TYPE_BINARY)

        # Add the query type in the parameter, since the view needs it to be there
        param[CARBONBLACK_JSON_QUERY_TYPE] = query_type

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, start, rows = self._parse_range(param, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if query_type not in VALID_QUERY_TYPE:
            return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_ERR_INVALID_QUERY_TYPE, types=', '.join(VALID_QUERY_TYPE))

        data = action_result.add_data({query_type: None})

        self.save_progress(CARBONBLACK_DOING_SEARCH.format(query_type=query_type))

        # Binary search
        ret_val, results = self._search(query_type, action_result, "md5:{0}".format(param[CARBONBLACK_JSON_HASH]), start=start, rows=rows)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (phantom.is_success(ret_val) and results):
            data[query_type] = results

        summary = CARBONBLACK_DISPLAYING_RESULTS_TOTAL.format(displaying=len(results.get('results', [])),
                query_type=query_type, total=results.get('total_results', 'Unknown'))

        action_result.set_summary({ "device_count": results.get('total_results', 'Unknown')})

        return action_result.set_status(phantom.APP_SUCCESS, summary)

    def _list_connections(self, param):
        """ All of the parameters for this optional, but of course some need to present
          " Fundamentally, it should work like this:
          "
          " if carbonblack_id
          "     get connections for id
          " elif pid AND ip_hostname:
          "     get list of hosts
          "     for each host, get connections for pid
          " elif process_name AND ip_hostname:
          "     get list of hosts
          "     for each host, get connections for process_name
          " else
          "     invalid input
          "
          " The parameters for this function have become kind of convoluted at this point
          " That said, _get_connections_for_process is generic enough to work on any search criteria
          " If some parameters need to be added to this in the future, you'll need to figure out
          "  how to turn the criteria into parameters for a process search
          " Then, you'll need to decide if ip_hostname is required to be used with it
        """
        ip_hostname = param.get(phantom.APP_JSON_IP_HOSTNAME, "")
        pid = param.get(CARBONBLACK_JSON_PID, "")
        process = param.get(CARBONBLACK_JSON_PROCESS_NAME, "")
        cb_id = param.get(CARBONBLACK_JSON_CB_ID, "")

        # We need to validate that the user gave proper input
        # Needs search criteria
        if (not pid and not process and not cb_id):
            action_result = self.add_action_result(ActionResult(param))
            msg = "Need to specify at least one of {}, {}, or {}".format(CARBONBLACK_JSON_PROCESS_NAME,
                    CARBONBLACK_JSON_PID, CARBONBLACK_JSON_CB_ID)
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Searching by carbonblack id is a bit different
        if (cb_id):
            action_result = self.add_action_result(ActionResult(param))
            query_parameters = {"cb.q.process_id": cb_id}
            return self._get_connections_for_process(query_parameters, action_result)

        # Need a hostname to search by pid or process id
        if (not ip_hostname):
            action_result = self.add_action_result(ActionResult(param))
            msg = "Need to specify an IP or hostname to search by {} or {}".format(CARBONBLACK_JSON_PROCESS_NAME,
                    CARBONBLACK_JSON_PID)
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Get a list of systems matching ip/hostname
        sys_info_ar = ActionResult(param)

        ret_val = self._get_system_info_from_cb(ip_hostname, sys_info_ar)

        if (phantom.is_fail(ret_val)):
            self.add_action_result(sys_info_ar)
            return sys_info_ar.get_status()

        systems = sys_info_ar.get_data()

        if (not systems):
            self.add_action_result(sys_info_ar)
            return sys_info_ar.set_status(phantom.APP_ERROR, CARBONBLACK_ERR_NO_ENDPOINTS.format(ip_hostname))

        # Generate query parameters
        query_parameters = {}
        if (pid):
            query_parameters['cb.q.process_pid'] = pid
            d = {'pid': pid}
        else:
            query_parameters['cb.q.process_name'] = process
            d = {'process_name': process}

        # Find process / pid on each system
        for system in systems:
            action_result = self.add_action_result(ActionResult(dict(d, **{phantom.APP_JSON_IP_HOSTNAME: system.get('computer_name')})))
            if (system.get('status') != 'Online'):
                action_result.set_status(phantom.APP_ERROR, "Ignoring Offline Endpoint")
                continue
            query_parameters['cb.q.hostname'] = system.get('computer_name')
            self._get_connections_for_process(query_parameters, action_result)

        return phantom.APP_SUCCESS

    def _validate_version(self, action_result):

        # make a rest call to get the info
        ret_val, info = self._make_rest_call("/info", action_result)

        if (phantom.is_fail(ret_val)):
            action_result.append_to_message("Product version validation failed.")
            return action_result.get_status()

        # get the version of the device
        device_version = info.get('version')
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
            self.debug_print("This version of CarbonBlack is not officially supported. Supported versions: '{0}'".format(version_regex))
            # self.save_progress(message)

        self.save_progress("Version validation done")

        return phantom.APP_SUCCESS

    def _reset_session(self, param):

        action_result = self.add_action_result(ActionResult(param))

        session_id = param[CARBONBLACK_JSON_SESSION_ID]
        url = '/v1/cblr/session/{}/keepalive'.format(session_id)
        error_msg = CARBONBLACK_ERR_RESET_SESSION.format(session_id=session_id)

        # make a rest call to get the info
        ret_val, response = self._make_rest_call(url, action_result, additional_succ_codes={404: error_msg})

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        if (response == error_msg):
            return action_result.set_status(phantom.APP_ERROR, response)

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_RESET_SESSION.format(session_id=session_id))

    def _on_poll(self, param):
        DT_STR_FORMAT = '%Y-%m-%dT%H:%M:%S'

        if (self._state.get('first_run', True)):
            self._state['first_run'] = False
            self._state.update({'last_ingested_time': datetime.datetime(1970, 1, 1).strftime(DT_STR_FORMAT)})

        action_result = self.add_action_result(ActionResult(dict(param)))
        endpoint = '/v1/alert?cb.q.created_time=%5B{0}%20TO%20*%5D&cb.fq.status=Unresolved&sort=alert_severity%20desc'.format(self._state['last_ingested_time'])
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            self.debug_print(action_result.get_message())
            self.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR
        else:
            self._state['last_ingested_time'] = datetime.datetime.now().strftime(DT_STR_FORMAT)
            self.save_state(self._state)

        results = response['results']

        for result in results:
            cef = {}
            cont = {}
            cont['name'] = "Unresolved CB_Response Alert: " + result['watchlist_name']
            cont['description'] = "Unresolved CB_Response Alerts"
            cont['source_data_identifier'] = result['unique_id']

            for key, value in result.iteritems():
                cef[key] = value
                # Create List to contain artifacts
                artList = []
                # Create the artifact
                art = {
                    'label': 'alert',
                    'cef': cef,
                }
                # Append Artifact to List
                artList.append(art)
                cont['data'] = result
                # Create "artifacts" field in Container
                cont['artifacts'] = artList

            status, msg, container_id_ = self.save_container(cont)
            if status == phantom.APP_ERROR:
                self.debug_print("Failed to store: {}".format(msg))
                self.debug_print('stat/msg {}/{}'.format(status, msg))
                action_result.set_status(phantom.APP_ERROR, 'Container creation failed: {}'.format(msg))
                return status
        return action_result.set_status(phantom.APP_SUCCESS)

    def _test_connectivity(self, param):

        # Progress
        self.save_progress(CARBONBLACK_USING_BASE_URL, base_url=self._base_url)

        url = self._base_url
        host = url[url.find('//') + 2:]

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, host)

        action_result = ActionResult()

        # validate the version, this internally makes all the rest calls to validate the config also
        ret_val = self._validate_version(action_result)

        if (phantom.is_fail(ret_val)):
            self.set_status(ret_val, action_result.get_message())
            self.append_to_message(CARBONBLACK_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, CARBONBLACK_SUCC_CONNECTIVITY_TEST)

    def handle_action(self, param):

        result = None
        action = self.get_action_identifier()

        # test connectivity is handled differently
        if (action != phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            action_result = ActionResult(param)
            # validate the version, this internally makes all the rest calls to validate the config also
            if (phantom.is_fail(self._validate_version(action_result))):
                self.add_action_result(action_result)
                return action_result.get_status()

        if (action == self.ACTION_ID_HUNT_FILE):
            result = self._hunt_file(param)
        elif (action == self.ACTION_ID_LIST_ALERTS):
            result = self._list_alerts(param)
        elif (action == self.ACTION_ID_LIST_ENDPOINTS):
            result = self._list_endpoints(param)
        elif (action == self.ACTION_ID_CREATE_ALERT):
            result = self._create_alert(param)
        elif (action == self.ACTION_ID_RUN_QUERY):
            result = self._run_query(param)
        elif (action == self.ACTION_ID_QUARANTINE_DEVICE):
            result = self._quarantine_device(param)
        elif (action == self.ACTION_ID_UNQUARANTINE_DEVICE):
            result = self._unquarantine_device(param)
        elif (action == self.ACTION_ID_SYNC_EVENTS):
            result = self._sync_events(param)
        elif (action == self.ACTION_ID_GET_SYSTEM_INFO):
            result = self._get_system_info(param)
        elif (action == self.ACTION_ID_LIST_PROCESSES):
            result = self._list_processes(param)
        elif (action == self.ACTION_ID_TERMINATE_PROCESS):
            result = self._terminate_process(param)
        elif (action == self.ACTION_ID_GET_FILE):
            result = self._get_file(param)
        elif (action == self.ACTION_ID_GET_FILE_INFO):
            result = self._get_file_info(param)
        elif (action == self.ACTION_ID_BLOCK_HASH):
            result = self._block_hash(param)
        elif (action == self.ACTION_ID_UNBLOCK_HASH):
            result = self._unblock_hash(param)
        elif (action == self.ACTION_ID_LIST_CONNECTIONS):
            result = self._list_connections(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            result = self._test_connectivity(param)
        elif (action == self.ACTION_ID_GET_LICENSE):
            result = self._get_license(param)
        elif (action == self.ACTION_ID_ON_POLL):
            result = self._on_poll(param)
        elif (action == self.ACTION_ID_PUT_FILE):
            result = self._put_file(param)
        elif (action == self.ACTION_ID_RUN_COMMAND):
            result = self._run_command(param)
        elif (action == self.ACTION_ID_EXECUTE_PROGRAM):
            result = self._execute_program(param)
        elif (action == self.ACTION_ID_RESET_SESSION):
            result = self._reset_session(param)
        elif (action == self.ACTION_ID_MEMORY_DUMP):
            result = self._memory_dump(param)

        return result


if __name__ == '__main__':

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

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CarbonblackConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
