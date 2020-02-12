# File: checkpoint_connector.py
# Copyright (c) 2017-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# imports specific to this connector
from checkpoint_consts import *

import simplejson as json
import requests
import socket
import struct
import time
import re


# Define the App Class
class CheckpointConnector(BaseConnector):

    # The actions supported by this connector
    ACTION_ID_BLOCK_IP = "block_ip"
    ACTION_ID_UNBLOCK_IP = "unblock_ip"
    ACTION_ID_LIST_LAYERS = "list_layers"
    ACTION_ID_LIST_POLICIES = "list_policies"
    ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"

    def __init__(self):

        # Call the BaseConnectors init first
        super(CheckpointConnector, self).__init__()

        self._base_url = None
        self._sid = None
        self._headers = None

    def initialize(self):

        config = self.get_config()

        # Base URL
        base_url = config[phantom.APP_JSON_URL]
        base_url = base_url + ('' if base_url.endswith('/') else '/')
        self._base_url = '{0}web_api/'.format(base_url)

        # Headers will always need content-Type
        self._headers = {"content-Type": "application/json"}

        self.set_validator('ip', self._is_ip)

        return phantom.APP_SUCCESS

    def _get_net_size(self, net_mask):

        net_mask = net_mask.split('.')

        binary_str = ''
        for octet in net_mask:
            binary_str += bin(int(octet))[2:].zfill(8)

        return str(len(binary_str.rstrip('0')))

    def _get_net_mask(self, net_size):

        host_bits = 32 - int(net_size)

        net_mask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))

        return net_mask

    def _break_ip_addr(self, ip_addr):

        ip = None
        net_size = None
        net_mask = None

        if ('/' in ip_addr):
            ip, net_size = ip_addr.split('/')
            net_mask = self._get_net_mask(net_size)
        elif(' ' in ip_addr):
            ip, net_mask = ip_addr.split()
            net_size = self._get_net_size(net_mask)
        else:
            ip = ip_addr
            net_size = "32"
            net_mask = "255.255.255.255"

        return (ip, net_size, net_mask)

    # Function that checks given address and return True if address is valid ip address or (ip address and subnet)
    def _is_ip(self, ip_addr):

        try:
            ip, net_size, net_mask = self._break_ip_addr(ip_addr)
        except Exception as e:
            self.debug_print("Validation for ip_addr failed", e)
            return False

        # Validate ip address
        if not phantom.is_ip(ip):
            return False

        # Regex to validate the subnet
        reg_exp = re.compile('^((128|192|224|240|248|252|254).0.0.0)|(255.(((0|128|192|224|240|248|252|254).0.0)'
                             '|(255.(((0|128|192|224|240|248|252|254).0)|255.(0|128|192|224|240|248|252|254|255)))))$')

        # Validate subnet
        if net_mask:
            if not reg_exp.match(net_mask):
                return False

        if net_size:
            try:
                net_size = int(net_size)
            except:
                self.debug_print("net_size: {0} invalid int".format(net_size))
                return False

            if (not (0 < net_size <= 32)):
                return False

        return True

    def _make_rest_call(self, endpoint, body, action_result):

        config = self.get_config()

        url = self._base_url + endpoint

        try:
            response = requests.post(url, data=json.dumps(body), headers=self._headers, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, CHECKPOINT_ERR_DEVICE_CONNECTIVITY.format(e)), None

        try:
            resp_json = response.json()
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, CHECKPOINT_ERR_DEVICE_CONNECTIVITY_NOFORMAT), None

        if response.status_code != 200:

            action_result.set_status(phantom.APP_ERROR, CHECKPOINT_ERR_DEVICE_CONNECTIVITY.format(resp_json.get('message')))

            if resp_json.get('warnings'):
                for warning in resp_json.get('warnings'):
                    action_result.append_to_message('\nWARNING: {0}'.format(warning.get('message')))

            if resp_json.get('errors'):
                for error in resp_json.get('errors'):
                    action_result.append_to_message('\nERROR: {0}'.format(error.get('message')))

            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _login(self, action_result):

        if (self._sid is not None):
            # sid already created for this call
            return phantom.APP_SUCCESS

        config = self.get_config()

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self._base_url)
        username = config[phantom.APP_JSON_USERNAME]
        password = config[phantom.APP_JSON_PASSWORD]
        domain = config.get(phantom.APP_JSON_DOMAIN)

        data = {"user": username, "password": password}

        if domain:
            data['domain'] = domain

        ret_val, resp_json = self._make_rest_call('login', data, action_result)

        if (not ret_val):
            return action_result.get_status()

        self._headers['X-chkp-sid'] = resp_json.get('sid')

        return phantom.APP_SUCCESS

    def _publish_and_wait(self, action_result):

        MAX_ITER = 10
        SLEEP_TIME = 6

        ret_val, resp_json = self._make_rest_call('publish', {}, action_result)

        if ((not ret_val) and (not resp_json)):
            return action_result.get_status()

        task_id = resp_json.get('task-id')

        count = 0
        while True:

            if count >= MAX_ITER:
                return False

            time.sleep(SLEEP_TIME)
            count += 1

            ret_val, resp_json = self._make_rest_call('show-task', {'task-id': task_id}, action_result)

            if ((not ret_val) and (not resp_json)):
                continue

            if (resp_json.get('tasks', [{}])[0].get('status') == 'succeeded'):
                return True

    def _check_for_object(self, name, ip, length, action_result):

        endpoint = 'show-hosts'
        if (length != '32'):
            endpoint = 'show-networks'

        body = {"details-level": "full"}

        ret_val, resp_json = self._make_rest_call(endpoint, body, action_result)

        if (not ret_val):
            return None

        found_name = False
        found_object = False
        for net_obj in resp_json.get('objects'):

            if name == net_obj.get('name'):
                found_name = True
                break

            if (length == '32'):
                if (ip == net_obj.get('ipv4-address')):
                    found_object = True
                    name = net_obj.get('name')
                    break

            else:
                if ((ip == net_obj.get('subnet4')) and (length == net_obj.get('mask-length4'))):
                    found_object = True
                    name = net_obj.get('name')
                    break

        if ((found_name) or (found_object)):
            return name

        return ""

    def _check_for_rule(self, name, layer, action_result):

        endpoint = 'show-access-rulebase'

        body = {'name': layer}

        ret_val, resp_json = self._make_rest_call(endpoint, body, action_result)

        if (not ret_val):
            return None

        for rule in resp_json.get('rulebase'):

            if name == rule.get('name'):
                return True

        return False

    def _test_connectivity(self, param):

        # Progress
        self.save_progress(CHECKPOINT_PROG_USING_BASE_URL, base_url=self._base_url)

        status = self._login(self)

        if (phantom.is_fail(status)):
            self.append_to_message(CHECKPOINT_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS, CHECKPOINT_SUCC_CONNECTIVITY_TEST)

    def _list_policies(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(self._login(action_result)):
            return action_result.get_status()

        endpoint = 'show-packages'

        ret_val, resp_json = self._make_rest_call(endpoint, {}, action_result)

        if (not ret_val):
            return action_result.get_status()

        policy_list = []

        for policy in resp_json.get('packages'):

            policy_list.append(policy.get('name'))

        num_policies = len(policy_list)

        if (num_policies):
            message = "Successfully found {0} polic{1}".format(num_policies, 'y' if num_policies == 1 else 'ies')
            action_result.add_data(resp_json)

        else:
            message = "Found no policies"

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _list_layers(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(self._login(action_result)):
            return action_result.get_status()

        endpoint = 'show-access-layers'

        ret_val, resp_json = self._make_rest_call(endpoint, {}, action_result)

        if (not ret_val):
            return action_result.get_status()

        layer_list = []

        for layer in resp_json.get('access-layers'):

            layer_list.append(layer.get('name'))

        num_layers = len(layer_list)

        if (num_layers):
            message = "Successfully found {0} layer{1}".format(num_layers, '' if num_layers == 1 else 's')
            action_result.add_data(resp_json)

        else:
            message = "Found no layers"

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _block_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(self._login(action_result)):
            return action_result.get_status()

        ip, length, mask = self._break_ip_addr(param.get(phantom.APP_JSON_IP))

        layer = param.get('layer')
        policy = param.get('policy')

        object_name = 'phantom - {0}/{1}'.format(ip, length)

        new_name = self._check_for_object(object_name, ip, length, action_result)

        if (new_name is None):
            return action_result.get_status()

        if (new_name is not ""):
            object_name = new_name

        else:

            body = {'name': object_name}

            endpoint = 'add-host'
            json_field = 'ip-address'

            if (length != '32'):
                endpoint = 'add-network'
                json_field = 'subnet'
                body['mask-length'] = length

            body[json_field] = ip

            ret_val, resp_json = self._make_rest_call(endpoint, body, action_result)

            if ((not ret_val) and (not resp_json)):
                return action_result.get_status()

        ret_val = self._check_for_rule(object_name, layer, action_result)

        if (ret_val is None):
            return action_result.get_status()

        if (ret_val):
            return action_result.set_status(phantom.APP_SUCCESS, "IP already blocked. Taking no action.")

        body = {'position': 'top', 'layer': layer, 'action': 'Drop', 'destination': object_name, 'name': object_name}

        ret_val, resp_json = self._make_rest_call('add-access-rule', body, action_result)

        if ((not ret_val) and (not resp_json)):
            return action_result.get_status()

        action_result.add_data(resp_json)

        if (not self._publish_and_wait(action_result)):
            return action_result.set_status(phantom.APP_ERROR, "Could not publish session after changes")

        ret_val, resp_json = self._make_rest_call('install-policy', {'policy-package': policy}, action_result)

        if ((not ret_val) and (not resp_json)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully blocked {0}".format('subnet' if length != '32' else 'IP'))

    def _unblock_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        if not(self._login(action_result)):
            return action_result.get_status()

        ip, length, mask = self._break_ip_addr(param.get(phantom.APP_JSON_IP))

        layer = param.get('layer')
        policy = param.get('policy')

        object_name = 'phantom - {0}/{1}'.format(ip, length)

        ret_val = self._check_for_rule(object_name, layer, action_result)

        if (ret_val is None):
            return action_result.get_status()

        if (not ret_val):
            return action_result.set_status(phantom.APP_SUCCESS, "IP not blocked. Taking no action.")

        body = {'layer': layer, 'name': object_name}

        ret_val, resp_json = self._make_rest_call('delete-access-rule', body, action_result)

        if ((not ret_val) and (not resp_json)):
            return action_result.get_status()

        action_result.add_data(resp_json)

        if (not self._publish_and_wait(action_result)):
            return action_result.set_status(phantom.APP_ERROR, "Could not publish session after changes")

        ret_val, resp_json = self._make_rest_call('install-policy', {'policy-package': policy}, action_result)

        if ((not ret_val) and (not resp_json)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully unblocked {0}".format('subnet' if length != '32' else 'IP'))

    def handle_action(self, param):

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()
        result = None

        self._param = param

        if (action_id == self.ACTION_ID_TEST_CONNECTIVITY):
            result = self._test_connectivity(param)
        elif (action_id == self.ACTION_ID_BLOCK_IP):
            result = self._block_ip(param)
        elif (action_id == self.ACTION_ID_UNBLOCK_IP):
            result = self._unblock_ip(param)
        elif (action_id == self.ACTION_ID_LIST_LAYERS):
            result = self._list_layers(param)
        elif (action_id == self.ACTION_ID_LIST_POLICIES):
            result = self._list_policies(param)

        return result


if __name__ == '__main__':

    import sys
    # import pudb
    # pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CheckpointConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
