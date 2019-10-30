# --
# File: ciscocatalyst_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.ciscoios_connector import CiscoiosConnector
from phantom.ciscoios_consts import *
from phantom.action_result import ActionResult

# THIS Connector imports
from ciscocatalyst_consts import *

# Timeouts in seconds
FIRST_RECV_TIMEOUT = 30
SECOND_ONWARDS_RECV_TIMEOUT = 1
SEND_TIMEOUT = 2

# The max number of bytes to read in Kb
MAX_RECV_BYTES_TO_READ = 5 * 1024


class CiscocatalystConnector(CiscoiosConnector):

    # Actions supported
    ACTION_ID_GET_CONFIG = "get_config"
    ACTION_ID_GET_VERSION = "get_version"
    ACTION_ID_SET_VLAN_ID = "set_vlan"

    def __init__(self):

        # Call the CiscoiosConnector init first
        super(CiscocatalystConnector, self).__init__()

    def _ping_ip(self, ip):

        self.save_progress(CISCOCATALYST_MSG_PINGING_IP_TO_REFRESH_MAC, ip=ip)
        cmd_to_run = "ping {ip} ".format(ip=ip)

        action_result = ActionResult()

        status_code, cmd_output = self._send_command(cmd_to_run, action_result)
        if (phantom.is_fail(status_code)):
            return status_code

        return phantom.APP_SUCCESS

    def _get_mac_of_ip(self, ip, ping_ip, action_result):

        mac_addr = None
        self.save_progress(CISCOCATALYST_MSG_GETTING_MAC_OF_IP)

        # The '| include' clause at the end allows one to _ignore_ the header values of the output table
        cmd_to_run = "show ip device tracking ip {ip} | include {ip} ".format(ip=ip)

        status_code, cmd_output = self._send_command(cmd_to_run, action_result)
        if (phantom.is_fail(status_code)):
            return (action_result.get_status(), mac_addr)

        cmd_output = self._reformat_cmd_output(cmd_output, rem_command=True, to_list=False)

        if (not cmd_output):
            if (ping_ip):
                # Ping the ip and call again
                self._ping_ip(ip)
                return self._get_mac_of_ip(ip, False, action_result)
            return (action_result.set_status(phantom.APP_ERROR, CISCOCATALYST_ERR_IP_MAC_NOT_FOUND), mac_addr)

        cmd_output = cmd_output.strip()
        if (not cmd_output):
            if (ping_ip):
                # Ping the ip and call again
                self._ping_ip(ip)
                return self._get_mac_of_ip(ip, False, action_result)
            return (action_result.set_status(phantom.APP_ERROR, CISCOCATALYST_ERR_IP_MAC_NOT_FOUND), mac_addr)

        # Output is of the following format
        #   IP Address     MAC Address   Vlan  Interface                STATE
        #   10.16.0.206     f80f.41bb.5bdb  160  GigabitEthernet0/24      ACTIVE
        ip_entry = cmd_output.split()
        if (not ip_entry):
            if (ping_ip):
                # Ping the ip and call again
                self._ping_ip(ip)
                return self._get_mac_of_ip(ip, False, action_result)
            return (action_result.set_status(phantom.APP_ERROR, CISCOCATALYST_ERR_IP_MAC_NOT_FOUND), mac_addr)

        mac_addr = ip_entry[-4].strip()

        if (not mac_addr):
            if (ping_ip):
                # Ping the ip and call again
                self._ping_ip(ip)
                return self._get_mac_of_ip(ip, False, action_result)
            return (action_result.set_status(phantom.APP_ERROR, CISCOCATALYST_ERR_IP_MAC_NOT_FOUND), mac_addr)

        return (phantom.APP_SUCCESS, mac_addr)

    def _set_vlan_of_mac(self, mac, param, action_result):

        # Don't know what format it will be in, so just replace everything
        mac = mac.lower()
        s = mac.replace(':', '')
        s = s.replace('.', '')

        mac_addr = '.'.join((s[:4], s[4:8], s[8:12]))

        self.save_progress(CISCOCATALYST_MSG_SEARCHING_MAC)

        # The '| include' clause at the end allows one to _ignore_ the header values of the output table
        cmd_to_run = "show mac address-table address {mac_addr} | include {mac_addr} ".format(mac_addr=mac_addr)

        status_code, cmd_output = self._send_command(cmd_to_run, action_result)
        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        cmd_output = self._reformat_cmd_output(cmd_output, rem_command=True, to_list=False)

        if (not cmd_output):
            return action_result.set_status(phantom.APP_ERROR, CISCOCATALYST_ERR_MAC_NOT_FOUND)

        cmd_output = cmd_output.strip()

        if (not cmd_output):
            return action_result.set_status(phantom.APP_ERROR, CISCOCATALYST_ERR_MAC_NOT_FOUND)

        # Output is of the following format
        # <curr_vlan_id>  <mac_address> <type> <switchport>
        # 170    f80f.41bb.5bdb    STATIC      Gi0/24
        curr_vlan_id, mac_addr, type, port = tuple(cmd_output.split())

        vlan_id = param[CISCOCATALYST_JSON_VLAN_ID]

        if (int(curr_vlan_id) == int(vlan_id)):
            return action_result.set_status(phantom.APP_SUCCESS, CISCOCATALYST_MSG_VLAN_SAME)

        # Get info about the port, Notice the '<space>' after {port} that is to make sure it matches the whole word
        cmd_to_run = "show interfaces status | include {port} ".format(port=port)

        status_code, cmd_output = self._send_command(cmd_to_run, action_result)
        if (phantom.is_fail(status_code)):
            return action_result.get_status()

        cmd_output = self._reformat_cmd_output(cmd_output, rem_command=True, to_list=False)

        if (not cmd_output):
            return action_result.set_status(phantom.APP_ERROR, CISCOCATALYST_ERR_PORT_NOT_FOUND, port=port)

        cmd_output = cmd_output.strip()

        if (not cmd_output):
            return action_result.set_status(phantom.APP_ERROR, CISCOCATALYST_ERR_PORT_NOT_FOUND, port=port)

        # Output is of the following format
        # Port      Name               Status       Vlan       Duplex  Speed Type
        # Gi0/24                       connected    170        a-full a-1000 10/100/1000BaseTX
        parts = cmd_output.split()
        port_vlan = parts[-4]

        if (port_vlan == 'trunk'):
            modify = bool(param[CISCOCATALYST_JSON_OVERRIDE_TRUNK])
            if (not modify):
                return action_result.set_status(phantom.APP_SUCCESS, CISCOCATALYST_MSG_PORT_TRUNK, port=port)

        # First we will require to go into the configure terminal
        cmd_to_run = "configure terminal"
        status_code, cmd_output = self._send_command(cmd_to_run, action_result)
        if (phantom.is_fail(status_code)):
            return (action_result.set_status(phantom.APP_ERROR, CISCOCATALYST_ERR_CMD_EXEC), cmd_output)

        self.save_progress(CISCOIOS_PROG_EXECUTED_CMD, cmd_to_run)

        cmd_to_run = "interface {port}".format(port=port)
        status_code, cmd_output = self._send_command(cmd_to_run, action_result)
        if (phantom.is_fail(status_code)):
            return (action_result.set_status(phantom.APP_ERROR, CISCOCATALYST_ERR_CMD_EXEC), cmd_output)

        self.save_progress(CISCOIOS_PROG_EXECUTED_CMD, cmd_to_run)

        cmd_to_run = "switchport access vlan {vlan_id}".format(vlan_id=vlan_id)
        status_code, cmd_output = self._send_command(cmd_to_run, action_result)
        if (phantom.is_fail(status_code)):
            return (action_result.set_status(phantom.APP_ERROR, CISCOCATALYST_ERR_CMD_EXEC), cmd_output)

        if phantom.is_fail(self._get_cmd_output_status(cmd_output)):
            action_result.set_status(phantom.APP_ERROR)
            if (cmd_output):
                action_result.append_to_message(CISCOCATALYST_MSG_FROM_DEVICE)
                action_result.append_to_message(self._reformat_cmd_output(cmd_output, rem_command=False,
                            to_list=False))
            return action_result.get_status()

        self.save_progress(CISCOIOS_PROG_EXECUTED_CMD, cmd_to_run)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _set_vlan_id(self, param, delete=False):

        if (phantom.is_fail(self._connect())):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = param[CISCOCATALYST_JSON_IP_MAC]
        ping_ip = param.get(CISCOCATALYST_JSON_PING_IP, True)
        mac = endpoint
        if (phantom.is_ip(endpoint)):
            (ret_val, mac) = self._get_mac_of_ip(endpoint, ping_ip, action_result)
            if (mac is None):
                return action_result.get_status()

        action_result.update_summary({CISCOCATALYST_JSON_MAC_ADDRESS: mac})

        return self._set_vlan_of_mac(mac, param, action_result)

    def handle_action(self, param):
        """Function that handles all the actions

            Args:

            Return:
                A status code
        """

        action = self.get_action_identifier()

        # Now each individual actions
        if (action == self.ACTION_ID_GET_CONFIG):
            self._get_config()
        elif (action == self.ACTION_ID_GET_VERSION):
            self._get_version()
        elif (action == self.ACTION_ID_SET_VLAN_ID):
            self._set_vlan_id(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            self._test_asset_connectivity(param)

        return self.get_status()

if __name__ == '__main__':

    import sys
    import simplejson as json
    import pudb

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        connector = CiscocatalystConnector()
        connector.print_progress_message = True
        connector._handle_action(json.dumps(in_json), None)

    # exit(0)
