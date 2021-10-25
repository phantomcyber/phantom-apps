# File: ciscocatalyst_consts.py
#
# Copyright (c) 2014-2019 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)# --
CISCOCATALYST_JSON_IP_MAC = "ip_macaddress"
CISCOCATALYST_JSON_VLAN_ID = "vlan_id"
CISCOCATALYST_JSON_OVERRIDE_TRUNK = "override_trunk"
CISCOCATALYST_JSON_PING_IP = "ping_ip"
CISCOCATALYST_JSON_MAC_ADDRESS = "mac_address"

CISCOCATALYST_ERR_IP_MAC_NOT_FOUND = "Unable to get the mac of the ip. Please specify the mac address"
CISCOCATALYST_ERR_MAC_NOT_FOUND = "MAC address not found on device"
CISCOCATALYST_MSG_SEARCHING_MAC = "Searching for mac on device"
CISCOCATALYST_MSG_VLAN_SAME = "VLAN id same as required"
CISCOCATALYST_ERR_PORT_NOT_FOUND = "Port information for '{port}' could not be found on the device"
CISCOCATALYST_MSG_PORT_TRUNK = "Vlan of trunk port {port} not modified, re-run action with Set vlan of trunk port"
CISCOCATALYST_ERR_CMD_EXEC = "Command execution failed"
CISCOCATALYST_MSG_GETTING_MAC_OF_IP = "Getting mac address of specified ip"
CISCOCATALYST_MSG_PINGING_IP_TO_REFRESH_MAC = "Pinging {ip} from device to get mac address"
CISCOCATALYST_MSG_FROM_DEVICE = "Message from device:\n"
