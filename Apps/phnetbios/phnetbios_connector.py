# --
# File: phnetbios_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from nmb.NetBIOS import NetBIOS


class NetBIOSConnector(BaseConnector):

    def _test_connectivity(self, param):

        config = self.get_config()

        ip = config['ip']
        port = int(param.get('port', 137))
        timeout = int(param.get('timeout', 30))

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        self.save_progress("Looking up IP : {0} to test connectivity".format(ip))
        nb = NetBIOS()
        hosts = nb.queryIPForName(ip, port, timeout)
        if hosts is None:
            self.save_progress("Request timed out")
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR)

        if hosts:
            self.save_progress("Got {0} hosts".format(len(hosts)))
            self.save_progress("Test Connectivity Passed")
            return action_result.set_status(phantom.APP_SUCCESS)

        self.save_progress("Lookup did not return any results, but connectivity passed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_ip(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        ip = param.get('ip')
        port = int(param.get('port', 137))
        timeout = int(param.get('timeout', 30))

        if not ip:
            return action_result.set_status(phantom.APP_ERROR, "IP must be provided.")

        nb = NetBIOS()
        hosts = nb.queryIPForName(ip, port, timeout)
        if hosts is None:
            return action_result.set_status(phantom.APP_ERROR, "Request timed out.")

        if hosts:
            action_result.set_summary({"hosts": len(hosts)})
            action_result.add_data({"hostnames": hosts})
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Lookup failed.")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "lookup_ip":
            ret_val = self._lookup_ip(param)
        elif (action_id == 'test_connectivity'):
            ret_val = self._test_connectivity(param)

        return ret_val
