# File: winrm_connector.py
# Copyright (c) 2018-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Local imports
import parse_callbacks as pc
import winrm_consts as consts

import re
import imp
import csv
import copy
import json
import winrm
import ntpath
import base64
import textwrap
import ipaddress
from base64 import b64encode
import requests

from builtins import str
import six

class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class WindowsRemoteManagementConnector(BaseConnector):

    def __init__(self):
        # Call the BaseConnectors init first
        super(WindowsRemoteManagementConnector, self).__init__()
        self._state = None

    def is_ip(self, param):
        if param in {'any', 'localsubnet', 'dns', 'dhcp', 'wins', 'defaultgateway'}:
            return True
        try:
            # ipaddress.ip_network(param.decode('utf-8'))
            ipaddress.ip_network(str(param))
        except:
            return False
        return True

    def _get_vault_file_text(self, action_result, vault_id):
        # type: (ActionResult, str) -> str
        # Get the contents of a file in the vault
        file_path = Vault.get_file_path(vault_id)
        if not file_path:
            return action_result.set_status(phantom.APP_ERROR, "Cannot retrieve vault file"), None

        try:
            return (phantom.APP_SUCCESS, open(file_path, 'r').read())
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error reading vault file: {}".format(str(e))), None

    def _get_custom_parser_method(self, action_result, vault_id):
        if vault_id is None:
            return phantom.APP_SUCCESS, pc.basic

        file_path = Vault.get_file_path(vault_id)
        if not file_path:
            return action_result.set_status(phantom.APP_ERROR, "Could not retrieve vault file"), None

        try:
            custom_parser = imp.load_source('custom_parser', file_path)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error creating custom parser: {}".format(str(e))), None

        try:
            return phantom.APP_SUCCESS, custom_parser.custom_parser  # noqa
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error saving custom parser: {}".format(str(e))), None

    def _sanitize_string(self, string):
        # To avoid any shenanigans, we need to quote the arguments
        # The breaking character in PS is '`', so first we break any breaking characters, then we
        # break any double quotes which are found, then we break any $, which is used to declare variables
        return string.replace('`', '``').replace('"', '`"').replace('$', '`$').replace('&', '`&').replace(')', '`)').replace('(', '`(')

    def _create_ps_script(self, action_result, args, whitelist_args=set(), cmd_prefix="", cmd_suffix=""):
        # Here, you can pass it something like {"val1": "value"} which will generate a string for "-val1 value"
        # "For your convenience" you can also pass it a list of strings and dicts, something like [val1, {"val2": "asdf"}, foo],
        #   which will generate a string like "-val1 -val2 asdf -foo".
        # Perhaps the name is a bit misleading, but this really only for creating one line of a script
        if type(args) == dict:
            args = [args]
        if type(args) != list:
            raise TypeError("Args Must be of type list or dict")
        arg_str = ""
        for arg in args:
            if type(arg) is dict:
                for k, v in six.iteritems(arg):
                    if (whitelist_args and k not in whitelist_args) or not k.isalpha():
                        return RetVal(action_result.set_status(
                            phantom.APP_ERROR, "Invalid argument: {}".format(k)
                        ), None)
                    if v is None:
                        continue
                    if type(v) is bool:
                        arg_str += "-{0} ${1} ".format(k, str(v))
                    else:
                        arg_str += "-{0} \"{1}\" ".format(k, self._sanitize_string(str(v)))
            if type(arg) is str:
                if (whitelist_args and arg not in whitelist_args) or not arg.isalpha():
                    return RetVal(action_result.set_status(
                        phantom.APP_ERROR, "Invalid argument: {}".format(k)
                    ), None)
                arg_str += "-{0} ".format(arg)
        return RetVal(phantom.APP_SUCCESS, "{0} {1} {2}".format(cmd_prefix, arg_str, cmd_suffix))

    def _init_session(self, action_result, param=None):
        config = self.get_config()
        default_port = config.get('default_port', 5985)
        default_protocol = config.get('default_protocol', 'http')
        if param:
            endpoint = param['ip_hostname']
        else:
            endpoint = config.get('endpoint')
            if endpoint is None:
                return action_result.set_status(
                    phantom.APP_ERROR, "No Endpoint Configured"
                )
        if re.search(r'^[a-z]+://', endpoint, re.UNICODE | re.IGNORECASE) is None:
            endpoint = '{0}://{1}'.format(default_protocol, endpoint)
        if re.search(r':\d+$', endpoint, re.UNICODE | re.IGNORECASE) is None:
            endpoint = '{0}:{1}'.format(endpoint, default_port)
        username = config['username']
        password = config['password']
        transport = config.get('transport')
        domain = config.get('domain')

        verify_bool = config.get(phantom.APP_JSON_VERIFY, False)
        if verify_bool:
            verify = 'validate'
        else:
            verify = 'ignore'

        if transport == 'basic' or transport == 'plaintext':
            if domain:
                self.save_progress(
                    "Warning: Domain is set but transport type is set to 'basic'"
                )
        elif transport == 'ntlm':
            if domain:
                username = r'{}\{}'.format(domain, username)
        elif transport == 'kerberos':
            return action_result.set_status(
                phantom.APP_ERROR, "This transport type is not yet implemented"
            )
        elif transport == 'credssp':
            return action_result.set_status(
                phantom.APP_ERROR, "This transport type is not yet implemented"
            )
        else:
            return action_result.set_status(
                phantom.APP_ERROR, "Invalid transport type: {}".format(transport)
            )

        self._session = winrm.Session(
            endpoint,
            auth=(username, password),
            server_cert_validation=verify,
            transport=transport
        )
        self._protocol = self._session.protocol

        return phantom.APP_SUCCESS

    def _run_cmd(self, action_result, cmd, args=None, parse_callback=pc.basic, additional_data=None, async_=False, command_id=None, shell_id=None):
        # The parser callback should have the function signature (ActionResult, winrm.Result) -> bool
        # The additional_data is a dictionary which will be passed to the parser, in which case the signature should be
        #  (ActionResult, winrm.Result, **kwargs) -> bool
        # async_ will start the command and return what you need to get the results later (command_id and shell_id)
        # you /could/ pass a command_id and shell_id from an async powershell script run here (and vice versa),
        #  but there is some additional data
        #  cleanup which goes on after running a powershell script which wont happen here, so its best not to
        if additional_data is None:
            additional_data = {}
        resp = None
        try:
            if command_id:
                if shell_id is None:
                    return action_result.set_status(phantom.APP_ERROR, "Must specify shell_id with command_id")
                resp = winrm.Response(self._protocol.get_command_output(shell_id, command_id))
                self._protocol.close_shell(shell_id)
            elif async_:
                shell_id = self._protocol.open_shell()
                command_id = self._protocol.run_command(shell_id, cmd, args)
                summary = action_result.set_summary({})
                summary['shell_id'] = shell_id
                summary['command_id'] = command_id
                return phantom.APP_SUCCESS
            else:
                resp = self._session.run_cmd(cmd, args)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error running command: {}".format(str(e)))
        if resp is None:
            # The exception will probably catch this
            self.debug_print("Error: _run_cmd is missing parameters")
            return action_result.set_status(phantom.APP_ERROR, "Unknown error while running command")
        return parse_callback(action_result, resp, **additional_data)

    def _run_ps(self, action_result, script, parse_callback=pc.basic, additional_data=None, async_=False, command_id=None, shell_id=None):
        if additional_data is None:
            additional_data = {}
        resp = None
        try:
            if command_id:
                if shell_id is None:
                    return action_result.set_status(phantom.APP_ERROR, "Must specify shell_id with command_id")
                resp = winrm.Response(self._protocol.get_command_output(shell_id, command_id))
                self._protocol.close_shell(shell_id)
                if len(resp.std_err):
                    resp.std_err = self._session._clean_error_msg(resp.std_err)
                    if isinstance(resp.std_err, bytes):
                        resp.std_err = resp.std_err.decode('UTF-8')
            elif async_:
                encoded_ps = b64encode(script.encode('utf_16_le')).decode('ascii')
                shell_id = self._protocol.open_shell()
                command_id = self._protocol.run_command(shell_id, 'powershell -encodedcommand {0}'.format(encoded_ps))
                summary = action_result.set_summary({})
                summary['shell_id'] = shell_id
                summary['command_id'] = command_id
                return phantom.APP_SUCCESS
            else:
                resp = self._session.run_ps(script)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error running PowerShell script: {}".format(str(e)))
        if resp is None:
            self.debug_print("Error: _run_ps is missing parameters")
            return action_result.set_status(phantom.APP_ERROR, "Unknown error while running PowerShell script")
        return parse_callback(action_result, resp, **additional_data)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result):
            self.save_progress("Test connectivity failed")
            return action_result.get_status()

        ret_val = self._run_cmd(action_result, 'ifconfig')
        if phantom.is_fail(ret_val):
            self.save_progress("Test connectivity failed")
            return self.set_status(phantom.APP_ERROR)
        return self.set_status_save_progress(phantom.APP_SUCCESS, "Test connectivity passed")

    def _handle_list_processes(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        ret_val = self._run_ps(action_result, 'get-process', pc.list_processes)
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully got process list")

    def _handle_terminate_process(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        pid = param.get('pid')
        name = param.get('name')
        if pid is None and name is None:
            return action_result.set_status(
                phantom.APP_ERROR, "Must specify at least one of pid or name"
            )

        args = {
            "id": pid,
            "processname": name
        }
        ret_val, script = self._create_ps_script(
            action_result, args, cmd_prefix="Stop-Process", cmd_suffix="-Force"
        )
        if phantom.is_fail(ret_val):
            return ret_val

        self.debug_print(script)

        ret_val = self._run_ps(action_result, script, parse_callback=pc.check_exit_no_data)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully terminated process")

    def _handle_list_connections(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        command = 'netstat'
        arguments = ['-no']  # yes

        ret_val = self._run_cmd(action_result, command, arguments, pc.list_connections)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully listed connections")

    def _create_filter(self, action_result, param):
        filter_data = {}
        filter_vars = [
            'filter_port',
            'filter_ip',
            'direction',
            'protocol'
        ]
        for var in filter_vars:
            if var in param:
                filter_data.update({var: param[var]})

        other = param.get('other')
        if other:
            try:
                other_dict = json.loads(other)
            except Exception as e:
                return action_result.set_status(
                    phantom.APP_ERROR, "Error parsing JSON Object: {}".format(str(e))
                ), None
            filter_data.update(other_dict)

        return phantom.APP_SUCCESS, filter_data

    def _handle_list_firewall_rules(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        command = 'netsh'
        ret_val, filter_data = self._create_filter(action_result, param)
        if phantom.is_fail(ret_val):
            return ret_val

        # There isn't a way to filter using the command, so we need to handle that in the parser
        arguments = ['advfirewall', 'firewall', 'show', 'rule', 'name=all']
        ret_val = self._run_cmd(action_result, command, arguments, pc.list_firewall_rules, filter_data)

        return ret_val

    def _handle_delete_firewall_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        ps_script_base = '& "netsh.exe" "advfirewall" "firewall" "delete" "rule" '
        argument_str = ''
        other = param.get('other')
        if other:
            try:
                other_dict = json.loads(other)
            except Exception as e:
                return action_result.set_status(
                    phantom.APP_ERROR, "Error parsing JSON Object: {}".format(str(e))
                )
            param.update(other_dict)

        val_map = {
            "local_ip": "localip",
            "local_port": "localport",
            "remote_ip": "remoteip",
            "remote_port": "remoteport"
        }

        valid_params = {
            'name', 'dir', 'action',
            'remote_ip', 'local_ip', 'remote_port',
            'local_port', 'protocol', 'program',
            'profile', 'service',
            'localip', 'remoteip',
            'localport', 'remoteport'
        }
        for k, v in six.iteritems(param):
            if k in valid_params:
                argument = '"{}"'.format(self._sanitize_string('{}={}'.format(val_map.get(k, k), v)))
                argument_str += argument + ' '

        ret_val = self._run_ps(action_result, ps_script_base + argument_str, pc.delete_firewall_rule)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully deleted firewall rule{}".format(
                "s" if action_result.get_summary().get('rules_deleted', 0) > 1 else ""
            )
        )

    def _handle_block_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        ps_script = '& "netsh.exe" "advfirewall" "firewall" "add" "rule" '
        name = param['name']
        remote_ip = param['remote_ip']

        ps_script += '"{}" '.format(self._sanitize_string('{}={}'.format('name', name)))
        ps_script += '"{}" '.format(self._sanitize_string('{}={}'.format('remoteip', remote_ip)))
        ps_script += '"dir=in" "action=block"'

        ret_val = self._run_ps(action_result, ps_script, pc.check_exit_no_data_stdout)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created firewall rule")

    def _handle_create_firewall_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        ps_script_base = '& "netsh.exe" "advfirewall" "firewall" "add" "rule" '
        argument_str = ''
        other = param.get('other')
        if other:
            try:
                other_dict = json.loads(other)
            except Exception as e:
                return action_result.set_status(
                    phantom.APP_ERROR, "Error parsing JSON Object: {}".format(str(e))
                )
            param.update(other_dict)

        val_map = {
            "local_ip": "localip",
            "local_port": "localport",
            "remote_ip": "remoteip",
            "remote_port": "remoteport"
        }

        valid_params = {
            'name', 'dir', 'action',
            'remote_ip', 'local_ip', 'remote_port',
            'local_port', 'protocol', 'enable',
            'program', 'service', 'description',
            'interfacetype', 'rmtcomputergrp', 'rmtusrgrp',
            'edge', 'security',
            'localip', 'remoteip',
            'localport', 'remoteport'
        }
        for k, v in six.iteritems(param):
            if k in valid_params:
                argument = '"{}"'.format(self._sanitize_string('{}={}'.format(val_map.get(k, k), v)))
                argument_str += argument + ' '

        ret_val = self._run_ps(action_result, ps_script_base + argument_str, pc.check_exit_no_data_stdout)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created firewall rule")

    def _handle_list_sessions(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        command = "query session"

        ret_val = self._run_cmd(action_result, command, parse_callback=pc.list_sessions)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully listed all sessions")

    def _handle_logoff_user(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        session_id = param.get('session_id')
        if not session_id.isdigit():
            return action_result.set_status(phantom.APP_ERROR, "")

        command = "logoff {0}".format(session_id)

        ret_val = self._run_cmd(action_result, command, parse_callback=pc.check_exit_no_data)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully logged off user")

    def _get_system_volume(self, action_result):
        ps_script = '"list volume" | diskpart'
        ret_val = self._run_ps(action_result, ps_script)
        if phantom.is_fail(ret_val):
            return RetVal(ret_val)

        volume = -1
        std_out = action_result.get_data()[0]['std_out']
        if isinstance(std_out, bytes):  # py3
            std_out = std_out.decode('UTF-8')

        try:
            for line in std_out.splitlines():
                if line.strip().lower().endswith('system'):
                    volume = int(line.split()[1])
        except:
            return RetVal(action_result.set_status(
                phantom.APP_ERROR, "Error parsing diskpart output"
            ))

        if volume == -1:
            return RetVal(action_result.set_status(
                phantom.APP_ERROR, "Could not find the System partition"
            ))

        return phantom.APP_SUCCESS, volume

    def _update_system_volume(self, action_result, state):
        tmp_action_result = copy.copy(action_result)
        ret_val, volume = self._get_system_volume(tmp_action_result)
        if phantom.is_fail(ret_val):
            action_result = tmp_action_result  # noqa
            return ret_val

        ps_script = '"select volume {0}`r`n{1}" | diskpart'.format(volume, state)

        ret_val = self._run_ps(action_result, ps_script, parse_callback=pc.check_exit_no_data)
        if phantom.is_fail(ret_val):
            return ret_val

        return phantom.APP_SUCCESS

    def _handle_deactivate_partition(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        ret_val = self._update_system_volume(
            action_result,
            "inactive"
        )
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deactivated partition")

    def _handle_activate_partition(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        ret_val = self._update_system_volume(
            action_result,
            "active"
        )
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully activated partition")

    def _handle_shutdown_system(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        ps_script = '& shutdown.exe /s /t 5 '
        comment = param.get('comment')
        reason = param.get('reason')
        if comment:
            ps_script += '/c "{}"'.format(self._sanitize_string(comment))
        if reason:
            ps_script += '/d "{}"'.format(self._sanitize_string(reason))

        ret_val = self._run_ps(action_result, ps_script, pc.check_exit_no_data)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully initiated system shutdown")

    def _handle_restart_system(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        ps_script = '& shutdown.exe /r /t 5 '
        comment = param.get('comment')
        reason = param.get('reason')
        if comment:
            ps_script += '/c "{}"'.format(self._sanitize_string(comment))
        if reason:
            ps_script += '/d "{}"'.format(self._sanitize_string(reason))

        self.debug_print(ps_script)
        ret_val = self._run_ps(action_result, ps_script, pc.check_exit_no_data)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully initiated system restart")

    def _format_list_applocker_script(self, action_result, location, ldap, xml=True, module=True):
        suffix = "-XML" if xml else ""
        if location.lower() not in ('local', 'domain', 'effective'):
            return action_result.set_status(
                phantom.APP_ERROR, 'Error: "location" must be one of "local", "domain", or "effective"'
            ), None
        if location.lower() == "domain":
            if not ldap:
                return action_result.set_status(
                    phantom.APP_ERROR, 'Error: "ldap" must be included with "domain"'
                ), None
            else:
                args = {
                    "LDAP": ldap
                }
                if module:
                    prefix = consts.APPLOCKER_BASE_SCRIPT + 'Get-AppLockerPolicy -Domain'
                else:
                    prefix = 'Get-AppLockerPolicy -Domain'
                ret_val, ps_script = self._create_ps_script(
                    action_result, args, cmd_prefix=prefix, cmd_suffix=suffix
                )
                if phantom.is_fail(ret_val):
                    return ret_val, None
        else:
            if module:
                ps_script = consts.APPLOCKER_BASE_SCRIPT + 'Get-AppLockerPolicy -{0} {1}'.format(location, suffix)
            else:
                ps_script = 'Get-AppLockerPolicy -{0} {1}'.format(location, suffix)

        return phantom.APP_SUCCESS, ps_script

    def _handle_list_applocker_policies(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        location = param['location']
        ldap = param.get('ldap')
        ret_val, ps_script = self._format_list_applocker_script(action_result, location, ldap)
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val = self._run_ps(action_result, ps_script, pc.list_applocker_policies)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully listed AppLocker Policies")

    def _handle_create_applocker_policy(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        deny_allow = param['deny_allow'].lower()
        if deny_allow not in ('allow', 'deny'):
            return action_result.set_status(
                phantom.APP_ERROR, "Invalid value for allow_deny"
            )

        file_path = param['file_path']
        args_new_policy = {
            'User': param.get('user'),
            'RuleNamePrefix': param.get('rule_name_prefix')
        }
        args_set_policy = {
            'LDAP': param.get('ldap')
        }
        ret_val, new_policy_str = self._create_ps_script(action_result, args_new_policy)
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, set_policy_str = self._create_ps_script(action_result, args_set_policy)
        if phantom.is_fail(ret_val):
            return ret_val

        if deny_allow == "allow":
            ps_script = consts.APPLOCKER_BASE_SCRIPT + consts.APPLOCKER_CREATE_POLICY.format(
                self._sanitize_string(file_path), new_policy_str, set_policy_str
            )
        else:
            ps_script = consts.APPLOCKER_BASE_SCRIPT + consts.APPLOCKER_CREATE_POLICY_DENY.format(
                self._sanitize_string(file_path), new_policy_str, set_policy_str
            )

        ret_val = self._run_ps(action_result, ps_script, parse_callback=pc.check_exit_no_data)
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created AppLocker policy")

    def _handle_delete_applocker_policy(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        policy_id = param['applocker_policy_id']
        if not re.match(r'[\w\d-]*', policy_id):
            return action_result.set_status(
                phantom.APP_ERROR, "Invalid AppLocker Policy ID"
            )
        ldap = param.get('ldap')
        if ldap:
            location = 'domain'
        else:
            location = 'local'

        ret_val, set_policy_str = self._create_ps_script(action_result, {'LDAP': ldap})
        if phantom.is_fail(ret_val):
            return ret_val

        tmp_action_result = ActionResult(dict(param))
        ret_val, ps_script = self._format_list_applocker_script(tmp_action_result, location, ldap, module=False, xml=False)
        if phantom.is_fail(ret_val):
            action_result = tmp_action_result
            return ret_val

        ps_script = consts.APPLOCKER_BASE_SCRIPT + consts.APPLOCKER_DELETE_POLICY.format(
            self._sanitize_string(policy_id), ps_script, set_policy_str
        )

        ret_val = self._run_ps(action_result, ps_script, parse_callback=pc.check_exit_no_data2)
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted AppLocker Policy")

    def _handle_get_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        file_path = param['file_path']

        file_path = self._sanitize_string(file_path)

        script_str = consts.GET_FILE.format(file_path)

        additional_data = {
            'container_id': self.get_container_id(),
            'file_name': ntpath.split(file_path)[-1]
        }
        ret_val = self._run_ps(action_result, script_str, pc.decodeb64_add_to_vault, additional_data)
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved file and added it to the Vault")

    def _handle_send_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        vault_id = param['vault_id']
        destination = param['destination']

        path = Vault.get_file_path(vault_id)
        if not path:
            return action_result.set_status(phantom.APP_ERROR, "Could not retrieve vault file")

        try:
            fp = open(path, 'rb')
            encoded_file = base64.b64encode(fp.read())
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to base64 encode file", e)

        destination = self._sanitize_string(destination)

        # Windows servers have a limit of 2074 characters per command, so we break it up into chunks
        sent_first = False  # Sent the first chunk
        try:
            chunks = textwrap.wrap(encoded_file, 1650)
        except TypeError:
            chunks = textwrap.wrap(encoded_file.decode('UTF-8'), 1650)
        num_chunks = len(chunks)
        for i, chunk in enumerate(chunks):
            ps_script = consts.SEND_FILE_START.format(
                b64string_chunk=chunk,
                file_path=destination,
                action=">>" if sent_first else ">"
            )
            # The final chunk
            if i == num_chunks - 1:
                ps_script += consts.SEND_FILE_END

            self.save_progress("Sending chunk {} of {}".format(i + 1, num_chunks))
            ret_val = self._run_ps(action_result, ps_script, parse_callback=pc.ensure_no_errors)
            if phantom.is_fail(ret_val):
                return action_result.append_to_message("Error sending file")

            sent_first = True

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully sent file")

    def _handle_copy_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        path_from = param['from']
        path_to = param['to']

        ps_script = "& copy {0} {1}".format(
            self._sanitize_string(path_from),
            self._sanitize_string(path_to)
        )

        ret_val = self._run_ps(action_result, ps_script, parse_callback=pc.check_exit_no_data)
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully copied files")

    def _handle_delete_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        file_path = param['file_path']
        force_delete = '-Force ' if param.get('force') else ''

        ps_script = "& del {0}{1}".format(
            force_delete,
            self._sanitize_string(file_path)
        )

        ret_val = self._run_ps(action_result, ps_script, parse_callback=pc.check_exit_no_data)
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted files")

    def _handle_run_command(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        # Validate Parameters
        command_id = param.get('command_id')
        shell_id = param.get('shell_id')
        if command_id and not shell_id or shell_id and not command_id:
            return action_result.set_status(
                phantom.APP_ERROR, "Both command_id and shell_id must be specified together"
            )
        command = param.get('command')
        arguments = param.get('arguments')
        if command is None and command_id is None:
            return action_result.set_status(
                phantom.APP_ERROR, "Either command or command_id + shell_id must be specified"
            )
        async_ = param.get('async', False)

        if not async_:
            ret_val, custom_parser = self._get_custom_parser_method(action_result, param.get('parser'))
            if phantom.is_fail(ret_val):
                return ret_val
        else:
            # Nothing will need to be parsed here
            custom_parser = None

        if arguments:
            arguments = next(csv.reader([arguments], skipinitialspace=True))

        ret_val = self._run_cmd(action_result, command, arguments, custom_parser, async_=async_, command_id=command_id, shell_id=shell_id)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully ran command")

    def _handle_run_script(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        if not self._init_session(action_result, param):
            return action_result.get_status()

        # Validate Parameters
        command_id = param.get('command_id')
        shell_id = param.get('shell_id')
        if command_id and not shell_id or shell_id and not command_id:
            return action_result.set_status(
                phantom.APP_ERROR, "Both command_id and shell_id must be specified together"
            )
        script_file = param.get('script_file')
        script_str = param.get('script_str')
        if script_file is None and script_str is None and command_id is None:
            return action_result.set_status(
                phantom.APP_ERROR, "Must specify either a script_file, script_str, or command_id + shell_id"
            )
        async_ = param.get('async', False)

        if not async_:
            ret_val, custom_parser = self._get_custom_parser_method(action_result, param.get('parser'))
            if phantom.is_fail(ret_val):
                return ret_val
        else:
            custom_parser = None

        if script_file and command_id is None:  # don't check script if retrieving previous command
            ret_val, script_str = self._get_vault_file_text(action_result, script_file)
            if phantom.is_fail(ret_val):
                return ret_val

        ret_val = self._run_ps(action_result, script_str, custom_parser, async_=async_, command_id=command_id, shell_id=shell_id)
        if phantom.is_fail(ret_val):
            return ret_val
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully ran PowerShell script")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'run_command':
            ret_val = self._handle_run_command(param)

        elif action_id == "run_script":
            ret_val = self._handle_run_script(param)

        elif action_id == "list_processes":
            ret_val = self._handle_list_processes(param)

        elif action_id == "terminate_process":
            ret_val = self._handle_terminate_process(param)

        elif action_id == "list_connections":
            ret_val = self._handle_list_connections(param)

        elif action_id == "list_firewall_rules":
            ret_val = self._handle_list_firewall_rules(param)

        elif action_id == "block_ip":
            ret_val = self._handle_block_ip(param)

        elif action_id == "create_firewall_rule":
            ret_val = self._handle_create_firewall_rule(param)

        elif action_id == "delete_firewall_rule":
            ret_val = self._handle_delete_firewall_rule(param)

        elif action_id == "list_sessions":
            ret_val = self._handle_list_sessions(param)

        elif action_id == "logoff_user":
            ret_val = self._handle_logoff_user(param)

        elif action_id == "deactivate_partition":
            ret_val = self._handle_deactivate_partition(param)

        elif action_id == "activate_partition":
            ret_val = self._handle_activate_partition(param)

        elif action_id == "shutdown_system":
            ret_val = self._handle_shutdown_system(param)

        elif action_id == "restart_system":
            ret_val = self._handle_restart_system(param)

        elif action_id == "list_applocker_policies":
            ret_val = self._handle_list_applocker_policies(param)

        elif action_id == "create_applocker_policy":
            ret_val = self._handle_create_applocker_policy(param)

        elif action_id == "delete_applocker_policy":
            ret_val = self._handle_delete_applocker_policy(param)

        elif action_id == "copy_file":
            ret_val = self._handle_copy_file(param)

        elif action_id == "send_file":
            ret_val = self._handle_send_file(param)

        elif action_id == "get_file":
            ret_val = self._handle_get_file(param)

        elif action_id == "delete_file":
            ret_val = self._handle_delete_file(param)

        return ret_val

    def initialize(self):
        self._state = self.load_state()
        self.set_validator("ip", self.is_ip)
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


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
            print("Accessing the Login page")
            login_url = BaseConnector._get_phantom_base_url() + 'login'
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
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = WindowsRemoteManagementConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
