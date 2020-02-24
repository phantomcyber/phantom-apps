# File: parse_callbacks.py
# Copyright (c) 2018-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# A list of methods to parse output
# The first few are generic methods, mainly for actions that don't have any output that needs to be parsed
#  in any specific manner

import phantom.app as phantom
from phantom.vault import Vault
import xmltodict
import tempfile
import base64
from collections import OrderedDict

from builtins import str
import six

def basic(action_result, response):
    # Default one, just add the data to the action result
    data = {}
    data['status_code'] = response.status_code
    data['std_out'] = response.std_out
    data['std_err'] = response.std_err

    action_result.add_data(data)
    return phantom.APP_SUCCESS


def check_exit(action_result, response):
    if response.std_err:
        return action_result.set_status(
            phantom.APP_ERROR, "Error running command: {}".format(response.std_err)
        )
    data = {}
    data['status_code'] = response.status_code
    data['std_out'] = response.std_out
    data['std_err'] = response.std_err

    action_result.add_data(data)


def check_exit_no_data(action_result, response):
    if response.status_code:
        if isinstance(response.std_err, bytes):
            try:
                response.std_err = response.std_err.decode('UTF-8')
            except:
                pass
        return action_result.set_status(
            phantom.APP_ERROR, "Error running command: {}".format(response.std_err)
        )
    return phantom.APP_SUCCESS


def check_exit_no_data2(action_result, response):
    if response.std_err:
        return action_result.set_status(
            phantom.APP_ERROR, "Error running command: {}".format(response.std_err)
        )
    return phantom.APP_SUCCESS


def check_exit_no_data_stdout(action_result, response):
    # Same as above, but for when the error message appears in std_out instead of std_err
    if response.status_code:
        return action_result.set_status(
            phantom.APP_ERROR, "Error running command: {}".format(response.std_out)
        )
    return phantom.APP_SUCCESS


def ensure_no_errors(action_result, response):
    if response.status_code or response.std_err:
        return action_result.set_status(
            phantom.APP_ERROR, "Error running command: {}{}".format(
                response.std_out,
                response.std_err
            )
        )
    return phantom.APP_SUCCESS


def list_processes(action_result, response):
    if response.status_code != 0:
        return action_result.set_status(
            phantom.APP_ERROR,
            "Error: Returned non-zero status code. stderr: {}".format(response.std_err)
        )

    output = response.std_out
    lines = output.splitlines()
    for line in lines[2:]:
        process = {}
        columns = line.split()
        try:
            process['handles'] = int(columns[0])
            process['non_paged_memory_(K)'] = int(columns[1])
            process['paged_memory_(K)'] = int(columns[2])
            process['working_set_(K)'] = int(columns[3])
            process['virtual_memory_(M)'] = int(columns[4])
            process['processor_time_(s)'] = float(columns[5])
            process['pid'] = int(columns[6])
            process['name'] = columns[7]
        except:
            continue
        action_result.add_data(process)

    size = action_result.get_data_size()
    if size == 0:
        return action_result.set_status(phantom.APP_ERROR, "Unable to parse process list")

    summary = action_result.update_summary({})
    summary['num_processes'] = size

    return phantom.APP_SUCCESS


def terminate_process(action_result, response):
    if response.std_err:
        return action_result.set_status(
            phantom.APP_ERROR, "Error terminating process: {}".format(response.std_err)
        )
    return phantom.APP_SUCCESS


def list_connections(action_result, response):
    if response.status_code != 0:
        return action_result.set_status(
            phantom.APP_ERROR,
            "Error: Returned non-zero status code. stderr: {}".format(response.std_err)
        )

    lines = response.std_out.splitlines()
    for line in lines[4:]:
        connection = {}
        columns = line.split()
        try:
            connection['protocol'] = columns[0]

            try:
                local_address = columns[1].rsplit(':', 1)
            except TypeError:  # py3
                local_address = (columns[1].decode('UTF-8')).rsplit(':', 1)

            connection['local_address_ip'] = local_address[0]
            connection['local_address_port'] = local_address[1]

            try:
                foreign_address = columns[2].rsplit(':', 1)
            except TypeError:  # py3
                foreign_address = (columns[2].decode('UTF-8')).rsplit(':', 1)

            connection['foreign_address_ip'] = foreign_address[0]
            connection['foreign_address_port'] = foreign_address[1]
            connection['state'] = columns[3]
            connection['pid'] = columns[4]
        except:
            continue
        action_result.add_data(connection)

    size = action_result.get_data_size()
    if size == 0:
        return action_result.set_status(phantom.APP_ERROR, "Unable to parse connection list")

    summary = action_result.update_summary({})
    summary['num_connections'] = size

    return phantom.APP_SUCCESS


def parse_rule(action_result, rule_lines):
    name_map = {
        'localip': 'local_ip',
        'remoteip': 'remote_ip',
        'localport': 'local_port',
        'remoteport': 'remote_port'

    }
    rule = {}
    for line in rule_lines:
        columns = line.split(':', 1)
        if columns[0].startswith('--'):
            continue
        key_name = columns[0].lower().replace(' ', '_')
        key_name = name_map.get(key_name, key_name)
        try:
            rule[key_name] = columns[1].lower().strip()
        except IndexError:
            pass

    return rule


def filtered_rule(
        action_result, rule,
        filter_port=None,
        filter_ip=None,
        **kwargs):

    if filter_port:
        if rule.get('remote_port') == filter_port:
            pass
        elif rule.get('local_port') == filter_port:
            pass
        else:
            return False

    if filter_ip:
        if rule.get('remote_ip') == filter_ip:
            pass
        elif rule.get('local_ip') == filter_ip:
            pass
        else:
            return False

    for k, v in six.iteritems(kwargs):
        if rule.get(k, '').lower() != v.lower():
            return False

    return True


# Unfortunately, the actual command for running this doesn't allow you to filter
#  (or at least, not with every field), so we need to do most of it here
def list_firewall_rules(action_result, response, **kwargs):
    if response.status_code != 0:
        # The only reason this should fail is if there are no firewall rules
        action_result.update_summary({'num_rules': 0})
        return action_result.set_status(
            phantom.APP_SUCCESS,
            "No firewall rules were found"
        )
    lines = list()

    if isinstance(response.std_out, str):
        lines = response.std_out.splitlines()
    else:
        lines = response.std_out.decode('UTF-8').splitlines()

    rule_lines = None
    for line in lines:
        # start of a new rule
        if line.startswith('Rule Name:'):
            rule_lines = []
            rule_lines.append(line)
        elif not rule_lines:
            continue
        elif line.strip() == '' and rule_lines:
            rule = parse_rule(action_result, rule_lines)
            if filtered_rule(action_result, rule, **kwargs):
                action_result.add_data(rule)
            rule_lines = []
        else:
            rule_lines.append(line)

    size = action_result.get_data_size()
    summary = action_result.update_summary({})
    summary['num_rules'] = size

    return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved firewall rules")


def create_firewall_rule(action_result, response):
    if response.status_code:
        try:
            msg = response.std_out.splitlines()[1]
        except:
            msg = response.std_out
        return action_result.set_status(
            phantom.APP_ERROR, "Error running command: {}".format(msg)
        )
    return phantom.APP_SUCCESS


def delete_firewall_rule(action_result, response):
    if response.status_code:
        return action_result.set_status(
            phantom.APP_ERROR, "Error running command: {}".format(response.std_out)
        )

    # action_result.add_data({'message': response.std_out})
    summary = action_result.update_summary({})
    try:
        summary['rules_deleted'] = int(response.std_out.split()[1])
    except:
        pass
    return phantom.APP_SUCCESS


def list_sessions(action_result, response):
    if isinstance(response.std_out, bytes):
        lines = (response.std_out.decode('UTF-8')).splitlines()
    else:
        lines = response.std_out.splitlines()

    username_index = lines[0].find('USERNAME')
    type_index = lines[0].find('TYPE')
    device_index = lines[0].find('DEVICE')

    for line in lines[1:]:
        i = 0
        session = {}
        columns = line.split()
        if line.startswith('>'):
            session['name'] = columns[i][1:]
            session['this'] = True
        else:
            session['name'] = columns[i]
            session['this'] = False
        if not line[username_index].isspace():
            i += 1
            username = columns[i]
        else:
            username = ""

        i += 1
        session['username'] = username
        session['id'] = columns[i]

        if not line[type_index].isspace():
            i += 1
            type_ = columns[i]
        else:
            type_ = ""

        i += 1
        session['type'] = type_

        if not line[device_index].isspace():
            i += 1
            device = columns[i]
        else:
            device = ""

        i += 1
        session['type'] = device
        action_result.add_data(session)

    size = action_result.get_data_size()
    summary = action_result.update_summary({})
    summary['num_sessions'] = size

    return phantom.APP_SUCCESS


def _parse_rule(rule):
    d = {}
    d['description'] = rule.pop('@Description', '')
    d['name'] = rule.pop('@Name', '')
    d['user_or_group_sid'] = rule.pop('@UserOrGroupSid', None)
    d['action'] = rule.pop('@Action', None)
    d['id'] = rule.pop('@Id', None)
    file_path_condition = rule.get('Conditions', {}).get('FilePathCondition', {}).get('@Path')
    if file_path_condition:
        d['file_path_condition'] = file_path_condition
        rule.get('Conditions', {}).pop('FilePathCondition', None)
        if len(rule.get('Conditions', {})) == 0:
            rule.pop('Conditions', None)
    for k, v in six.iteritems(rule):
        # Add anything left over
        d[k] = v
    return d


def list_applocker_policies(action_result, response):
    if response.status_code:
        return action_result.set_status(
            phantom.APP_ERROR, "Error running command: {}".format(response.std_err)
        )
    try:
        # Get rid of all the linebreaks to prevent errors during reading
        data = xmltodict.parse("".join(response.std_out.splitlines()))
    except TypeError:
        data = xmltodict.parse("".join((response.std_out.decode('utf-8')).splitlines()))
    except Exception as e:
        return action_result.set_status(
            phantom.APP_ERROR, "Error parsing XML response: {}".format(str(e))
        )

    try:
        rule_collection = data['AppLockerPolicy']['RuleCollection']
    except KeyError:
        return action_result.set_status(phantom.APP_SUCCESS, "No AppLocker Policies were found")

    if type(rule_collection) in (dict, OrderedDict):
        rule_collection = [rule_collection]

    for rule in rule_collection:
        r_type = rule['@Type']
        enforcement_mode = rule['@EnforcementMode']
        for rule_condition in ['FilePublisherRule', 'FilePathRule', 'FileHashRule']:
            condition = rule.get(rule_condition)
            if condition is None:
                continue
            if type(condition) in (dict, OrderedDict):
                d = _parse_rule(condition)
                d['type'] = r_type
                d['enforcement_mode'] = enforcement_mode
                action_result.add_data(d)
            elif type(condition) is list:
                for c in condition:
                    d = _parse_rule(c)
                    d['type'] = r_type
                    d['enforcement_mode'] = enforcement_mode
                    action_result.add_data(d)

    return phantom.APP_SUCCESS


def decodeb64_add_to_vault(action_result, response, container_id, file_name):
    if response.status_code:
        if isinstance(response.std_err, bytes):
            response.std_err = response.std_err.decode('UTF-8')
        return action_result.set_status(
            phantom.APP_ERROR, "Error running command: {}".format(response.std_err)
        )

    b64string = response.std_out

    try:
        if hasattr(Vault, 'create_attachment'):
            resp = Vault.create_attachment(base64.b64decode(b64string), container_id, file_name=file_name)
        else:
            tmp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, dir='/opt/phantom/vault/tmp')
            tmp_file.write(base64.b64decode(b64string))
            tmp_file.close()
            resp = Vault.add_attachment(tmp_file.name, container_id, file_name=file_name)
    except Exception as e:
        return action_result.set_status(
            phantom.APP_ERROR, "Error adding file to vault", e
        )

    action_result.update_summary({
        'vault_id': resp['vault_id']
    })

    return phantom.APP_SUCCESS
