# File: taniumthreatresponse_view.py
# Copyright (c) 2020-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)def get_events(headers, data):


def get_events(headers, data):
    """ Build a list of dictionaries that have the detail and what that detail "contains".

    Args:
        headers (list): Headers for these type of events (Provides the order and expected output)
        data (dict): Event data to lookup

    Returns:
        list: list of dictionary objects that maps the data to what is contained.
    """

    # Map header names to what is contained in each.
    contains_map = {
        'source_addr': ['ip'],
        'destination_ip': ['ip'],
        'username': ['user name'],
        'process_table_id': ['threatresponse process table id'],
        'process_name': ['file path', 'file name'],
        'process_id': ['pid'],
        'process_command_line': ['file name'],
        'file': ['file path'],
        'domain': ['domain'],
        'ImageLoaded': ['file path', 'file name'],
        'Hashes': ['md5']
    }

    events = []
    for event in data:
        event_details = []
        for head in headers:
            data = event.get(head, None)
            event_details.append({
                'data': data,
                'contains': contains_map.get(head, None) if data else None
            })
        events.append(event_details)

    return events


def display_events(provides, all_app_runs, context):

    # Use this mapping to control what data gets shown in which order for each event type
    headers_map = {
        'combined': [
            'type',
            'id',
            'timestamp',
            'operation',
            'process_name',
            'detail'
        ],  # 'timestamp_raw'
        'dns': [
            'id',
            'timestamp',
            'operation',
            'query',
            'response',
            'process_name',
            'process_table_id',
            'process_id',
            'domain',
            'username'
        ],  # 'timestamp_raw'
        'driver': [
            'id',
            'timestamp',
            'ImageLoaded',
            'Hashes',
            'event_opcode',
            'process_table_id',
            'Signed',
            'Signature',
            'sid',
            'event_task_id',
            'event_record_id'
        ],  # 'event_id','timestamp_raw'
        'file': [
            'id',
            'timestamp',
            'operation',
            'file',
            'process_name',
            'process_table_id',
            'process_id',
            'domain',
            'username'
        ],  # 'timestamp_raw'
        'network': [
            'id',
            'timestamp',
            'operation',
            'source_addr',
            'source_port',
            'destination_addr',
            'destination_port',
            'process_name',
            'process_table_id',
            'process_id',
            'domain',
            'username'
        ],  # 'timestamp_raw'
        'process': [
            'create_time',
            'end_time',
            'exit_code',
            'process_name',
            'process_table_id',
            'process_id',
            'process_command_line',
            'domain',
            'username',
            'sid'
        ],  # 'create_time_raw', 'end_time_raw'
        'registry': [
            'id',
            'timestamp',
            'operation',
            'key_path',
            'value_name',
            'process_name',
            'process_table_id',
            'process_id',
            'domain',
            'username'
        ],  # 'timestamp_raw'
        'sid': [
            'domain',
            'username',
            'sid_hash',
            'sid'
        ]
    }

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            params = result.get_param()
            headers = headers_map.get(params['event_type'], [])

            results.append({
                'headers': headers,
                'events': get_events(headers, result.get_data())
            })

    return 'taniumthreatresponse_display_events.html'


def display_process_tree(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            results.append({
                'data': result.get_data(),
                'parameter': result.get_param(),
                'message': result.get_message()
            })

    return 'taniumthreatresponse_display_process_tree.html'
