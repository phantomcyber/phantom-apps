# File: carbonblack_view.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import carbonblack_consts as consts


# pylint: disable=E1601


def fill_table(query_type, context, data, result):

    # rows is an array or rows :-)
    rows = context['rows']

    # The Headers
    if (query_type == consts.CARBONBLACK_QUERY_TYPE_BINARY):
        context['headers'] = ["MD5", "Endpoints", "Signed", "Company Name", "Product Name", "Is Executable", "File Length", "Filenames"]
    else:
        context['headers'] = ["Process Name", "Process Path", "MD5", "User Name", "Host Name", "Start", "PID", "Parent PID", "Host Type", "OS", "Unique ID", "Cmdline"]
    # every action result will have a single data
    data_rows = data['results']

    for i, data_row in enumerate(data_rows):
        new_row = []
        rows.append(new_row)

        # Append the various columns in the row
        if (query_type == consts.CARBONBLACK_QUERY_TYPE_BINARY):
            # MD5
            new_row.append({'value': data_row['md5'], 'contains': ['md5'], 'id': result.id, 'offset': i})
            # Endpoints
            new_row.append({'value': '\n'.join(data_row['endpoint'])})
            # Signed
            new_row.append({'value': data_row['signed']})
            # Company Name
            new_row.append({'value': data_row['company_name']})
            # Product Name
            new_row.append({'value': data_row['product_name']})
            # Image Type
            new_row.append({'value': data_row['is_executable_image']})
            # Len
            new_row.append({'value': data_row['orig_mod_len']})
            # Filenames
            new_row.append({'value': '\n'.join(data_row['observed_filename'])})

        elif(query_type == consts.CARBONBLACK_QUERY_TYPE_PROCESS):
            # Process Name
            new_row.append({'value': data_row['process_name'], 'contains': ['process name'], 'id': result.id, 'offset': i})
            # Process Path
            new_row.append({'value': data_row['path'], 'contains': ['file path']})
            # MD5
            new_row.append({'value': data_row['process_md5'], 'contains': ['md5']})
            # User Name
            new_row.append({'value': data_row['username'], 'contains': ['user name']})
            # Host Name
            new_row.append({'value': data_row['hostname'], 'contains': ['host name']})
            # Start
            new_row.append({'value': data_row['start']})
            # PID
            new_row.append({'value': data_row['process_pid'], 'contains': ['pid']})
            # Parent PID
            new_row.append({'value': data_row['parent_pid']})
            # Host Type
            new_row.append({'value': data_row['host_type']})
            # OS
            new_row.append({'value': data_row['os_type']})
            # Unique ID
            new_row.append({'value': data_row['unique_id']})
            # Cmdline
            new_row.append({'value': data_row['cmdline']})

    return True


def query_results(provides, all_results, context):

    context['rows'] = []
    for summary, action_results in all_results:

        for result in action_results:

            # The query and type
            parameter = result.get_param()
            context['query'] = parameter['query']
            context['type'] = parameter['type'].capitalize()

            data = result.get_data()
            if (not data):
                continue

            # every action result will have a single data

            # fill it
            fill_table(parameter['type'], context, data[0], result)

    return '/widgets/generic_table.html'


def hunt_file(provides, all_results, context):

    context['rows'] = []
    for summary, action_results in all_results:

        # Each result is going to represent two tables
        for result in action_results:
            parameter = result.get_param()

            if (not parameter):
                continue

            query_type = parameter.get('type')

            if (not query_type):
                continue

            data = result.get_data()

            if (not data):
                continue

            # get the binary data
            query_data = data[0][query_type]

            context['query'] = 'md5:{0}'.format(parameter['hash'])
            context['type'] = query_type.capitalize()

            # fill it
            fill_table(query_type, context, query_data, result)

    return '/widgets/generic_table.html'


def get_file_detail_ctx(result):

    ctx_result = {}

    param = result.get_param()

    ctx_result['md5'] = param.get('hash')

    message = result.get_message()

    if (message) and ('Not Found' in message):
        ctx_result['message'] = message
        print message

    data = result.get_data()

    if (not data):
        return ctx_result

    data = data[0]

    if (not data):
        return ctx_result

    ctx_result['data'] = data
    ctx_result['id'] = result.id

    # work on the endpoint list
    endpoints = data.get('file_details', {}).get('endpoint')

    if (endpoints):
        data['file_details']['endpoint'] = [dict(zip(('host', 'sensor'), x.split('|'))) for x in endpoints]

    summary = result.get_summary()

    if (summary):
        ctx_result['cb_url'] = summary.get('cb_url')
        file_type = summary.get('file_type')
        if (file_type):
            contains = [str(x) for x in file_type.split(',')]
            contains.append('vault id')
            ctx_result['vault_contains'] = contains

    return ctx_result


def display_file_details(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_file_detail_ctx(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    print context

    return 'cb_file_details.html'
