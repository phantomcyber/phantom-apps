# File: cuckoo_view.py
# Copyright (c) 2014-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
#
# --

import json


def _adjust_keys(d, new_keys):
    d = {new_keys[k] if k in new_keys else k: v for k, v in d.iteritems()}


def _process_data(data):
    data = data[0]  # Data will only ever contain 1 item

    # Ignore empty dicts
    report = data.get('report', {})
    filtered_report = {k: v for k, v in report.iteritems() if v}
    data['report'] = filtered_report

    # Convert lists to string for output
    debug = data['report'].get('debug')
    if debug:
        if isinstance(debug.get('log'), list):
            debug['log'] = "".join(debug['log'])
        if isinstance(debug.get('errors'), list):
            debug['errors'] = "".join(debug['errors'])

    target = data['report'].get('target')
    if target:
        phantom_info = target.get(target.get('category'))
        if isinstance(phantom_info, dict):
            target['phantom_info'] = phantom_info

    behavior = data['report'].get('behavior')
    if behavior:
        for pt in behavior.get('processtree', []):
            _adjust_keys(pt, {'ppid': 'parent_id', 'process_name': 'name'})

    strings = data['report'].get('strings')
    if strings:
        if isinstance(strings, list):
            data['report']['strings'] = "\n".join(strings)

    # Creat dumped JSON string for 'other' values
    for k, v in data['report'].iteritems():
        if k not in ['info', 'debug', 'static', 'behavior', 'strings', 'target', 'static']:
            # JSON dump section
            data['report'][k] = json.dumps(v, separators=(',', ':'), sort_keys=True, indent=4)

    return data


def _get_ctx_result(result, provides):
    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    if summary:
        ctx_result['summary'] = summary
    if data:
        ctx_result['data'] = _process_data(data)
    if param:
        ctx_result['param'] = param
    ctx_result['formatted_sections'] = ['info', 'debug', 'static', 'behavior', 'strings', 'target', 'static']

    return ctx_result


def all_results(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return 'view_results.html'
