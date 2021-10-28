# File: threatgrid_view.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

from collections import OrderedDict
import json
import os

from threatgrid_consts import *

from phantom.app import APP_SUCCESS

START_TIME_KEY = 'started_at'
END_TIME_KEY = 'completed_at'

OLD_UBER_WIDGET_WWW_TEMPLATE_PATH = 'phantom_ui/templates/widgets/uber_widget.html'


def str2bool(s):
    return s.lower() in ("yes", "true", "t", "1")


def all_results(provides, all_results, context):

    view = context['QS'].get('view', [None])[0]
    container = context['QS'].get('container', [None])[0]
    force_jsonview = str2bool(context['QS'].get('force_jsonview', ['false'])[0])

    if force_jsonview:
        return json_dump_view(all_results, context, view)

    if view == '_ph_query':
        return unfinished(all_results, context)

    if view == 'info' or not container:
        return formatted_view(all_results, context, view)
    else:
        return menu_view(all_results, context)


def unfinished(all_results, context):

    context['rows'] = rows = []
    context['headers'] = ['Results Link', 'Task ID']
    context['allow_links'] = (0,)
    for _, action_results in all_results:
        for result in action_results:
            new_row = []
            new_row.append(
                {'value': result.get_summary().get(RESULTS_URL_KEY)})
            new_row.append({'value': result.get_summary().get(TASK_ID_KEY),
                            'contains': ['threatgrid task id'], 'id': result.id,
                            'data_path': ['action_result.summary.{}'.format(TASK_ID_KEY)]})
            rows.append(new_row)

    return '/widgets/generic_table.html'


def formatted_view(all_results, context, section):

    context['data'] = data = []
    for _, action_results in all_results:
        for result in action_results:
            if result and len(result.get_data()) > 0:
                item = result.get_data()[0]
                if item:
                    data.append(item)
                    item['results_url'] = result.get_summary().get(RESULTS_URL_KEY)
                    item['target'] = result.get_summary().get(TARGET_KEY)
    return 'info.html'


def json_dump_view(all_results, context, section):

    j = []
    for _, action_results in all_results:
        for result in action_results:
            if result and len(result.get_data()) > 0:
                item = {}
                item['summary'] = result.get_summary()
                item['parameter'] = result.get_param()
                item['status'] = result.get_status()
                item['message'] = result.get_message()
                data = result.get_data()[0]
                if data:
                    item['data'] = [data]
                j.append(item)

    context['json'] = [json.dumps(item, separators=(',', ':'), sort_keys=True, indent=4) for item in j]
    return 'json_dump.html'


def menu_view(all_results, context):

    tasks = {}
    for _, action_results in all_results:
        for result in action_results:
            if result.get_status() == APP_SUCCESS:
                tid = result.get_summary().get(TASK_ID_KEY)
                data = result.get_data()[0]
                if tid in tasks:
                    dt = data.get(RESULT_STATUS_KEY, {}).get(END_TIME_KEY)
                    if dt and dt > tasks[tid][0]:
                        target = result.get_summary().get(TARGET_KEY, 'Unknown')
                        tasks[tid] = (dt, result, target)
                else:
                    dt = data.get(RESULT_STATUS_KEY, {}).get(END_TIME_KEY)
                    if not dt:
                        dt = data.get(RESULT_STATUS_KEY, {}).get(START_TIME_KEY)
                    target = result.get_summary().get(TARGET_KEY, 'Unknown')
                    tasks[tid] = (dt, result, target)

    context['menu'] = menu = {}
    force_jsonview = context['QS'].get('force_jsonview', ['false'])[0]

    for tid, result in tasks.items():
        target = '{} (run: {})'.format(result[2], tid)
        result = result[1]
        data = result.get_data()[0]
        app_run_id = result.id
        menu[target] = submenu = OrderedDict()
        if RESULT_STATUS_KEY in data and data[RESULT_STATUS_KEY][RESPONSE_STATE_KEY] in THREATGRID_DONE_STATES:
            submenu['Info'] = [
                '/app/threatgrid_e52c6b70-2972-47e2-ad80-c131f9604ff4/all?app_run={}&view=info&force_jsonview={}'.format(app_run_id, force_jsonview)]
        else:
            submenu['Get Report'] = [
                '/app/threatgrid_e52c6b70-2972-47e2-ad80-c131f9604ff4/all?app_run={}&view=_ph_query&force_jsonview={}'.format(app_run_id, force_jsonview)]
    context['has_maximize'] = True

    if os.path.isfile(OLD_UBER_WIDGET_WWW_TEMPLATE_PATH):
        return '/widgets/uber_widget.html'

    return '/../../phapps/templates/phapps/uber_widget.html'
