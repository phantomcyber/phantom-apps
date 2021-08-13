# File: windowsdefenderatp_view.py
# Copyright (c) 2019-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

def get_ctx_result(result):

    ctx_result = {}
    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param

    if data:
        ctx_result['data'] = data

    if summary:
        ctx_result['summary'] = summary

    return ctx_result


def display_alerts(provides, all_app_runs, context):

    context['results'] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    return 'windowsdefenderatp_list_alerts.html'
