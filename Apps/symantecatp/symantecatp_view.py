# File: symantecatp_view.py
# Copyright (c) 2017-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


def get_ctx_result(result):

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param

    if summary:
        ctx_result['summary'] = summary

    if not data:
        ctx_result['data'] = {}
        return ctx_result

    ctx_result['data'] = data[0]

    return ctx_result


def display_report(provides, all_app_runs, context):

    context['results'] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue
            if ctx_result['data'].get('action') == 'delete_endpoint_file':
                ctx_result['device_uid'] = ctx_result['data']['status'][0]['target']['device_uid']
            results.append(ctx_result)

    return 'symantecatp_display_status.html'


def display_targets(provides, all_app_runs, context):

    context['results'] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue

            if provides == 'delete file':
                ctx_result['param']['hash'] = ctx_result['param']['hash'].split(',')
            else:
                ctx_result['param']['targets'] = ctx_result['param']['targets'].split(',')

            ctx_result['action'] = provides

            results.append(ctx_result)

    return 'symantecatp_display_targets.html'
