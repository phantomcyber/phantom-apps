# File: ssmachine_view.py
# Copyright (c) 2016-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# --


def get_ctx_result(result):

    ctx_result = {}
    # param = result.get_param()
    summary = result.get_summary()

    ctx_result['vault_id'] = summary.get('vault_id')
    ctx_result['vault_file_name'] = summary.get('name')
    ctx_result['vault_file_path'] = summary.get('vault_file_path')

    try:
        ctx_result['message'] = result.get_message()
    except:
        pass
    return ctx_result


def display_scrshot(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    # print context
    return 'display_scrshot.html'
