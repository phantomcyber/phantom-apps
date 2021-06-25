# File: adldap_view.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


def get_ctx_result(result):
    ctx_result = {}
    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param

    if (data):
        ctx_result['data'] = data[0]

    if (summary):
        ctx_result['summary'] = summary

    return ctx_result


def display_attributes(provides, all_app_runs, context):
    context['results'] = results = []
    context['attributes'] = []
    print("DEBUG all_app_runs = {}".format(all_app_runs))
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    print("DEBUG ctx_result = {}".format(ctx_result))

    # populate keys into 'attributes' variable for django template
    try:
        for n in list(ctx_result['data']['entries'][0]['attributes'].keys()):
            if n not in context['attributes']:
                context['attributes'].append(n)
    except Exception as e:
        context['attributes'] = False
        context['error'] = str(e)

    return 'display_attributes.html'
