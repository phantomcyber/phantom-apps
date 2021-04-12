# File: awsiam_view.py
# Copyright (c) 2018-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


def get_ctx_result(provides, result):
    """ Function that parses data.

    :param result: result
    :param provides: action name
    :return: response data
    """

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param

    if summary:
        ctx_result['summary'] = summary
    ctx_result['action'] = provides
    if not data:
        if provides == 'list users':
            ctx_result['data'] = []
        elif provides == 'get user':
            ctx_result['data'] = {}
        return ctx_result

    if provides == 'list users':
        ctx_result['data'] = data
    elif provides == 'get user':
        ctx_result['data'] = data[0]

    return ctx_result


def display_view(provides, all_app_runs, context):
    """ Function that displays view.

    :param provides: action name
    :param context: context
    :param all_app_runs: all app runs
    :return: html page
    """

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(provides, result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == 'list users':
        return_page = "awsiam_list_users.html"
    elif provides == 'get user':
        return_page = "awsiam_get_user.html"
    return return_page
