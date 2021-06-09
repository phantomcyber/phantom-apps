# File: bmcremedy_view.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


def _get_ctx_result(result, provides):

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

    if provides == 'create ticket':
        ctx_result['data'] = data
    elif provides == 'get ticket':
        ctx_result['data'] = {"work_details": data[0]['work_details']['entries'],
                              "incident_details": data[0]['entries']}
    else:
        ctx_result['data'] = data[0].get('entries')
    ctx_result['action'] = provides

    return ctx_result


def display_tickets(provides, all_app_runs, context):

    context['results'] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return 'bmcremedy_display_tickets.html'


def create_ticket(provides, all_app_runs, context):

    context['results'] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return 'bmcremedy_create_ticket.html'


def display_ticket_details(provides, all_app_runs, context):

    context['results'] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return 'bmcremedy_display_ticket_details.html'
