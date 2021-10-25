# File: agari_view.py
#
# Copyright (c) Agari, 2021
#
# This unpublished material is proprietary to Agari.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Agari.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


def _get_ctx_result(result, provides):

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param
    ctx_result["action_name"] = provides
    if summary:
        ctx_result['summary'] = summary

    if not data:
        ctx_result['data'] = {}
        return ctx_result

    ctx_result['data'] = data

    return ctx_result


def display_view(provides, all_app_runs, context):

    context['results'] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == 'get message':
        return 'agari_get_message.html'
    elif provides == 'list policy events':
        return 'agari_list_policy_events.html'
    else:
        return 'agari_list_messages.html'
