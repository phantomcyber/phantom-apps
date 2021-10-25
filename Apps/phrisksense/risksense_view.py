# --
# File: risksense_view.py
#
# Copyright (c) RiskSense, 2020
#
# This unpublished material is proprietary to RiskSense.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of RiskSense.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# --


def _get_ctx_result(result, provides):

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result["check_param"] = False

    if len(list(param.keys())) > 1:
        ctx_result["check_param"] = True

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
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == 'list filter attributes':
        return 'risksense_list_filter_attributes.html'

    elif provides == 'list users':
        return 'risksense_list_users.html'

    elif provides == 'list tags':
        return 'risksense_list_tags.html'

    elif provides in ['list hosts', 'get hosts']:
        return 'risksense_list_hosts.html'

    elif provides in ['list host findings', 'get host finding']:
        return 'risksense_list_host_findings.html'

    elif provides in ['list apps', 'get app']:
        return 'risksense_list_apps.html'

    elif provides == 'list vulnerabilities':
        return 'risksense_list_vulnerabilities.html'
