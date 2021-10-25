# File: deepsight_view.py
#
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
def get_ctx_result(result, fetch_all=False):
    ctx_result = {}
    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param

    if data:
        ctx_result['data'] = data if fetch_all else data[0]

    if summary:
        ctx_result['summary'] = summary

    return ctx_result


def custom_view(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == 'file reputation':
        return 'display_report.html'

    if provides == 'get report':
        return 'display_report_detail.html'

    return 'display_reputation.html'


def display_mati_report(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result, fetch_all=True)
            if not ctx_result:
                continue
            data = ctx_result.get('data')
            if data and type(data) is list:
                ctx_data = {'matiReports': data}
                ctx_result['data'] = ctx_data
            results.append(ctx_result)

    return 'display_report.html'
