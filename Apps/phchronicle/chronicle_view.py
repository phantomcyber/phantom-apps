# File: chronicle_view.py
#
# Copyright (c) 2020-2021 Google LLC.
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
def _get_ctx_result(result, provides):
    """Get context result from given action result object and action identifier.

    Parameters:
        :param result: object of Action Result
        :param provides: action identifier
    Returns:
        :return: context result
    """
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
    """Render the custom output view for the respective actions.

    Parameters:
        :param provides: action identifier
        :param result: object of all app runs
        :param context: object of context for all app runs
    Returns:
        :return: render HTML output template
    """
    context['results'] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides in ['list ioc details', 'domain reputation', 'ip reputation']:
        return 'chronicle_list_ioc_details.html'

    if provides == 'list assets':
        return 'chronicle_list_assets.html'

    if provides == 'list iocs':
        return 'chronicle_list_iocs.html'

    if provides == 'list alerts':
        return 'chronicle_list_alerts.html'
