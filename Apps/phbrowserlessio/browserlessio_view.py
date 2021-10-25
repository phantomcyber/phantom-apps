# File: browserlessio_view.py
#
# Copyright (c) Stboch, 2020
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
def get_ctx_result(result):
    ctx_result = {}
    summary = result.get_summary()
    ctx_result['vault_id'] = summary.get('vault_id')
    ctx_result['vault_file_name'] = summary.get('name')
    ctx_result['vault_file_path'] = summary.get('vault_file_path')
    ctx_result['message'] = result.get_message()
    return ctx_result


def display_screenshot(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return 'display_screenshot.html'
