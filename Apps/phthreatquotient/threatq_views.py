# File: threatq_views.py
#
# Copyright (c) 2016-2021 ThreatQuotient, Inc. All rights reserved.
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
#
#
# ThreatQuotient Proprietary and Confidential
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this material is strictly forbidden unless prior
# written permission is obtained from ThreatQuotient, Inc.
from api.tq_mappings import object_types


def get_ctx_result(provides, result):
    """
    Function that parses data.

    Parameters:
        - result: result
        - provides: action name

    Returns: response data
    """

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()
    message = result.get_message()

    ctx_result['param'] = param
    ctx_result['data'] = []
    ctx_result['summary'] = {}
    ctx_result['message'] = message
    ctx_result['action'] = provides
    ctx_result['object_types'] = object_types

    if summary:
        ctx_result['summary'] = summary

    if data:
        ctx_result['data'] = data

    return ctx_result


def render_summarize(provides, all_app_runs, context):
    """
    Function that displays view.

    Parameters:
        - provides: action name
        - context: context
        - all_app_runs: all app runs

    Returns: html page
    """

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(provides, result)
            if not ctx_result:
                continue

            results.append(ctx_result)

    return "threatq_view_summarize.html"


def render_uploaded(provides, all_app_runs, context):
    """
    Function that displays view.

    Parameters:
        - provides: action name
        - context: context
        - all_app_runs: all app runs

    Returns: html page
    """

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(provides, result)
            if not ctx_result:
                continue

            results.append(ctx_result)

    return "threatq_view_uploaded.html"
