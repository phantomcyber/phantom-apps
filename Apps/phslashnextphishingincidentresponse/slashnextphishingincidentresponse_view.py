# File: slashnextphishingincidentresponse_view.py
#
# Copyright (c) 2019-2020 SlashNext Inc. (www.slashnext.com)
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
"""
Created on August 20, 2019

@author: Saadat Abid, Umair Ahmad
"""


def get_action_all_results_context(action_results):
    """
    Extracts the context of action results
    :param action_results: Action results after an action is executed in Phantom
    :return: Context
    """
    ar_context = {}
    param = action_results.get_param()
    status = action_results.get_status()
    summary = action_results.get_summary()
    data = action_results.get_data()
    message = action_results.get_message()

    ar_context['param'] = param
    ar_context['status'] = status

    if data:
        ar_context['data'] = data

    if summary:
        ar_context['summary'] = summary

    if message:
        ar_context['message'] = message

    return ar_context


def get_action_result_context(action_results):
    """
    Extracts the context of action results
    :param action_results: Action results after an action is executed in Phantom
    :return: Context
    """
    ar_context = {}
    param = action_results.get_param()
    status = action_results.get_status()
    summary = action_results.get_summary()
    data = action_results.get_data()
    message = action_results.get_message()

    ar_context['param'] = param
    ar_context['status'] = status

    if data:
        ar_context['data'] = data[0]

    if summary:
        ar_context['summary'] = summary

    if message:
        ar_context['message'] = message

    return ar_context


def display_api_quota(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ar_context = get_action_result_context(result)
            if not ar_context:
                continue
            results.append(ar_context)

    # Load the HTML Widget
    return 'display_api_quota.html'


def display_host_reputation(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ar_context = get_action_result_context(result)
            if not ar_context:
                continue
            results.append(ar_context)

    # Load the HTML Widget
    return 'display_host_reputation.html'


def display_host_urls(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ar_context = get_action_result_context(result)
            if not ar_context:
                continue
            results.append(ar_context)

    # Load the HTML Widget
    return 'display_host_urls.html'


def display_host_report(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ar_context = get_action_all_results_context(result)
            if not ar_context:
                continue
            results.append(ar_context)

    # Load the HTML Widget
    return 'display_host_report.html'


def display_url_scan(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ar_context = get_action_all_results_context(result)
            if not ar_context:
                continue
            results.append(ar_context)

    # Load the HTML Widget
    return 'display_url_scan.html'


def display_url_scan_sync(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ar_context = get_action_all_results_context(result)
            if not ar_context:
                continue
            results.append(ar_context)

    # Load the HTML Widget
    return 'display_url_scan_sync.html'


def display_scan_report(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ar_context = get_action_all_results_context(result)
            if not ar_context:
                continue
            results.append(ar_context)

    # Load the HTML Widget
    return 'display_scan_report.html'


def display_sc(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ar_context = get_action_result_context(result)
            if not ar_context:
                continue
            results.append(ar_context)

    # Load the HTML Widget
    return 'display_sc.html'


def display_html(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ar_context = get_action_result_context(result)
            if not ar_context:
                continue
            results.append(ar_context)

    # Load the HTML Widget
    return 'display_html.html'


def display_text(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ar_context = get_action_result_context(result)
            if not ar_context:
                continue
            results.append(ar_context)

    # Load the HTML Widget
    return 'display_text.html'
