# File: netskope_view.py
# Copyright (c) 2018-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

from datetime import datetime


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
        ctx_result['data'] = {}
        return ctx_result
    ctx_result['data'] = _parse_data(data[0])
    return ctx_result


def _parse_data(data):
    """ Function that parse data.

    :param data: response data
    :return: response data
    """
    for pages in data.get('page', []):
        try:
            if pages.get('_insertion_epoch_timestamp'):
                pages['_insertion_epoch_timestamp'] = ('{}Z').format(datetime.fromtimestamp(pages['_insertion_epoch_timestamp']).isoformat())
        except ValueError:
            pass

    for app in data.get('application', []):
        try:
            if app.get('_insertion_epoch_timestamp'):
                app['_insertion_epoch_timestamp'] = ('{}Z').format(datetime.fromtimestamp(app['_insertion_epoch_timestamp']).isoformat())
        except ValueError:
            pass

    return data


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

    return_page = 'netskope_run_query.html'
    return return_page
