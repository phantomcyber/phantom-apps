# File: qradar_view.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
import phantom.app as phantom  # noqa
import phantom.utils as ph_utils

interested_contains = ["ip", "hash", "sha1", "sha256", "md5", "mac address", "url", "email"]


def _get_contains(value):

    contains = []

    if (not value):
        return contains

    for contain, validator in ph_utils.CONTAINS_VALIDATORS.iteritems():

        if (not contain) or (not validator):
            continue

        if (contain not in interested_contains):
            continue

        # This validation is because the Phantom validators are expecting string or buffer value as input
        if (validator(value if not isinstance(value, int) and not isinstance(value, long) and not isinstance(value, float) else str(value))):
            contains.append(contain)

    return contains


def _process_item(item_name, ctx_result):

    item_data_list = ctx_result['data'][item_name]

    if (not item_data_list):
        return

    # get the 1st item on the item list
    headers = item_data_list[0].keys()

    output_dict = {}
    output_dict['headers'] = headers
    contains_data_list = []

    for curr_item_data in item_data_list:

        contains_item = {}
        # data_item_contains = {}
        for k, v in curr_item_data.iteritems():
            contains = _get_contains(v)
            contains_item.update({k: contains})
        contains_data_list.append(contains_item)

    output_dict['data'] = zip(item_data_list, contains_data_list)
    ctx_result['data'][item_name] = output_dict


def get_ctx_result(result):

    ctx_result = {}
    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    if (summary):
        ctx_result['summary'] = summary

    ctx_result['param'] = param

    if (not data):
        return ctx_result

    ctx_result['data'] = data[0]

    items = ctx_result['data']

    if (not items):
        return ctx_result

    item_keys = items.keys()

    # events, flows etc
    for curr_item in item_keys:
        _process_item(curr_item, ctx_result)

    # print (json.dumps(ctx_result, indent=4))
    return ctx_result


def display_query_results(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    # print context
    return 'display_qr.html'
