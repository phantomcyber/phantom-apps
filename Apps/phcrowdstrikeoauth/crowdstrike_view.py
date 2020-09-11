# File: crowdstrike_view.py
# Copyright (c) 2019-2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import phantom.app as phantom
import phantom.utils as util


def _get_hash_type(hash_value):

    if util.is_md5(hash_value):
        return (phantom.APP_SUCCESS, "md5")

    if util.is_sha1(hash_value):
        return (phantom.APP_SUCCESS, "sha1")

    if util.is_sha256(hash_value):
        return (phantom.APP_SUCCESS, "sha256")

    return (phantom.APP_ERROR, None)


def get_ctx_result_ps(result):

    ctx_result = {}

    param = result.get_param()

    if ('ioc' in param):
        ioc = param.get('ioc')
        ret_val, param['ioc_type'] = _get_ioc_type(ioc)

    ctx_result['param'] = param

    message = result.get_message()
    ctx_result['message'] = message

    summary = result.get_summary()
    ctx_result['summary'] = summary

    data = result.get_data()

    if (not data):
        return ctx_result

    ctx_result['data'] = data

    return ctx_result


def _get_ioc_type(ioc):

    if util.is_ip(ioc):
        return (phantom.APP_SUCCESS, "ip")

    if util.is_hash(ioc):
        return _get_hash_type(ioc)

    if util.is_domain(ioc):
        return (phantom.APP_SUCCESS, "domain")

    return (phantom.APP_ERROR, "Failed to detect the IOC type")


def _trim_results(data, key):

    if (key not in data):
        return

    if (len(data[key]) <= 100):
        return

    data[key] = data[key][:101]

    data[key][-1] = '...'


def get_ctx_result_hunt(result):

    ctx_result = {}

    param = result.get_param()

    hunt_object = param.get('hash')
    if (not hunt_object):
        hunt_object = param.get('domain')

    param['ioc'] = hunt_object
    ret_val, param['ioc_type'] = _get_ioc_type(hunt_object)

    ctx_result['param'] = param

    message = result.get_message()
    ctx_result['message'] = message

    summary = result.get_summary()
    ctx_result['summary'] = summary

    data = result.get_data()

    if (not data):
        return ctx_result

    ctx_result['data'] = data

    return ctx_result


def get_ctx_result(result):

    ctx_result = {}

    param = result.get_param()

    if ('ioc' in param):
        ioc = param.get('ioc')
        ret_val, param['ioc_type'] = _get_ioc_type(ioc)

    ctx_result['param'] = param

    message = result.get_message()
    ctx_result['message'] = message

    summary = result.get_summary()
    ctx_result['summary'] = summary

    data = result.get_data()

    if (not data):
        return ctx_result

    data = data[0]

    if (not data):
        return ctx_result

    _trim_results(data, 'ip')
    _trim_results(data, 'domain')
    _trim_results(data, 'sha256')
    _trim_results(data, 'sha1')
    _trim_results(data, 'md5')

    ctx_result['data'] = data

    return ctx_result


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

    if provides == 'assign hosts':
        return 'crowdstrike_assign_hosts.html'

    if provides == 'remove hosts':
        return 'crowdstrike_remove_hosts.html'

    if provides == 'create session':
        return 'crowdstrike_create_session.html'

    if provides == 'get indicator':
        return 'crowdstrike_get_indicator.html'

    if provides == 'list incidents':
        return 'crowdstrike_list_incidents.html'

    if provides == 'list incident behaviors':
        return 'crowdstrike_list_incident_behaviors.html'

    if provides == 'list custom indicators':
        return 'crowdstrike_list_custom_indicators.html'

    if provides == 'get user roles':
        return 'crowdstrike_get_user_roles.html'

def hunt_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result_hunt(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    # print context
    return 'hunt_view.html'


def set_status_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    # print context
    return 'set_status_view.html'


def process_list_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result_ps(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)

    # print context
    return 'process_list_view.html'
