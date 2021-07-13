# File: autofocus_view.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import ast


def get_search_string(query_dict, indent=0):

    query_str = ''

    for x in range(indent):
        query_str += "&nbsp;&nbsp;&nbsp;"

    if len(query_dict['children']) > 1:
        query_str += "Match {0} of the following conditions:<br>".format(query_dict['operator'])
        for child in query_dict['children']:
            if ('children' not in child):
                for x in range(indent):
                    query_str += "&nbsp;&nbsp;&nbsp;"
                query_str += "&nbsp;&nbsp&nbsp;<b>{0}</b> <i>{1}</i> {2}<br>".format(child['field'], child['operator'], child['value'])
            else:
                child_string = get_search_string(child, indent + 1)
                query_str += child_string
    elif len(query_dict['children']) == 1:
        child = query_dict['children'][0]
        if ('children' not in child):
            query_str += "<b>{0}</b> <i>{1}</i> {2}<br>".format(child['field'], child['operator'], child['value'])
        else:
            child_string = get_search_string(child, indent + 1)
            query_str += child_string
    else:
        query_str = "none"

    return query_str


def get_ctx_result(result):
    ctx_result = {}
    ctx_result['summary'] = result.get_summary()
    ctx_result['param'] = result.get_param()
    ctx_result['status'] = result.get_status()

    if (not ctx_result['status']):
        ctx_result['message'] = result.get_message()

    data = result.get_data()

    if (not data):
        return ctx_result

    data = data[0]
    try:
        data['tag']['refs'] = ast.literal_eval(data['tag']['refs'])
    except:
        # eh, we tried
        pass

    # Convert the search definition to something resembling what the actual UI shows
    for tag_search in data['tag_searches']:
        try:
            tag_search['ui_search_string'] = get_search_string(ast.literal_eval(tag_search['ui_search_definition']))
        except:
            tag_search['ui_search_string'] = 'Not Parsed...'

    ctx_result['data'] = data

    return ctx_result


def get_report(provides, all_app_runs, context):
    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    # print context
    return 'af_get_report.html'


def _convert_dict_to_results(input_results):

    import phantom.app as phantom

    from phantom.action_result import ActionResult

    action_results = []
    for i, item in enumerate(input_results):
        r = ActionResult()
        setattr(r, '_ActionResult__status_code', item['status'] == phantom.APP_SUCCESS_STR and phantom.APP_SUCCESS or phantom.APP_ERROR)
        setattr(r, '_ActionResult__status_message', item['message'])
        r.get_data().extend(item['data'])
        r.set_summary(item['summary'])
        r.set_param(item['parameter'])
        r.offset = i
        action_results.append(r)

    return action_results

if __name__ == '__main__':
    import sys
    import pudb
    import json

    pudb.set_trace()
    with open(sys.argv[1]) as f:
        in_json = f.read()
        results = json.loads(in_json)
        # print(json.dumps(in_json, indent=' ' * 4))
        results = _convert_dict_to_results(results)
        for result in results:
            ctx_result = get_ctx_result(result)

    exit(0)
