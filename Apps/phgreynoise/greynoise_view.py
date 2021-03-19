# File: greynoise_view.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import logging

logger = logging.getLogger(__name__)


def _parse_data(data, param):

    try:
        res = {}

        # parsing data for lookup ip action
        if 'ip' in param.keys() and "code" in data[0].keys():
            for item in data:
                res['ip'] = item['ip']
                res['noise'] = item['noise']
                res['code_meaning'] = item['code_meaning']
                res['visualization'] = item['visualization']
        # parsing data for lookup ips action
        elif 'ips' in param.keys():
            ip_return_list = []
            temp_dict = {}
            for item in data[0]:
                temp_dict['ip'] = item['ip']
                temp_dict['noise'] = item['noise']
                temp_dict['code_meaning'] = item['code_meaning']
                temp_dict['visualization'] = item['visualization']
                ip_return_list.append(temp_dict.copy())
            res['lookup_ips'] = ip_return_list
        # parsing data for ip reputation action
        elif 'ip' in param.keys() and 'seen' in data[0].keys() and 'query' not in param.keys():
            if data[0]['seen'] is False:
                res['ip'] = data[0]["ip"]
                res['seen'] = data[0]['seen']
                res['first_seen'] = "This IP has never been seen scanning the internet"
                res['last_seen'] = "This IP has never been seen scanning the internet"
            else:
                for item in data:
                    res['ip'] = item['ip']
                    res['seen'] = item['seen']
                    res['classification'] = item['classification']
                    res['first_seen'] = item['first_seen']
                    res['last_seen'] = item['last_seen']
                    res['visualization'] = item['visualization']
                    res['actor'] = item['actor']
                    res['organization'] = item['metadata']['organization']
                    res['asn'] = item['metadata']['asn']
                    if item['metadata']['country']:
                        res['country'] = item['metadata']['country']
                    if item['metadata']['city']:
                        res['city'] = item['metadata']['city']
                    res['tags'] = item['tags']
        # parsing data for gnql query
        elif 'query' in param.keys():
            gnql_list = []
            temp_dict = {}
            if data[0]["count"] == 0:
                res['query'] = data[0]['query']
                res['message'] = data[0]['message']
            else:
                for item in data[0]["data"]:
                    temp_dict['ip'] = item['ip']
                    temp_dict['classification'] = item['classification']
                    temp_dict['first_seen'] = item['first_seen']
                    temp_dict['last_seen'] = item['last_seen']
                    temp_dict['visualization'] = item['visualization']
                    temp_dict['actor'] = item['actor']
                    temp_dict['organization'] = item['metadata']['organization']
                    temp_dict['asn'] = item['metadata']['asn']
                    if item['metadata']['country']:
                        temp_dict['country'] = item['metadata']['country']
                    if item['metadata']['city']:
                        temp_dict['city'] = item['metadata']['city']
                    temp_dict['tags'] = item['tags']
                    gnql_list.append(temp_dict.copy())
                res['gnql_query'] = gnql_list
                res['message'] = "results"
        return res

    except Exception as err:
        logger.warning('Error in _parse_data: %s' % str(err))


def _get_ctx_result(result, provides):
    try:
        ctx_result = {}

        param = result.get_param()
        summary = result.get_summary()
        data = result.get_data()

        ctx_result['param'] = param
        if summary:
            ctx_result['summary'] = summary

        if not data:
            ctx_result['data'] = {}
            return ctx_result

        parsed_data = _parse_data(data, ctx_result['param'])

        ctx_result['data'] = parsed_data
        return ctx_result
    except Exception as err:
        logger.warning('Error in _get_ctx_result: %s' % str(err))


def report(provides, all_app_runs, context):
    try:
        context["results"] = []
        for summary, action_results in all_app_runs:
            for result in action_results:
                ctx_result = _get_ctx_result(result, provides)
                if ctx_result:
                    context["results"].append(ctx_result)

        return "view_reports.html"
    except Exception as err:
        logger.warning('Error in report: %s' % str(err))
