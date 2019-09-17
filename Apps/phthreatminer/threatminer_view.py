# import json


def display_hash(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    # print context
    return 'display_threatminer.html'


def get_ctx_result(result):
    ctx_result = {}
    data = result.get_data()

    if (data):
        ctx_result['raw'] = data[0]
        try:
            if int(data[0]['hosts_domains_and_ips']['status_code']) == 200:
                ctx_result['hosts_domains_and_ips'] = data[0]['hosts_domains_and_ips']['results'][0]
        except:
            pass

        try:
            if int(data[0]['av_detections']['status_code']) == 200:
                ctx_result['av_detections'] = data[0]['av_detections']['results'][0]
        except:
            pass

        try:
            if int(data[0]['http_traffic']['status_code']) == 200:
                ctx_result['http_traffic'] = data[0]['http_traffic']['results'][0]
        except:
            pass

        try:
            if int(data[0]['registry_keys']['status_code']) == 200:
                ctx_result['registry_keys'] = data[0]['registry_keys']['results'][0]
        except:
            pass

        try:
            if int(data[0]['mutants']['status_code']) == 200:
                ctx_result['mutants'] = data[0]['mutants']['results'][0]
        except:
            pass

        try:
            if int(data[0]['metadata']['status_code']) == 200:
                ctx_result['metadata'] = [data[0]['metadata']['results'][0].iteritems()]
        except:
            pass

        try:
            if int(data[0]['report_tagging']['status_code']) == 200:
                ctx_result['report_tagging'] = [data[0]['report_tagging']['results'][0].iteritems()]
        except:
            pass

        try:
            if int(data[0]['samples']['status_code']) == 200:
                ctx_result['samples'] = data[0]['samples']['results']
        except:
            pass

    return ctx_result
