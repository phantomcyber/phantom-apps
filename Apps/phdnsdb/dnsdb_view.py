# File: dnsdb_view.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

def _parse_data(data, param):

    res = {}

    # parsing data for flex search action
    if 'query' in param.keys():
        res['flex'] = {}
        rrtypes = set(map(lambda x: x['rrtype'], data))
        for curr_rrtype in rrtypes:
            res['flex'][curr_rrtype] = []
        for match in data:
            res['flex'][match['rrtype']].append(match)
    # parsing data for lookup ip action
    elif 'ip' in param.keys() or 'name' in param.keys():
        res['response'] = {}
        res['response'] = data
        res['ip'] = {}
        res['ip']['domains'] = set()
        for rdata in data:
            if rdata['rrname']:
                res['ip']['domains'].add(rdata['rrname'])

        for rt in res['ip']:
            if isinstance(res['ip'][rt], set):
                res['ip'][rt] = list(res['ip'][rt])
    # parsing data for lookup raw rdata action
    elif 'raw_rdata' in param.keys():
        res['response'] = {}
        res['response'] = data
        res['raw'] = {}
        res['raw']['domains'] = set()
        for rdata in data:
            if rdata['rrname']:
                res['raw']['domains'].add(rdata['rrname'])

        for rt in res['raw']:
            if isinstance(res['raw'][rt], set):
                res['raw'][rt] = list(res['raw'][rt])
    # parsing data for lookup domain action
    elif 'owner_name' in param.keys() or ("type" in param.keys() and param["type"] == "RRSET"):
        res['domain'] = {}
        rrtype = param.get('type', 'ANY')
        rrtypes = set(map(lambda x: x['rrtype'], data))

        # if data contains multiple record types
        if rrtype in ('ANY', 'ANY-DNSSEC'):
            for curr_rrtype in rrtypes:
                if curr_rrtype in ['SOA', 'MX']:
                    res['domain'][curr_rrtype] = []
                else:
                    res['domain'][curr_rrtype] = set()

        # if specific record type selected
        elif rrtype in ['SOA', 'MX']:
            res['domain'][rrtype] = []
        else:
            res['domain'][rrtype] = set()

        for rrset in data:
            if rrset['rrtype'] in ['SOA', 'MX']:
                res['domain'][rrset['rrtype']] =\
                    res['domain'][rrset['rrtype']] + rrset['rdata']
            else:
                res['domain'][rrset['rrtype']] =\
                    res['domain'][rrset['rrtype']].union(rrset['rdata'])

        if 'SOA' in res['domain']:
            res['domain']['SOA'] =\
                [dict(s) for s in set(frozenset(d.items())
                 for d in res['domain']['SOA'])]
        if 'MX' in res['domain']:
            res['domain']['MX'] =\
                [dict(s) for s in set(frozenset(d.items())
                 for d in res['domain']['MX'])]

        for rt in res['domain']:
            if isinstance(res['domain'][rt], set):
                res['domain'][rt] = list(res['domain'][rt])

    return res


def _get_ctx_result(result):

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

    data = _parse_data(data, ctx_result['param'])

    ctx_result['data'] = data
    return ctx_result


def display_lookup_info(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return 'dnsdb_lookup_info.html'


def show_rate_limits(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            param = result.get_param()
            summary = result.get_summary()
            data = result.get_data()
            ctx_result = {}

            ctx_result['param'] = param
            if summary:
                ctx_result['summary'] = summary

            if not data:
                ctx_result['data'] = {}
            else:
                ctx_result['data'] = data
            results.append(ctx_result)

    return 'dnsdb_rate_limits.html'
