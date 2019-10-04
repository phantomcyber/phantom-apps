# --
# File: athena_view.py
#
# Copyright (c) Phantom Cyber Corporation, 2017-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

from django.http import HttpResponse
import json


def display_query_results(provides, all_results, context):

    for summary, action_results in all_results:
        for result in action_results:
            header_data = result.get_data()

    headers = []
    if header_data:
        for header in header_data[0]:
            headers.append(header.get('VarCharValue'))

    context['ajax'] = True
    if 'start' not in context['QS']:
        context['headers'] = headers
        return '/widgets/generic_table.html'

    start = int(context['QS']['start'][0])
    length = int(context['QS'].get('length', ['5'])[0])
    end = start + length
    cur_pos = 0
    rows = []
    total = 0
    for summary, action_results in all_results:
        for result in action_results:

            data = result.get_data()
            total += len(data)

            for item in data[1:]:

                cur_pos += 1
                if (cur_pos - 1) < start:
                    continue
                if (cur_pos - 1) >= end:
                    break

                row = []
                count = 0
                for h in headers:
                    row.append({'value': item[count].get('VarCharValue')})
                    count += 1
                rows.append(row)

    content = {
        "data": rows,
        "recordsTotal": total,
        "recordsFiltered": total,
    }

    return HttpResponse(json.dumps(content), content_type='text/javascript')
