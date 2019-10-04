# File: athena_view.py
# Copyright (c) 2017-2019 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

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
