# --
# File: urlexpander_views.py
# --

from django.http import HttpResponse
import json


def expand_url(provides, all_results, context):

    headers = ['Container ID', 'Container', 'Artifact ID', 'Artifact Name', 'Found in field', 'Matched Value']

    context['ajax'] = True
    context['allow_links'] = [0, 1]
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
            base = result.get_summary().get('server')
            data = result.get_data()
            total += len(data)
            for item in data:
                cur_pos += 1
                if (cur_pos - 1) < start:
                    continue
                if (cur_pos - 1) >= end:
                    break
                row = []

                c_link = base + '/mission/{}'.format(item.get('container_id'))
                # a_link = c_link + '/artifact_id/{}'.format(item.get('id'))
                row.append({ 'value': c_link, 'link': item.get('container_id') })
                row.append({ 'value': c_link, 'link': item.get('container_name') })
                row.append({ 'value': item.get('id'), 'link': item.get('id') })
                row.append({ 'value': item.get('name'), 'link': item.get('name') })
                row.append({ 'value': item.get('found in') })
                row.append({ 'value': item.get('matched') })
                rows.append(row)

    content = {
      "data": rows,
      "recordsTotal": total,
      "recordsFiltered": total,
    }
    return HttpResponse(json.dumps(content), content_type='text/javascript')
