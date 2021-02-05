# File: athena_view.py
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


def display_query_results(provides, all_results, context):
    context['results'] = results = []

    for summary, action_results in all_results:
        for result in action_results:
            table = {}
            table['data'] = table_data = []
            table['header'] = table_header = []
            data = result.get_data()
            for header_item in data[:1]:  # create headers
                for h in header_item:
                    table_header.append(h.get('VarCharValue'))
            for item in data[1:]:  # skipping header
                row = []
                for _index, _ in enumerate(table_header):
                    row.append({'value': item[_index].get('VarCharValue')})
                table_data.append(row)
            results.append(table)

    return 'run_query.html'
