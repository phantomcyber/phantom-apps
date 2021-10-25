# File: athena_view.py
#
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
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
