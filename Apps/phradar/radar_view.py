# File: radar_view.py
#
# Copyright (c) 2020-2021 RADAR, LLC
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
def display_view(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for r in action_results:
            result = process_results(r)
            if not result:
                continue
            results.append(result)

    if provides == "create privacy incident":
        return_page = "radar_create_privacy_incident.html"
    if provides == "get privacy incident":
        return_page = "radar_get_privacy_incident.html"
    if provides == "add note":
        return_page = "radar_add_note.html"
    if provides == "get notes":
        return_page = "radar_get_notes.html"
    return return_page


def process_results(result):
    result_data = {}
    result_data["param"] = result.get_param()
    result_data["status_success"] = result.get_status()
    # The phantom action result data is where the output of the action should be added.
    #  This always is a list, even when it contains only a single item
    data = result.get_data()
    if not data:
        result_data["data"] = {}
        return result_data
    if len(data) == 1:
        result_data["data"] = data[0]
    if len(data) > 1:
        result_data["data_list"] = data
    return result_data
