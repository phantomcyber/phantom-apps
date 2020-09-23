# File: radar_view.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


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
    result_data["data"] = data[0]
    return result_data
