# File: radar_view.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


def display_create_incident_results(provides, all_app_runs, context):
    context["create_incident_results"] = process_results(all_app_runs)
    return "radar_display.html"


def display_get_incident_results(provides, all_app_runs, context):
    context["get_incident_results"] = process_results(all_app_runs)
    return "radar_display.html"


def display_add_note_results(provides, all_app_runs, context):
    context["add_note_results"] = process_results(all_app_runs)
    return "radar_display.html"


def display_get_notes_results(provides, all_app_runs, context):
    context["get_notes_results"] = process_results(all_app_runs)
    if not len(context["get_notes_results"]):
        context["get_note_results_none"] = True
    return "radar_display.html"


def process_results(all_app_runs):
    data = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            # The phantom action result data is where the output of the action should be added. This always is a list, even when it contains only a single item
            result_data = result.get_data()
            if len(result_data) > 0:
                data.append(result_data[0])
    return data
