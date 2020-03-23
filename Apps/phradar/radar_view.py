# File: radar_view.py
# Copyright (c) 2020 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


def display_create_incident_results(provides, all_app_runs, context):
    context["create_incident_results"] = process_incident_results(all_app_runs)
    return "radar_display.html"


def display_get_incident_results(provides, all_app_runs, context):
    context["get_incident_results"] = process_incident_results(all_app_runs)
    return "radar_display.html"


def process_incident_results(all_app_runs):
    data = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            # The phantom action result data is where the output of the action should be added. This always is a list, even when it contains only a single item
            data.append(result.get_data()[0])
    return data


def display_privacy_incident_note(provides, all_app_runs, context):
    for summary, action_results in all_app_runs:
        context["notes"] = []
        for result in action_results:
            # The phantom action result data is where the output of the action should be added. This always is a list, even when it contains only a single item
            data = result.get_data()[0]
            context["notes"].append(data)

    return "radar_display.html"
