# File: cofenseintelligence_view.py
# Copyright (c) 2020-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

# Local imports
import time


# Function to parse time in human readable format
def parse_data(data):

    data['firstPublished'] = time.strftime(
        '%Y-%m-%d %H:%M:%S',
        time.localtime(data['firstPublished'] / 1000))
    data['lastPublished'] = time.strftime(
        '%Y-%m-%d %H:%M:%S',
        time.localtime(data['lastPublished'] / 1000))
    return data


# Function to collect information to be rendered for 'get report' action
def get_ctx_result(result):

    ctx_result = generate_data(result)
    if not ctx_result:
        return ctx_result

    data = result.get_data()
    if not data:
        return ctx_result
    data = data[0]

    if data.get("data"):
        data = data['data']
        if data.get("threats"):
            data = data['threats']
    else:
        return ctx_result

    data = parse_data(data)

    ctx_result['report'] = data
    return ctx_result


# Function to initialize 'get report' action
def get_report(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return 'cofenseintelligence_display_report.html'


# Function to render custom view for hunt ip, hunt domain and
# hunt ip actions
def get_reputation(provides, all_app_runs, context):

    context["results"] = results = []
    param_name = None

    # Set containing details of each actions that will be used
    # to render corresponding html files based on the action chosen.
    # Key: Parameter name in action_result.param
    # Value: [Header Name of action that will be displayed, HTML file name]
    action_details = {
        "domain": "Domain Name",
        "url": "URL",
        "ip": "IPv4 Address",
        "file": "File Name"
    }

    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = generate_data(result)

            if not ctx_result:
                continue

            data = result.get_data()
            if data:
                data = data[0]["data"]

                if "threats" not in list(data.keys()):
                    return ctx_result

                if provides == "hunt ip":
                    param_name = "ip"
                elif provides == "hunt domain":
                    param_name = "domain"
                elif provides == "hunt url":
                    param_name = "url"
                elif provides == "hunt file":
                    param_name = "file"

                if str(param_name) in list(action_details.keys()):
                    ctx_result["type"] = action_details[param_name]
                    ctx_result = get_threat_reputation(
                        data,
                        ctx_result
                    )
            ctx_result["param_name"] = param_name
            results.append(ctx_result)

            return 'cofenseintelligence_display_threat.html'


# Function to initialize ctx_result dictionary
def generate_data(result):

    ctx_result = {}
    ctx_result["details"] = []
    ctx_result["param"] = result.get_param()
    ctx_result["summary"] = result.get_summary()
    ctx_result["status"] = result.get_status()
    if not ctx_result['status']:
        ctx_result['message'] = result.get_message()

    return ctx_result


# Function to collect information to be rendered for 'hunt ip',
# 'hunt url' and 'hunt domain' actions
def get_threat_reputation(data, ctx_result):

    ctx_result["details"] = []
    ctx_result["details"] = data["threats"]

    for threats in ctx_result["details"]:
        if "firstPublished" in threats:
            threats["firstPublished"] = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(
                    threats["firstPublished"] / 1000
                )
            )

        if "lastPublished" in threats:
            threats["lastPublished"] = time.strftime(
                '%Y-%m-%d %H:%M:%S', time.localtime(
                    threats["lastPublished"] / 1000
                )
            )

    return ctx_result
