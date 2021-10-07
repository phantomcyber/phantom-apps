###########################################################################################################
# File: utils.py
#
# ThreatQuotient Proprietary and Confidential
# Copyright (c)2021 ThreatQuotient, Inc. All rights reserved.
#
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
#
# Dissemination of this information or reproduction of this material is strictly forbidden unless prior
# written permission is obtained from ThreatQuotient, Inc.
###########################################################################################################

import json
import re

from copy import copy
from six import string_types
from .indicator_parser import IndicatorParser
from .tq_mappings import statused_objects, threatq_objects, typed_objects, object_types


class Utils(object):
    """
    Utilities class. A bunch of methods to facilitate the connector
    """

    object_data = {
        'api_name': None,
        'value': None,
        'type': None
    }

    @staticmethod
    def parse_agnostic_input(raw, use_indicator_parser=True):
        """
        Parses a raw input into known and unknown objects. This function will dispatch
        the raw input to the appropriate handler

        Parameters:
            - raw (any): The raw input of unknown type
        """

        if Utils.is_json(raw):
            return Utils.parse_agnostic_json(json.loads(raw), use_indicator_parser)
        elif isinstance(raw, string_types):
            return Utils.parse_agnostic_string(raw, use_indicator_parser)

    @staticmethod
    def parse_agnostic_string(raw, use_indicator_parser=True):
        """
        Parses a string in an unknown format into known and unknown objects.
        This function will check multiple types of formatting and attempts
        to parse out any value and type information

        Parameters:
            - raw (str): An unstructured string input

        Returns: Tuple containing known and unknown objects
        """

        output = []
        unknown = []

        # Handle either comma-separated list or line-separated list
        items = [raw]
        if '\n' in raw:
            items = raw.split('\n')
        elif ',' in raw:
            items = raw.split(',')

        # Remove empty whitelist
        items = [item.strip() for item in items if item]

        if use_indicator_parser:
            for i in items:
                # Try to parse each entry for indicator matches
                parser = IndicatorParser(i)
                matches = parser.match_all()
                if not matches:
                    unknown.append(raw)

                for match in matches:
                    data = copy(Utils.object_data)
                    data['api_name'] = 'indicators'
                    data['value'] = match['value']
                    data['type'] = match['type']
                    output.append(data)

            # If no indicator matches, try to match the name/value pair
            # The name value pair could be an indicator or another object type
            for index in range(len(unknown)):
                pair_data = Utils.parse_name_value_pair(unknown[index])
                if pair_data and pair_data['api_name'] and (pair_data['value'] or pair_data['title']):
                    output.append(pair_data)
                    del unknown[index]

        else:
            for i in items:
                pair_data = Utils.parse_name_value_pair(i)
                if pair_data and pair_data['api_name']:
                    output.append(pair_data)
                else:
                    unknown.append(raw)

        return output, unknown

    @staticmethod
    def parse_name_value_pair(line):
        """
        Parses out a name value pair into possible object data

        Parameters:
            - line (str): The line to parse

        Returns: Parsed pair data, if found
        """

        # We will handle 3 types of delimiters
        delimiter = None
        if line.count("="):
            delimiter = '='
        elif line.count(":"):
            delimiter = ':'
        elif line.count("|"):
            delimiter = '|'

        # If no delimiter, it's not a N/V pair, so return none
        if not delimiter:
            return None

        pair_data = copy(Utils.object_data)

        # Split by the delimiter, then trim
        items = line.split(delimiter)
        part1 = items[0].strip()
        part2 = delimiter.join(items[1:]).strip()

        # Check if either part is an indicator type
        part1_type_match = Utils.match_name_to_indicator_type(part1)
        part2_type_match = Utils.match_name_to_indicator_type(part2)

        # Set pair data accordingly if the first part is the type
        # or if the second half is the type
        if part1_type_match:
            pair_data['api_name'] = 'indicators'
            pair_data['value'] = part2
            pair_data['type'] = part1_type_match
        elif part2_type_match:
            pair_data['api_name'] = 'indicators'
            pair_data['value'] = part1
            pair_data['type'] = part2_type_match
        else:
            # Check if either part is an event type
            part1_event_type_match = Utils.match_name_to_event_type(part1)
            part2_event_type_match = Utils.match_name_to_event_type(part2)

            # Set pair data accordingly if the first part is the type
            # or if the second half is the object name
            if part1_event_type_match:
                pair_data['api_name'] = 'events'
                pair_data['title'] = part2
                pair_data['type'] = part1_event_type_match
            elif part2_event_type_match:
                pair_data['api_name'] = 'events'
                pair_data['title'] = part1
                pair_data['type'] = part2_event_type_match
            else:

                # Check if either part is an object name. If so, use the other as the value
                part1_obj_match = Utils.match_name_to_object(part1).get('collection')
                part2_obj_match = Utils.match_name_to_object(part2).get('collection')

                # Set pair data accordingly if the first part is the type
                # or if the second half is the object name
                if part1_obj_match:
                    pair_data['api_name'] = part1_obj_match
                    pair_data['value'] = part2
                elif part2_obj_match:
                    pair_data['api_name'] = part2_obj_match
                    pair_data['value'] = part1

        return pair_data

    @staticmethod
    def parse_agnostic_json(data, use_indicator_parser=True):
        """
        Parses out a JSON input in an unkown format

        Parameters:
            - data (JSON): JSON data in an unknown format

        Returns: Tuple containing known and unknown objects
        """

        output = []
        unknown = []

        if isinstance(data, list):
            # If the data is a list, do some recursion to parse the child dictionaries
            for i in data:
                r_output, u_output = Utils.parse_agnostic_json(i)
                output.extend(r_output)
                unknown.extend(u_output)
        elif isinstance(data, dict):
            obj = copy(Utils.object_data)

            # Get object metadata (with field fallbacks)
            # This way, we can handle multiple formats for the input JSON
            obj['api_name'] = data.get('object_name', data.get('object_code', data.get('object', data.get('api_name'))))
            obj['value'] = data.get('value', data.get('object_value'))
            obj['type'] = data.get('type', data.get('object_type', data.get('subtype')))

            # If no API name (object name) or object value is found, add to unknown list
            if obj['api_name'] and obj['value']:
                output.append(obj)
            else:
                unknown.append(data)
        elif isinstance(data, string_types):
            s_known, s_unknown = Utils.parse_agnostic_string(data, use_indicator_parser)
            output.extend(s_known)
            unknown.extend(s_unknown)

        return output, unknown

    @staticmethod
    def match_name_to_object(name):
        """
        Matches a user-input to an object name. This will handle any sanitization
        during the compare process, ensuring that we will take into account any
        variations of an object name.

        Parameters:
            - name (str): A string to match to an object name

        Returns: String, corresponding with an object's API name
        """

        for obj in threatq_objects:
            if (
                Utils.flatten_string(name) == Utils.flatten_string(obj['display_name']) or
                Utils.flatten_string(name) == Utils.flatten_string(obj['name']) or
                Utils.flatten_string(name) == Utils.flatten_string(obj['display_name_plural']) or
                Utils.flatten_string(name) == Utils.flatten_string(obj['collection'])
            ):
                return obj
        return {}

    @staticmethod
    def match_name_to_indicator_type(name):
        """
        Matches a user-input to an indicator type. This will handle any sanitization
        during the compare process, ensuring that we will take into account any
        variations of an indicator type

        Parameters:
            - name (str): A string to match to an indicator type

        Returns: String, corresponding with an indicator's type
        """

        for obj in threatq_objects:
            # Skip over any non-indicator types
            if obj['name'] != 'indicator':
                continue

            for i in obj.get('types', []):
                if Utils.flatten_string(i['name']) == Utils.flatten_string(name):
                    return i['name']

    @staticmethod
    def match_name_to_event_type(name):
        """
        Matches a user-input to an event type. This will handle any sanitization
        during the compare process, ensuring that we will take into account any
        variations of an event type

        Parameters:
            - name (str): A string to match to an event type

        Returns: String, corresponding with an indicator's type
        """

        for obj in threatq_objects:
            # Skip over any non-event
            if obj['name'] != 'event':
                continue

            for i in obj.get('types', []):
                if Utils.flatten_string(i['name']) == Utils.flatten_string(name):
                    return i['name']

    @staticmethod
    def match_assignee(assignee, tq_users):
        """
        Attempts to match a TQ user with the given task's assignee. Handles
        any sanitization on comparison to ensure user-input is not botched

        Parameters:
            - assignee (str): The assignee string given by the user
            - tq_users (list): A list of ThreatQ users, presumably returned by the API

        Returns: A user dictionary from the ThreatQ API
        """

        if not assignee or not tq_users:
            return None

        matched = None
        for user in tq_users:
            if (
                Utils.flatten_string(assignee) == Utils.flatten_string(user['display_name']) or
                Utils.flatten_string(assignee) == Utils.flatten_string(user['email'])
            ):
                matched = user
                break

        return matched

    @staticmethod
    def flatten_string(value):
        """
        Flattens a string by removing any new lines, underscores, spaces,
        and then making sure it's lowercase

        Parameters:
            - value (str): The string to "flatten"

        Returns: A flattened string
        """

        value = value.replace('\n', '').replace('_', '').replace(' ', '')
        return value.lower()

    @staticmethod
    def sanitize_indicator(value):
        """
        Sanitizes the input value so it will return results correctly.
        For URL queries, we want to any URL in that domain. So we want to strip
        out any schemas, and replace them with a "wildcard" character. Then, strip
        out anything after the first "/" character, and replace it with a wildcard

        Parameters:
            - value (str): Input indicator value

        Returns: A search-safe indicator value (for URL parameter)
        """

        # Replace the protocol with a wildcard
        if Utils.is_url(value):
            value = Utils.remove_protocol(value, replacement='%')

            # Strip out everything after the forward-slash in the URL
            # Or add a wildcard to match any full URLs
            if '/' in value:
                value = u'{}%'.format(value.split('/')[0])
            else:
                value = u'{}%'.format(value)

            if not value.startswith('%'):
                value = u'%{}'.format(value)

        # Patch weird unicode passing issue
        if value.startswith("u'") or value.startswith("[u'"):
            value = value.replace("[u'", '').replace("u'", '')
            if value.endswith("'"):
                value = value[:-1]
            elif value.endswith("']"):
                value = value[:-2]

        return value

    @staticmethod
    def remove_protocol(value, replacement=''):
        """
        Removes a protocol from a string. Then replaces it with a given value.

        Parameters:
            - value (str): The string to remove a protocol from
            - replacement (str): A string/character to replace the protocol with

        Returns: A value without a protocol (URL Parameter-safe)
        """

        value = value.replace('http://', replacement, 1)
        value = value.replace('https://', replacement, 1)
        value = value.replace('ssh://', replacement, 1)
        value = value.replace('tcp://', replacement, 1)
        value = value.replace('udp://', replacement, 1)
        if value.startswith('%'):
            value = value.replace('www.', '')
        else:
            value = value.replace('www.', '%')

        # Remove trailing /
        if value.endswith('/'):
            value = value[:-1]

        return value

    @staticmethod
    def build_with_params(object_type, relationships=False):
        """
        Builds a full list of "with" parameters for the ThreatQ API.
        This will build the list based on the current object type. This way,
        we can fetch object-specific fields such as score, type, or status.
        This also handles ignoring fields with an underscore to avoid a 500 error

        Parameters:
            - object_type (str): The name of the object type being searched on

        Returns: A comma-separated list of fields to fetch for an object
        """

        output = ["attributes", "sources"]

        # Add self-with attributes
        if object_type in typed_objects:
            output.append("type")
        if object_type in statused_objects:
            output.append("status")
        if object_type == "indicators":
            output.append("score")

        # Add related-with attributes
        if relationships:
            for i in object_types:
                # Skip bugged object types
                if '_' in i:
                    continue

                if i in typed_objects:
                    output.append("{}.type".format(i))
                if i in statused_objects:
                    output.append("{}.status".format(i))
                    output.append(i)
                if i not in typed_objects and i not in statused_objects:
                    output.append(i)

        return ",".join(output)

    @staticmethod
    def generate_summary(details):
        """
        Generates a summary for Phantom, based on given data

        Parameters:
            - details (dict): Details on a response from ThreatQ

        Returns: A summary dictionary for Phantom
        """

        output = {}

        if 'value' in details:
            output['value'] = details['value']
        if 'title' in details:
            output['title'] = details['title']
        if 'name' in details:
            output['name'] = details['name']
        if 'published_at' in details:
            output['published_at'] = details['published_at']
        if 'score' in details:
            output['score'] = details['score']

        # Load types and statuses
        if 'status' in details:
            if isinstance(details['status'], dict):
                output['status'] = details.get('status', {}).get('name', 'N/A')
            else:
                output['status'] = details['status']
        if 'type' in details:
            if isinstance(details['type'], dict):
                output['type'] = details.get('type', {}).get('name', 'N/A')
            else:
                output['type'] = details['type']

        # Load relationship data
        for i in object_types:
            if i in details and isinstance(details[i], list) and len(details[i]) > 0:
                output["related_{}".format(i)] = len(details[i])

        return output

    @staticmethod
    def is_url(value):
        """
        Checks if a value is a URL or Domain

        Parameters:
            - value (str): Possible URL or domain string

        Returns: True or False
        """

        # Check if URL
        pattern = re.compile(IndicatorParser.regex_map['url'], flags=re.IGNORECASE)
        for match in re.finditer(pattern, value):
            if match and match.group(0):
                return True

        # Check if Domain
        pattern = re.compile(IndicatorParser.regex_map['domain'], flags=re.IGNORECASE)
        for match in re.finditer(pattern, value):
            if match and match.group(0):
                return True

        return False

    @staticmethod
    def is_json(raw):
        """
        Checks if a given input is JSON (list or dict)

        Parameters:
            - raw (?): An unstructured and unknown input

        Returns: True or False
        """

        try:
            json.loads(raw)
        except Exception:
            return False

        return True
