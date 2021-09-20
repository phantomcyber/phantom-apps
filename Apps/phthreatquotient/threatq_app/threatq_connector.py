###########################################################################################################
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
import os
import requests
import traceback

from datetime import datetime
from dateutil.parser import parse as parse_date

# Phantom imports
import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault

# ThreatQ imports
from api import Utils
from api.tq_mappings import object_types
from threatq_consts import (
    ERR_CONNECTIVITY_TEST, INVESTIGATION_PRIORITY_MAP, INVESTIGATION_VISIBILITY_MAP,
    NO_DATA, SUCC_CONNECTIVITY_TEST, TASK_STATUS_MAP,

)
from threatqsdk import Event, File, Threatq, ThreatQAttribute, ThreatQObject, ThreatQSource


class ThreatQConnector(BaseConnector):
    """
    A ThreatQ connector for Phantom

    Inherits: BaseConnector
    """

    # Default source and status for objects ingested into ThreatQ
    default_source = ThreatQSource("Phantom")
    default_status = "Active"

    def __init__(self):
        # Call the BaseConnector to "extend" it
        super(ThreatQConnector, self).__init__()
        self.tq = None

        # Create action mapping
        self.action_map = {
            'query_indicators': self.query_indicators,
            'create_indicators': self.create_indicators,
            'create_task': self.create_task,
            'create_adversaries': self.create_adversaries,
            'create_event': self.create_event,
            'upload_spearphish': self.create_spearphish,
            'create_custom_objects': self.create_custom_objects,
            'start_investigation': self.start_investigation,
            'upload_file': self.create_file,
            'set_indicator_status': self.set_indicator_status,
            'add_attribute': self.add_attribute,
            'get_related_objects': self.get_related_objects
        }

    def _handle_test_connectivity(self, host, auth_data, verify=True, oauth=False):
        """
        Tests the connectivity to ThreatQ

        Parameters:
            - host (str): The ThreatQ host to connect to
            - auth_data (dict): Authentication data for ThreatQ
            - verify (bool): Whether to verify SSL or not
            - oauth (bool): Whether to authenticate using OAuth credentials or not

        Returns: A Phantom status response
        """

        if not host:
            self.save_progress("ThreatQ Hostname/IP not set")
            return self.get_status()

        self.save_progress("Attempting to authenticate...")
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, host)

        try:
            Threatq(host, auth_data, verify=verify, private=oauth)
            return self.set_status_save_progress(phantom.APP_SUCCESS, SUCC_CONNECTIVITY_TEST)
        except Exception as e:
            msg = '{} -- {}'.format(e.message, traceback.format_exc())
            return self.set_status_save_progress(phantom.APP_ERROR, ERR_CONNECTIVITY_TEST, msg)

    def query_indicators(self, params):
        """
        Action to query ThreatQ for indicator matches

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: List of action results (per input indicator)
        """

        # Get the passed items
        values = params.get('indicator_list')
        exact = params.get('exact', False)
        relationships = params.get('with_all_relationships', False)

        # Convert input to a list
        items = self.get_value_list(values)

        results = []
        for index, item in enumerate(items):
            # Get results from ThreatQ
            self.save_progress("Querying for [{}] - {}/{}".format(item, index + 1, len(items)))
            details = self.query_object_details('indicators', item, exact=exact, relationships=relationships)

            # Add action results
            action_result = ActionResult(dict(params))
            msg = "ThreatQ found [{}] result(s)".format(len(details))
            self.save_progress(msg)

            # Set the status of the request
            if len(details) == 0:
                action_result.set_status(phantom.APP_SUCCESS, NO_DATA)
            else:
                action_result.set_status(phantom.APP_SUCCESS, msg)

            # Add in summary information
            action_result.update_summary({"total": len(details)})
            action_result = self.set_data_response(action_result, details)

            # Add results
            results.append(action_result)

        return results

    def create_indicators(self, params):
        """
        Action to create indicators in ThreatQ

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: Action result
        """

        # Get container info
        _, container_info, _ = self.get_container_info()
        tlp = container_info.get('sensitivity')

        # Get the passed items
        values = params.get('indicator_list')
        default_status = params.get('indicator_status', self.default_status)
        found, unknown = Utils.parse_agnostic_input(values)

        self.save_progress("Parsed [{}] indicators; Unable to parse [{}] strings".format(len(found), len(unknown)))

        # Build new source with TLP
        source_obj = ThreatQSource("Phantom", tlp=tlp)

        indicators = []
        for i in found:
            obj = ThreatQObject(self.tq, 'indicators')
            obj.fill_from_api_response(i)
            obj.status = default_status
            obj.add_source(source_obj)
            indicators.append(obj)

        ThreatQObject.bulk_upload(self.tq, indicators)
        uploaded = [ind for ind in indicators if ind.oid]
        msg = "Successfully uploaded [{}] indicator(s)".format(len(uploaded))

        # Create action result
        action_result = ActionResult(dict(params))
        action_result.update_summary({"total": len(uploaded)})

        # Save progress
        self.save_progress(msg)
        if len(uploaded) == 0:
            action_result.set_status(phantom.APP_ERROR, "No indicators created in ThreatQ")
        else:
            action_result.set_status(phantom.APP_SUCCESS, msg)

        action_result = self.set_data_response(action_result, uploaded)
        return action_result

    def create_task(self, params):
        """
        Action to create a task in ThreatQ

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: Action result
        """

        # Create action result
        action_result = ActionResult(dict(params))

        # Get container info
        _, container_info, _ = self.get_container_info()
        tlp = container_info.get('sensitivity')
        event_name = container_info.get('name')

        # Get task data
        prefix = params.get('task_prefix', '')
        name = params['task_name']
        assigned_to = params.get('assigned_to', '')
        status = params['task_status']
        priority = params['task_priority']
        description = params.get('task_description', '')
        values = params.get('indicator_list', '')
        found, unknown = Utils.parse_agnostic_input(values)

        # Format task name
        if prefix:
            prefix = prefix.strip()
            if prefix.endswith(':'):
                prefix = prefix[:-1]
            if prefix.endswith(' - '):
                prefix = prefix[:-3]
            name = u'{}: {}'.format(prefix, name)

        # Match the assignee to a user ID
        users = self.tq.get_users(withp='source')
        assignee = Utils.match_assignee(assigned_to, users)

        # Get Source with TLP from container
        source_obj = ThreatQSource("Phantom", tlp=tlp)

        # Create task payload
        data = {
            'name': name,
            'priority': priority,
            'status_id': TASK_STATUS_MAP.get(status, 1),
            'sources': [source_obj.to_dict()]
        }

        # Append description (if available)
        if description:
            if not description.startswith('<p>'):
                description = u'<p>{}</p>\n'.format(description)
            data['description'] = description
        if assignee:
            data['assignee_source_id'] = assignee['source']['id']

        # Upload the task
        self.save_progress("Uploading task to ThreatQ")
        res = self.tq.post('/api/tasks', data=data).get('data', {})
        if not res.get('id'):
            action_result.set_status(phantom.APP_ERROR, "Failed to upload task to ThreatQ")
            return action_result

        # Create indicator list
        indicators = []
        if found:
            self.save_progress("Uploading [{}] indicators".format(len(found)))
        for i in found:
            obj = ThreatQObject(self.tq, 'indicators')
            obj.fill_from_api_response(i)
            obj.status = self.default_status
            obj.add_source(source_obj)
            indicators.append(obj)

        # Upload indicator list
        ThreatQObject.bulk_upload(self.tq, indicators)
        uploaded_inds = [ind for ind in indicators if ind.oid]

        # Relate indicators to task
        if uploaded_inds:
            self.save_progress("Relating [{}] indicators to the task".format(len(uploaded_inds)))
        for i in uploaded_inds:
            self.tq.post("{}/tasks".format(i._get_api_endpoint()), data=[{'id': res['id']}])

        # Find and relate event (if available)
        event = ThreatQObject(self.tq, 'events')
        event.set_value(event_name)
        event.find()
        if event.oid:
            data = {'id': event.oid}
            self.save_progress("Relating container event to the task")
            self.tq.post('/api/tasks/{}/events'.format(res['id']), data=data)

            # Add the data to the results
            res.update({'events': [event._to_dict()]})

        # Add data and summary to output result
        action_result.update_summary({"total": 1, "results": [Utils.generate_summary(res)]})
        res.update({
            'host': self.tq.threatq_host,
            'indicators': [ind._to_dict() for ind in uploaded_inds],
            'api_name': 'tasks'
        })
        action_result.add_data(res)

        # Set status and return results
        action_result.set_status(phantom.APP_SUCCESS, "Successfully uploaded task to ThreatQ")
        self.save_progress("Successfully uploaded task to ThreatQ")
        return action_result

    def create_event(self, params):
        """
        Action to create an event in ThreatQ

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: Action result
        """

        # Create action result
        action_result = ActionResult(dict(params))

        # Grab current container info
        _, container_info, _ = self.get_container_info()
        event_name = container_info['name']
        tlp = container_info.get('sensitivity')
        if not container_info['description']:
            event_desc = 'Event created from Phantom'
        else:
            event_desc = container_info['description']

        start_time = parse_date(container_info['start_time'])

        # Event Attributes
        try:
            due_time = parse_date(container_info['due_time'])
            due_time = datetime.strftime(due_time, '%Y-%m-%d %H:%M:%S')
        except Exception:
            due_time = None

        # Get event data from params
        event_type = params.get('event_type', "Incident")
        values = params.get('indicator_list', '')
        found, unknown = Utils.parse_agnostic_input(values)

        # Build out the event
        self.save_progress("Building event to upload to ThreatQ")
        source_obj = ThreatQSource("Phantom", tlp=tlp)
        event = ThreatQObject(self.tq, 'events')
        event.set_value(event_name)
        event.description = event_desc
        event.type = event_type
        event.add_source(source_obj)
        event.happened_at = datetime.strftime(start_time, '%Y-%m-%d %H:%M:%S')

        # Add in attributes
        event.add_attribute(ThreatQAttribute("Severity", container_info.get('severity'), sources=source_obj))
        if due_time:
            event.add_attribute(ThreatQAttribute("Due Date", due_time, sources=source_obj))

        # Upload event
        self.save_progress("Uploading event to ThreatQ")
        event.upload()
        if not event.oid:
            action_result.set_status(phantom.APP_ERROR, "Failed to upload event to ThreatQ")
            return action_result

        # Create indicator list
        indicators = []
        if found:
            self.save_progress("Uploading [{}] indicators and relating to event".format(len(found)))
        for i in found:
            obj = ThreatQObject(self.tq, 'indicators')
            obj.fill_from_api_response(i)
            obj.status = self.default_status
            obj.add_source(source_obj)
            obj.relate_object(event)
            indicators.append(obj)

        # Upload indicator list
        ThreatQObject.bulk_upload(self.tq, indicators)

        # Add data and summary to output result
        output = event._to_dict(for_api=False)
        action_result.update_summary({"total": 1, "results": [Utils.generate_summary(output)]})
        output.update({'host': self.tq.threatq_host})
        action_result.add_data(output)

        # Set status and return action results
        action_result.set_status(phantom.APP_SUCCESS, "Successfully uploaded event to ThreatQ")
        return action_result

    def create_spearphish(self, params):
        """
        Action to create a spearphish event in ThreatQ

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: Action result
        """

        # Create action result
        action_result = ActionResult(dict(params))

        # Grab current container info
        _, container_info, _ = self.get_container_info()
        event_name = container_info['name']
        tlp = container_info.get('sensitivity')

        # Get parameters from request
        vault_id = params.get('vault_id')
        indicator_status = params.get('indicator_status', 'Review')

        # Get the file from the vault
        v_file = Vault.get_file_info(vault_id=vault_id)
        if not v_file:
            action_result.set_status(phantom.APP_ERROR, "No spearphish file found in the Vault!")
            return action_result

        v_file = v_file[0]
        file_name = v_file['name']
        file_path = v_file['path']

        # Read the file
        f = open(file_path, 'r')
        file_text = f.read()
        f.close()

        source_obj = ThreatQSource("Phantom", tlp=tlp)
        spearphish = Event(self.tq)
        spearphish.set_title(file_name)
        spearphish.set_text(file_text)
        spearphish.set_status(indicator_status)
        spearphish.happened_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        spearphish.set_type('Spearphish')

        # Upload the event
        self.save_progress('Uploading spearphish event to ThreatQ')
        spearphish.upload(sources=source_obj)

        # Link the event to the investigation
        event = ThreatQObject(self.tq, 'events')
        event.set_value(event_name)
        event.find()
        if event.oid:
            data = {'id': event.oid}
            self.save_progress("Relating container event to Spearphish event")
            self.tq.post('/api/events/{}/events'.format(spearphish.eid), data=data)

        # Add in some extra info to the output data
        data = spearphish._to_dict()
        data.update({
            'id': spearphish.eid,
            'api_name': 'events',
            'host': self.tq.threatq_host
        })

        # Add data and set summary
        action_result.add_data(data)
        action_result.update_summary(Utils.generate_summary(data))

        # Set status and return action results
        action_result.set_status(phantom.APP_SUCCESS, "Successfully uploaded spearphish event to ThreatQ")
        return action_result

    def create_file(self, params):
        """
        Action to create a file in ThreatQ

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: Action result
        """

        # Create action result
        action_result = ActionResult(dict(params))

        # Grab current container info
        _, container_info, _ = self.get_container_info()
        event_name = container_info['name']
        tlp = container_info.get('sensitivity')

        # Get parameters from request
        vault_id = params.get('vault_id')
        parse = params.get('parse_for_indicators', False)
        indicator_status = params.get('default_indicator_status', 'Review')

        # Get the file from the vault
        v_file = Vault.get_file_info(vault_id=vault_id)
        if not v_file:
            action_result.set_status(phantom.APP_ERROR, "No file found in the Vault!")
            return action_result

        v_file = v_file[0]
        file_name = v_file['name']
        file_path = v_file['path']

        source_obj = ThreatQSource("Phantom", tlp=tlp)
        tq_file = File(self.tq)
        tq_file.name = file_name
        tq_file.path = file_path
        tq_file.ftype = "Phantom Vault File"

        # Check if the file exists already
        tq_file.find()

        if tq_file.fid:
            self.save_progress('File already exists in ThreatQ. Not re-uploading or re-parsing')
        else:
            self.save_progress('Uploading spearphish event to ThreatQ')
            tq_file.upload(sources=source_obj)

            if parse:
                self.save_progress('Parsing file for indicators')
                tq_file.parse_and_import(source_obj, status=indicator_status)

        # Link the event to the investigation
        event = ThreatQObject(self.tq, 'events')
        event.set_value(event_name)
        event.find()
        if event.oid:
            data = {'id': event.oid}
            self.save_progress("Relating container event to file")
            self.tq.post('/api/attachments/{}/events'.format(tq_file.fid), data=data)

        # Add in some extra info to the output data
        data = {}
        data.update({
            'id': tq_file.fid,
            'api_name': 'files',
            'name': tq_file.name,
            'host': self.tq.threatq_host
        })

        # Add data and set summary
        action_result.add_data(data)
        action_result.update_summary(Utils.generate_summary(data))

        # Set status and return action results
        action_result.set_status(phantom.APP_SUCCESS, "Successfully uploaded file to ThreatQ")
        return action_result

    def start_investigation(self, params):
        """
        Action to start an investigation in ThreatQ

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: Action result
        """

        # Create action result
        action_result = ActionResult(dict(params))

        # Get container info
        _, container_info, _ = self.get_container_info()
        tlp = container_info.get('sensitivity')
        event_name = container_info.get('name')

        # Get investigation data
        name = params['investigation_name']
        priority = params['investigation_priority']
        desc = params.get('investigation_description', '')
        visibility = params.get('investigation_visbility', 'Private')
        values = params.get('indicator_list', '')
        found, unknown = Utils.parse_agnostic_input(values)

        # If no indicators, don't create an investigation
        if not found:
            action_result.set_status(phantom.APP_ERROR, "No indicators to add to investigation! Ignoring...")
            return action_result

        # Get Source with TLP from container
        source_obj = ThreatQSource("Phantom", tlp=tlp)

        # Build indicator list
        indicators = []
        if found:
            self.save_progress("Uploading [{}] indicators".format(len(found)))
        for i in found:
            obj = ThreatQObject(self.tq, 'indicators')
            obj.fill_from_api_response(i)
            obj.status = self.default_status
            obj.add_source(source_obj)
            indicators.append(obj)

        # Upload indicator list
        ThreatQObject.bulk_upload(self.tq, indicators)
        uploaded_inds = [ind for ind in indicators if ind.oid]

        # Create the investigation
        self.save_progress("Creating investigation in ThreatQ")
        res = self.tq.post('/api/investigations', data={
            'name': name,
            'priority_id': INVESTIGATION_PRIORITY_MAP.get(priority, 1),
            'status_id': 1,  # Open
            'visible': INVESTIGATION_VISIBILITY_MAP.get(visibility, 0),
            'description': desc
        }).get('data', {})

        # Make sure that it's uploaded
        if not res.get('id'):
            action_result.set_status(phantom.APP_ERROR, "Failed to create investigation")
            return action_result

        # Link the indicators as nodes to the investigation
        self.save_progress("Adding indicator nodes to investigation")
        for ind in uploaded_inds:
            data = {'object_id': ind.oid, 'object_type': 'indicator'}
            self.tq.post('/api/investigations/{}/nodes'.format(res['id']), data=data)

        # Link the event to the investigation
        event = ThreatQObject(self.tq, 'events')
        event.set_value(event_name)
        event.find()
        if event.oid:
            data = {'object_id': event.oid, 'object_type': 'event'}
            self.save_progress("Adding container event to investigation")
            self.tq.post('/api/investigations/{}/nodes'.format(res['id']), data=data)

        # Add data and summary to output result
        action_result.update_summary({"total": 1, "results": [Utils.generate_summary(res)]})
        res.update({'host': self.tq.threatq_host, 'api_name': 'investigations'})
        action_result.add_data(res)

        # Set status and return action result
        action_result.set_status(phantom.APP_SUCCESS, "Successfully created investigation")
        return action_result

    def create_adversaries(self, params):
        """
        Action to create adversaries in ThreatQ

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: Action result
        """

        # Get container info
        _, container_info, _ = self.get_container_info()
        tlp = container_info.get('sensitivity')

        # Get the passed items
        values = params.get('adversary_list')

        # Convert input to a list
        items = self.get_value_list(values)

        self.save_progress("Creating [{}] adversaries in ThreatQ".format(len(items)))

        # Build new source with TLP
        source_obj = ThreatQSource("Phantom", tlp=tlp)

        objects = []
        for i in items:
            obj = ThreatQObject(self.tq, 'adversaries')
            obj.name = i
            obj.add_source(source_obj)
            objects.append(obj)

        ThreatQObject.bulk_upload(self.tq, objects)
        uploaded = [ind for ind in objects if ind.oid]
        msg = "Successfully uploaded [{}] adversaries".format(len(uploaded))

        # Create action result
        action_result = ActionResult(dict(params))
        action_result.update_summary({"total": len(uploaded)})

        # Save progress
        self.save_progress(msg)
        if len(uploaded) == 0:
            action_result.set_status(phantom.APP_ERROR, "No adversaries created in ThreatQ")
        else:
            action_result.set_status(phantom.APP_SUCCESS, msg)

        # Add summary and data to action result and return
        action_result = self.set_data_response(action_result, uploaded)
        return action_result

    def create_custom_objects(self, params):
        """
        Action to create custom objects in ThreatQ

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: Action result
        """

        # Get container info
        _, container_info, _ = self.get_container_info()
        tlp = container_info.get('sensitivity')

        # Get the passed items
        values = params.get('object_list')
        object_type = params.get('object_type')

        # Convert input to a list
        items = self.get_value_list(values)

        # Make sure the object type is valid
        action_result = ActionResult(dict(params))
        obj_data = Utils.match_name_to_object(object_type)
        if not obj_data:
            action_result.set_status(phantom.APP_ERROR, "Invalid object type provided!")
            return action_result

        self.save_progress("Creating [{}] {} in ThreatQ".format(len(items), obj_data['display_name_plural']))

        # Build new source with TLP
        source_obj = ThreatQSource("Phantom", tlp=tlp)

        objects = []
        for i in items:
            obj = ThreatQObject(self.tq, obj_data['collection'])
            if obj_data['collection'] == "indicators":
                found, unknown = Utils.parse_agnostic_input(i)
                if found:
                    obj.fill_from_api_response(found[0])
                    obj.status = self.default_status
            else:
                obj.set_value(i)
            obj.add_source(source_obj)
            objects.append(obj)

        ThreatQObject.bulk_upload(self.tq, objects)
        uploaded = [ind for ind in objects if ind.oid]
        msg = "Successfully uploaded [{}] {}".format(len(uploaded), obj_data['display_name_plural'])

        # Create action result summary
        action_result.update_summary({"total": len(uploaded)})

        # Save progress
        self.save_progress(msg)
        if len(uploaded) == 0:
            action_result.set_status(
                phantom.APP_ERROR, "No {} created in ThreatQ".format(obj_data['display_name_plural']))
        else:
            action_result.set_status(phantom.APP_SUCCESS, msg)

        # Create a list of summaries
        action_result = self.set_data_response(action_result, uploaded)
        return action_result

    def add_attribute(self, params):
        """
        Action to add an attribute to objects in ThreatQ

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: Action result
        """

        action_result = ActionResult(dict(params))

        # Get container info
        _, container_info, _ = self.get_container_info()
        tlp = container_info.get('sensitivity')
        start_time = parse_date(container_info['start_time'])

        # Build new source with TLP
        source_obj = ThreatQSource("Phantom", tlp=tlp)

        # Get the passed items
        values = params.get('object_list')
        object_type = params.get('object_type')
        attribute_name = params.get('attribute_name')
        attribute_value = params.get('attribute_value')

        # Make sure the object type is valid
        obj_data = Utils.match_name_to_object(object_type)
        if not obj_data:
            action_result.set_status(phantom.APP_ERROR, "Invalid object type provided!")
            return action_result

        # Get the passed items
        found, unknown = Utils.parse_agnostic_input(values, obj_data["collection"] == "indicators")

        self.save_progress("Adding attribute to [{}] objects in ThreatQ".format(len(found)))

        # If it's an object that only takes a single value field, add in the unknowns
        if obj_data["collection"] not in ["indicators", "signatures", "events"]:
            identifier = "value"
            if obj_data["collection"] == "adversaries":
                identifier = "name"
            unknown = [{identifier: val} for val in unknown if val]

        # Build the objects
        objects = {}
        for i in found + unknown:
            obj = ThreatQObject(self.tq, obj_data["collection"])
            obj.fill_from_api_response(i)
            if obj_data["collection"] == "indicators":
                obj.status = self.default_status
            if obj_data["collection"] == "events":
                obj.happened_at = datetime.strftime(start_time, '%Y-%m-%d %H:%M:%S')
            obj.add_source(source_obj)
            obj.add_attribute(ThreatQAttribute(attribute_name, attribute_value, sources=source_obj))

            if obj.api_name not in objects:
                objects[obj.api_name] = []
            objects[obj.api_name].append(obj)

        # Upload the objects
        uploaded = []
        for objs in objects.values():
            ThreatQObject.bulk_upload(self.tq, objs)
            uploaded.extend([u_obj for u_obj in objs if u_obj.oid])

        msg = "Successfully added attribute to [{}] objects".format(len(uploaded))

        # Create action result summary
        action_result.update_summary({"total": len(uploaded)})

        # Save progress
        self.save_progress(msg)
        if len(uploaded) == 0:
            action_result.set_status(phantom.APP_ERROR, "No attributes created in ThreatQ")
        else:
            action_result.set_status(phantom.APP_SUCCESS, msg)

        action_result = self.set_data_response(action_result, uploaded)
        return action_result

    def get_related_objects(self, params):
        """
        Action to query for related objects within ThreatQ

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: List of action results (per input indicator)
        """

        # Get the passed items
        values = params.get('object_list')
        object_type = params.get('object_type')
        related_object_type = params.get('related_object_type')

        # Make sure the object type is valid
        action_result = ActionResult(dict(params))
        obj_data = Utils.match_name_to_object(object_type)
        related_obj_data = Utils.match_name_to_object(related_object_type)
        if not obj_data or not related_obj_data:
            action_result.set_status(phantom.APP_ERROR, "Invalid object type provided!")
            return action_result

        self.save_progress("Fetching related [{}] in ThreatQ".format(obj_data['display_name_plural']))

        # Convert the input values into a list
        items = self.get_value_list(values)

        results = []
        for index, item in enumerate(items):
            base_obj = obj_data["collection"]
            related_obj = related_obj_data["collection"]

            # Get results from ThreatQ
            self.save_progress("Querying for {}'s related {} - {}/{}".format(
                obj_data["display_name"], related_obj_data["display_name_plural"], index + 1, len(items)))
            result = self.query_object_details(base_obj, item, exact=True, relationships=False)

            if not result:
                action_result.set_status(phantom.APP_SUCCESS, NO_DATA)
                continue

            related_objects = []
            related_res = self.tq.get(
                '/api/{}/{}/{}'.format(base_obj, result[0].oid, related_obj), withp="attributes").get('data', [])
            for rel in related_res:
                rel_obj = ThreatQObject(self.tq, related_obj)
                rel_obj.fill_from_api_response(rel)
                related_objects.append(rel_obj)

            # Add action results
            action_result = ActionResult(dict(params))
            msg = "ThreatQ found [{}] result(s)".format(len(related_objects))
            self.save_progress(msg)

            # Set the status of the request
            if len(related_objects) == 0:
                action_result.set_status(phantom.APP_SUCCESS, NO_DATA)
            else:
                action_result.set_status(phantom.APP_SUCCESS, msg)

            # Add in summary information
            action_result.update_summary({"total": len(related_objects)})
            action_result = self.set_data_response(action_result, related_objects)

            # Add results
            results.append(action_result)

        return results

    def set_indicator_status(self, params):
        """
        Action to set the status of a list of indicators in ThreatQ

        Parameters:
            - params (dict): Parameters from Phantom

        Returns: Action result
        """

        # Get container info
        _, container_info, _ = self.get_container_info()
        tlp = container_info.get('sensitivity')

        # Build new source with TLP
        source_obj = ThreatQSource("Phantom", tlp=tlp)

        # Get the passed items
        values = params.get('indicator_list')
        indicator_status = params.get('indicator_status', self.default_status)
        found, unknown = Utils.parse_agnostic_input(values)

        self.save_progress("Parsed [{}] indicators; Unable to parse [{}] strings".format(len(found), len(unknown)))

        # Build out the objects
        indicators = []
        for i in found:
            obj = ThreatQObject(self.tq, 'indicators')
            obj.fill_from_api_response(i)
            obj.status = indicator_status
            obj.add_source(source_obj)
            indicators.append(obj)

        # Upload the objects
        self.save_progress("Uploading [{}] indicators".format(len(indicators)))
        ThreatQObject.bulk_upload(self.tq, indicators)
        uploaded = [ind for ind in indicators if ind.oid]

        # Set the status manually
        payload = {'status': {'name': indicator_status}}
        if uploaded:
            self.save_progress("Setting status of [{}] indicators to [{}]".format(len(uploaded), indicator_status))
        for i in uploaded:
            self.tq.put(i._get_api_endpoint(), data=payload)

        msg = "Successfully set status of [{}] indicator(s)".format(len(uploaded))

        # Create action result
        action_result = ActionResult(dict(params))
        action_result.update_summary({"total": len(uploaded)})

        # Save progress
        self.save_progress(msg)
        if len(uploaded) == 0:
            action_result.set_status(phantom.APP_ERROR, "No statuses changed in ThreatQ")
        else:
            action_result.set_status(phantom.APP_SUCCESS, msg)

        # Add summary and data to action result
        action_result = self.set_data_response(action_result, uploaded)
        return action_result

    def get_value_list(self, value):
        """
        Converts an input string into a list
        """

        try:
            # Test to see if it's a list
            value = json.loads(value)
        except Exception:
            pass

        # Get the passed items
        items = value
        if not isinstance(value, list):
            if '\n' in value:
                items = value.split('\n')
            elif ',' in value:
                items = value.split(',')
            else:
                items = [value]

        return [item.strip() for item in items if item]

    def set_data_response(self, action_result, data):
        """
        Helper for adding data and summary to the action result

        Parameters:
            - action_result (ActionResult): The action result to add to
            - data (dict/list): The result set from the action

        Returns: Updated action result
        """

        if not isinstance(data, list):
            data = [data]

        summary_res = []
        for index, item in enumerate(data):
            # Add the data to the action result
            dict_data = item._to_dict(ignore=["type_id", "status_id"], for_api=False)
            dict_data.update({'host': self.tq.threatq_host})
            dict_data.update({'display_value': item.value or item.name or item.title})
            summary_res.append(Utils.generate_summary(dict_data))
            action_result.add_data(dict_data)

        # Append to summary
        action_result.update_summary({"results": summary_res})

        return action_result

    def query_object_details(self, object_type, value, exact=False, relationships=False):
        """
        Queries for all object details, including relationships

        Parameters:
            - object_type (str): The API name for the object being searched for
            - value (str): The value to search for

        Returns: List of results from ThreatQ
        """

        identifier = "value"
        if object_type in ["adversaries", "signatures"]:
            identifier = "name"
        elif object_type in ["events", "attachments"]:
            identifier = "title"

        # If we don't want the exact value, sanitize it to do an "approximate" search
        if not exact:
            value = Utils.sanitize_indicator(value)

        # Compile "with" parameters
        params = {identifier: value, "with": Utils.build_with_params(object_type, relationships=relationships)}

        # Send the request
        res = self.tq.get('/api/{}'.format(object_type), params=params)

        results = []
        for i in res.get('data', []):
            # Get "bugged" objects via direct endpoint
            if relationships:
                for obj_type in object_types:
                    if '_' in obj_type:
                        i[obj_type] = self.tq.get(
                            '/api/{}/{}/{}'.format(object_type, i['id'], obj_type)).get('data', [])

            obj = ThreatQObject(self.tq, object_type)
            obj.fill_from_api_response(i)
            results.append(obj)

        return results

    def handle_action(self, params):
        """
        Dispatches Phantom actions to the correct handler

        Parameters:
            - params (dict): Parameters passed in by Phantom
        """

        status = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()
        self.debug_print("action_id", self.get_action_identifier())

        # Get the current configuration
        config = self.get_config()
        tq_host = config.get('tq_server')
        clientid = config.get('clientid')
        username = config.get('username')
        password = config.get('password')
        trust_ssl = config['trust_ssl']

        auth_data = {'clientid': clientid, 'auth': {'email': username, 'password': password}}

        # If we are trusting the certificat, remove the CA Bundle requirement
        # This may be able to be removed becase we are passing it directly to the SDK
        if trust_ssl and 'REQUESTS_CA_BUNDLE' in os.environ:
            del os.environ['REQUESTS_CA_BUNDLE']

        # Check if we are testing connectivity through the UI
        if action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            status = self._handle_test_connectivity(tq_host, auth_data, verify=(not trust_ssl))
            return status

        try:
            # Re-authenticate with ThreatQ
            self.tq = Threatq(tq_host, auth_data, verify=(not trust_ssl))
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, ERR_CONNECTIVITY_TEST, e.message)

        # Get the action
        action = self.action_map.get(action_id)
        if not action:
            return self.set_status(
                phantom.APP_ERROR, "No action handler associated with action [{}]".format(action_id))

        try:
            # Dispatch the action
            action_results = action(params)
        except Exception as e:
            action_results = ActionResult(dict(params))
            action_results.set_status(phantom.APP_ERROR, "{} -- {}".format(e.message, traceback.format_exc()))

        if not isinstance(action_results, list):
            action_results = [action_results]

        # Add the action results
        for i in action_results:
            self.add_action_result(i)

        return self.get_status()


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print ("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ThreatQConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
