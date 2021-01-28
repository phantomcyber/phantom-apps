# File: ds_on_poll_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from urllib.parse import urlparse
from datetime import datetime
from unidecode import unidecode
# import time

import phantom.app as phantom
from phantom.action_result import ActionResult

from digital_shadows_consts import *

# from dsapi.service.data_breach_service import DataBreachService
from dsapi.service.data_breach_record_service import DataBreachRecordService
from dsapi.service.incident_service import IncidentService
from dsapi.service.intelligence_incident_service import IntelligenceIncidentService
from exception_handling_functions import ExceptionHandling

from dsapi.config import ds_api_host
import json


class DSOnPollConnector(object):

    def __init__(self, connector):
        """
        :param connector: DigitalShadowsConnector
        """
        self._connector = connector
        self._handle_exception_object = ExceptionHandling()
        config = connector.get_config()
        self._ds_api_key = config[DS_API_KEY_CFG]
        self._ds_api_secret_key = config[DS_API_SECRET_KEY_CFG]
        self._poll_interval = config['ingest'].get('interval_mins')
        self._container_label = config['ingest']['container_label']
        self._history_days_interval = config['history_days_interval']
        self._global_incident = config.get('global_incident', False)
        self._private_incident = config.get('private_incident', False)
        self._inc_typ_data_leakage = config.get('inc_typ_data_leakage', False)
        self._inc_typ_brand_protection = config.get('inc_typ_brand_protection', False)
        self._inc_typ_infrastructure = config.get('inc_typ_infrastructure', False)
        self._inc_typ_physical_security = config.get('inc_typ_physical_security', False)
        self._inc_typ_social_media_compliance = config.get('inc_typ_social_media_compliance', False)
        self._inc_typ_cyber_threat = config.get('inc_typ_cyber_threat', False)

    def on_poll(self, param): # noqa

        self._connector.debug_print(param)
        action_result = ActionResult(dict(param))
        self._connector.add_action_result(action_result)

        start_time, end_time = self._phantom_daterange(param)
        if start_time is None or end_time is None:
            action_result.set_status(phantom.APP_ERROR, status_message='start time or end time not specified')
        else:
            self._connector.save_progress("Start creating incident")
            # Validate 'history_days_interval' configuration parameter
            ret_val, self._history_days_interval = self._handle_exception_object.validate_integer(action_result, self._history_days_interval, HISTORY_DAYS_INTERVAL_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            date_range = "P{}D".format(self._history_days_interval)

            incident_types = []
            if self._inc_typ_data_leakage:
                incident_types.append({'type': 'DATA_LEAKAGE', 'subTypes': DS_DL_SUBTYPE })
            if self._inc_typ_brand_protection:
                incident_types.append({'type': 'BRAND_PROTECTION', 'subTypes': DS_BP_SUBTYPE })
            if self._inc_typ_infrastructure:
                incident_types.append({'type': 'INFRASTRUCTURE', 'subTypes': DS_INFR_SUBTYPE })
            if self._inc_typ_physical_security:
                incident_types.append({'type': 'PHYSICAL_SECURITY', 'subTypes': DS_PS_SUBTYPE })
            if self._inc_typ_social_media_compliance:
                incident_types.append({'type': 'SOCIAL_MEDIA_COMPLIANCE', 'subTypes': DS_SMC_SUBTYPE })
            if self._inc_typ_cyber_threat:
                incident_types.append({'type': 'CYBER_THREAT'})

            if self._private_incident:
                try:
                    incident_service = IncidentService(self._ds_api_key, self._ds_api_secret_key)

                    incident_view = IncidentService.incidents_view(date_range=date_range, date_range_field='published', statuses=['READ', 'UNREAD'], types=incident_types)
                    self._connector.save_progress("incident req view: {}".format(json.dumps(incident_view, ensure_ascii=False)))
                except Exception as e:
                    error_message = self._handle_exception_object.get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))

                try:
                    incident_pages = incident_service.find_all_pages(view=incident_view)
                    j = 0
                    incident_total = len(incident_pages)
                except StopIteration:
                    error_message = 'No Incident objects retrieved from the Digital Shadows API in page groups'
                    return action_result.set_status(phantom.APP_ERROR, "Error Details: {0}".format(error_message))
                except Exception as e:
                    error_message = self._handle_exception_object.get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {}".format(error_message))
                for incident_page in incident_pages:
                    for incident in incident_page:
                        status, message = self._save_incident(incident)
                        if status == phantom.APP_SUCCESS:
                            j += 1
                            self._connector.save_progress(DS_POLL_INCIDENT_COMPLETE.format(incident.id, j, incident_total))
                        else:
                            self._connector.error_print("Did not ingest incident {}".format(incident.id))
                            action_result.set_status(phantom.APP_ERROR, message)
                            self._connector.add_action_result(action_result)
                            return action_result.get_status()
                self._connector.save_progress("Ingesting DS Incidents Completed.")

                if j != incident_total:
                    action_result.set_status(phantom.APP_ERROR,
                                         status_message='Did not receive all the incident from Digital Shadows')
                else:
                    action_result.set_status(phantom.APP_SUCCESS)

            if self._global_incident:
                try:
                    intelligence_incident_service = IntelligenceIncidentService(self._ds_api_key, self._ds_api_secret_key)
                    intelligence_incident_view = IntelligenceIncidentService.intelligence_incidents_view(date_range=date_range,
                                                                                  date_range_field='published', types=incident_types)
                    self._connector.save_progress('intelligence_incident_view: {}'.format(json.dumps(intelligence_incident_view, ensure_ascii=False)))
                except Exception as e:
                    error_message = self._handle_exception_object.get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, "{0} {1}".format(SERVICE_ERR_MSG, error_message))

                try:
                    intelligence_incident_pages = intelligence_incident_service.find_all_pages(view=intelligence_incident_view)
                    k = 0
                    intelligence_incident_total = len(intelligence_incident_pages)
                except StopIteration:
                    error_message = 'No IntelligenceIncident objects retrieved from the Digital Shadows API in page groups'
                    return action_result.set_status(phantom.APP_ERROR, "Error Details: {0}".format(error_message))
                except Exception as e:
                    error_message = self._handle_exception_object.get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {}".format(error_message))

                for intelligence_incident_page in intelligence_incident_pages:
                    for intelligence_incident in intelligence_incident_page:
                        self._connector.save_progress('count: {}'.format(k))
                        status, message = self._save_intel_incident(intelligence_incident)
                        if status == phantom.APP_SUCCESS:
                            k += 1
                            self._connector.save_progress(DS_POLL_INCIDENT_COMPLETE.format(intelligence_incident.id, k, intelligence_incident_total))
                        else:
                            self._connector.error_print("Did not ingest intel-incident {}".format(intelligence_incident.id))
                            action_result.set_status(phantom.APP_ERROR, message)
                            self._connector.add_action_result(action_result)
                            return action_result.get_status()

                if k != intelligence_incident_total:
                    action_result.set_status(phantom.APP_ERROR,
                                         status_message='Did not receive all the intelligence incident from Digital Shadows')
                else:
                    action_result.set_status(phantom.APP_SUCCESS)

                self._connector.save_progress("Ingesting DS Intelligence Incidents Completed.")

            """
            self._connector.save_progress("Ingesting Data Breaches from {} until {}".format(start_time, end_time))
            published_filter = '{}/{}'.format(start_time.isoformat(), end_time.isoformat())

            breach_service = DataBreachService(self._ds_api_key, self._ds_api_secret_key)

            view = DataBreachService.data_breach_view(published=published_filter)
            breach_pages = breach_service.find_all_pages(view=view)

            i = 0
            total = len(breach_pages)
            for breach_page in breach_pages:
                for breach in breach_page:
                    status, message = self._save_data_breach(breach)
                    if status == phantom.APP_SUCCESS:
                        i += 1
                        self._connector.save_progress(DS_POLL_BREACH_COMPLETE.format(breach.id, i, total))
                    else:
                        self._connector.error_print("Did not ingest Data Breach {}".format(breach.id))
                        action_result.set_status(phantom.APP_ERROR, message)
                        self._connector.add_action_result(action_result)
                        return action_result.get_status()

            if i != total:
                action_result.set_status(phantom.APP_ERROR,
                                         status_message='Did not receive all data breaches from Digital Shadows')
            else:
                action_result.set_status(phantom.APP_SUCCESS)
            """

        return action_result.get_status()

    def _phantom_daterange(self, param):
        """
        Extract Phantom start time and end time as datetime objects.
        Divide by 1000 to resolve milliseconds.

        :param param: dict
        :return: start_time, end_time
        """
        try:
            start_time_param = float(param.get('start_time'))
            end_time_param = float(param.get('end_time'))
        except TypeError:
            self._connector.error_print("start time or end time not specified")
            return None, None

        return datetime.fromtimestamp(start_time_param / 1000.0), datetime.fromtimestamp(end_time_param / 1000.0)

    def _save_data_breach(self, breach):

        container = self._prepare_container(breach)
        status, message, container_id = self._connector.save_container(container)

        if status == phantom.APP_SUCCESS:
            breach_record_service = DataBreachRecordService(self._ds_api_key, self._ds_api_secret_key)

            for breach_record_page in breach_record_service.find_all_pages(breach.id):
                artifacts = list(map(
                    lambda breach_record: self._prepare_artifact(container_id,
                                                                 container['severity'],
                                                                 breach,
                                                                 breach_record),
                    breach_record_page
                ))
                self._connector.save_artifacts(artifacts)

            return status, message
        else:
            return status, message

    def _save_intel_incident(self, intelligence_incident):
        container = self._prepare_intel_incident_container(intelligence_incident)
        status, message, container_id = self._connector.save_container(container)
        if status == phantom.APP_SUCCESS and message != 'Duplicate container found':
            intel_incident_artifacts = self._prepare_intel_incident_artifact(container_id, container['severity'], intelligence_incident)
            self._connector.save_artifact(intel_incident_artifacts)
            self._connector.save_progress("Created the intelligence incident successfully")
            return status, message
        else:
            return status, message

    def _prepare_intel_incident_container(self, intelligence_incident):
        """
        Create a container from Digital Shadows incident.
        """
        # now = datetime.now()
        container = dict()
        # self._connector.save_progress(" print container: " + str(container))
        container['label'] = self._container_label
        container['name'] = '{} - {}'.format(intelligence_incident.payload['type'].title().replace('_', ' '), unidecode(intelligence_incident.payload['title']))
        intel_incident_desc = unidecode(intelligence_incident.payload['title'])
        # intel_incident_desc = intel_incident_desc.replace( u'\u201c', u'"').replace( u'\u201d', u'"')
        container['description'] = '{}'.format(intel_incident_desc)
        container['custom_fields'] = dict()
        container['custom_fields']['IncidentType'] = str(intelligence_incident.payload['type'])
        if 'subType' in intelligence_incident.payload:
            container['custom_fields']['IncidentSubType'] = str(intelligence_incident.payload['subType'])
        container['custom_fields']['IncidentURL'] = 'https://portal-digitalshadows.com/client/intelligence/incident/{}'.format(intelligence_incident.payload['id'])
        container['severity'] = self._ds_to_phantom_severity_transform(intelligence_incident.payload['severity'])
        container['source_data_identifier'] = intelligence_incident.id
        container['start_time'] = intelligence_incident.payload['published']
        container['ingest_app_id'] = self._connector.get_app_id()
        return container

    def _prepare_intel_incident_artifact(self, container_id, container_severity, intelligence_incident):
        """
        Create an artifact from Digital Shadows Intelligence Incidents.

        :param container_id: int
        :param incident: DS Incident
        :return: dict
        """
        now = datetime.now()
        artifact = dict()
        artifact['container_id'] = container_id
        artifact['label'] = ' '
        artifact['name'] = 'Intelligence Incident details'
        artifact['description'] = 'Details provided by Digital Shadows'
        artifact['severity'] = container_severity
        artifact['type'] = ' '
        artifact['start_time'] = now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        artifact['source_data_identifier'] = intelligence_incident.id
        artifact['run_automation'] = False
        artifact['cef'] = dict()
        artifact['cef']['externalId'] = intelligence_incident.id
        artifact['cef']['deviceAddress'] = 'https://portal-digitalshadows.com/client/intelligence/incident/{}'.format(intelligence_incident.id)
        artifact['cef']['   Title'] = intelligence_incident.payload['title']
        # artifact['cef']['   Type'] = intelligence_incident.payload['type'].title().replace('_', ' ')
        artifact['cef']['deviceEventCategory'] = intelligence_incident.payload['type']
        if 'subType' in intelligence_incident.payload:
            # artifact['cef']['   SubType'] = intelligence_incident.payload['subType'].title().replace('_', ' ')
            artifact['cef']['deviceFacility'] = intelligence_incident.payload['subType']
        artifact['cef']['  Description'] = intelligence_incident.payload['description']
        # artifact['cef']['  Impact'] = intelligence_incident.payload['impactDescription']
        # artifact['cef']['  Mitigation'] = intelligence_incident.payload['mitigation']
        artifact['cef']['  Summary'] = dict()
        # artifact['cef']['  Summary'] = intelligence_incident.payload['entitySummary']
        if 'domain' in intelligence_incident.payload['entitySummary']:
            # artifact['cef']['  Summary']['domain'] = intelligence_incident.payload['entitySummary']['domain']
            artifact['cef']['deviceDnsDomain'] = intelligence_incident.payload['entitySummary']['domain']
        if 'contentRemoved' in intelligence_incident.payload['entitySummary']:
            artifact['cef']['  Summary']['contentRemoved'] = intelligence_incident.payload['entitySummary']['contentRemoved']
        if 'source' in intelligence_incident.payload['entitySummary']:
            artifact['cef']['  Summary']['source'] = intelligence_incident.payload['entitySummary']['source']
        if 'sourceDate' in intelligence_incident.payload['entitySummary']:
            artifact['cef']['  Summary']['sourceDate'] = intelligence_incident.payload['entitySummary']['sourceDate']
        if 'summaryText' in intelligence_incident.payload['entitySummary']:
            artifact['cef']['  Summary']['summaryText'] = intelligence_incident.payload['entitySummary']['summaryText']
        if 'type' in intelligence_incident.payload['entitySummary']:
            # artifact['cef']['  Summary']['type'] = intelligence_incident.payload['entitySummary']['type']
            artifact['cef']['fileType'] = intelligence_incident.payload['entitySummary']['type']

        if 'dataBreach' in intelligence_incident.payload['entitySummary']:
            # artifact['cef']['  Summary']['DataBreach ID'] = intelligence_incident.payload['entitySummary']['dataBreach']['id']
            artifact['cef']['deviceExternalId'] = intelligence_incident.payload['entitySummary']['dataBreach']['id']
        artifact['cef'][' Internal'] = intelligence_incident.payload['internal']
        artifact['cef'][' Restricted'] = intelligence_incident.payload['restrictedContent']
        artifact['cef']['Dates'] = dict()
        if 'alerted' in intelligence_incident.payload:
            artifact['cef']['Dates']['alerted'] = intelligence_incident.payload['alerted']
        artifact['cef']['Dates']['verified'] = intelligence_incident.payload['verified']
        artifact['cef']['Dates']['occurred'] = intelligence_incident.payload['occurred']
        artifact['cef']['Dates']['modified'] = intelligence_incident.payload['modified']
        # artifact['cef']['Dates']['published'] = intelligence_incident.payload['published']
        artifact['cef']['deviceCustomeDate1'] = intelligence_incident.payload['published']

        artifact['cef_types'] = dict()
        artifact['cef_types']['deviceAddress'] = ['url']

        return artifact

    def _save_incident(self, incident):
        container = self._prepare_incident_container(incident)
        status, message, container_id = self._connector.save_container(container)

        if status == phantom.APP_SUCCESS and message != 'Duplicate container found':
            incident_artifacts = self._prepare_incident_artifact(container_id, container['severity'], incident)
            self._connector.save_artifact(incident_artifacts)
            self._connector.save_progress("Created the incident successfully")
            return status, message
        else:
            return status, message

    def _prepare_incident_container(self, incident):
        """
        Create a container from Digital Shadows incident.
        """
        # now = datetime.now()
        container = dict()
        container['label'] = self._container_label
        container['name'] = '{} - {}'.format(incident.payload['type'].title().replace('_', ' '), unidecode(incident.payload['title']))
        incident_desc = unidecode(incident.payload['title'])
        container['description'] = '{}'.format(incident_desc)
        container['custom_fields'] = dict()
        container['custom_fields']['IncidentType'] = str(incident.payload['type'])
        if 'subType' in incident.payload:
            container['custom_fields']['IncidentSubType'] = str(incident.payload['subType'])
        container['custom_fields']['IncidentURL'] = 'https://www.portal-digitalshadows.com/client/incidents/{}'.format(incident.payload['id'])
        container['severity'] = self._ds_to_phantom_severity_transform(incident.payload['severity'])
        container['source_data_identifier'] = incident.id
        container['start_time'] = incident.payload['published']
        container['ingest_app_id'] = self._connector.get_app_id()
        return container

    def _prepare_incident_artifact(self, container_id, container_severity, incident):
        """
        Create an artifact from Digital Shadows Incidents.

        :param container_id: int
        :param incident: DS Incident
        :return: dict
        """
        now = datetime.now()
        artifact = dict()
        artifact['container_id'] = container_id
        artifact['label'] = ' '
        artifact['name'] = 'Incident details'
        artifact['description'] = 'Details provided by Digital Shadows'
        artifact['severity'] = container_severity
        artifact['type'] = ' '
        artifact['start_time'] = now.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        artifact['source_data_identifier'] = incident.id
        artifact['run_automation'] = False
        artifact['cef'] = dict()
        artifact['cef']['externalId'] = incident.id
        artifact['cef']['deviceAddress'] = 'https://www.portal-digitalshadows.com/client/incidents/{}'.format(incident.payload['id'])
        artifact['cef']['   Title'] = incident.payload['title']
        # artifact['cef']['   Type'] = incident.payload['type'].title().replace('_', ' ')
        artifact['cef']['deviceEventCategory'] = incident.payload['type']
        if 'subType' in incident.payload:
            # artifact['cef']['  Sub Type'] = incident.payload['subType'].title().replace('_', ' ')
            artifact['cef']['deviceFacility'] = incident.payload['subType']
        artifact['cef']['  Description'] = incident.payload['description']
        artifact['cef']['  Impact'] = incident.payload['impactDescription']
        artifact['cef']['  Mitigation'] = incident.payload['mitigation']
        artifact['cef']['  Summary'] = dict()
        # artifact['cef']['  Summary'] = incident.payload['entitySummary']
        if 'domain' in incident.payload['entitySummary']:
            artifact['cef']['deviceDnsDomain'] = incident.payload['entitySummary']['domain']
        if 'type' in incident.payload['entitySummary']:
            artifact['cef']['fileType'] = incident.payload['entitySummary']['type']
        if 'contentRemoved' in incident.payload['entitySummary']:
            artifact['cef']['  Summary']['contentRemoved'] = incident.payload['entitySummary']['contentRemoved']
        if 'source' in incident.payload['entitySummary']:
            artifact['cef']['  Summary']['source'] = incident.payload['entitySummary']['source']
        if 'sourceDate' in incident.payload['entitySummary']:
            artifact['cef']['  Summary']['sourceDate'] = incident.payload['entitySummary']['sourceDate']
        if 'summaryText' in incident.payload['entitySummary']:
            artifact['cef']['  Summary']['summaryText'] = incident.payload['entitySummary']['summaryText']
        if 'type' in incident.payload['entitySummary']:
            artifact['cef']['fileType'] = incident.payload['entitySummary']['type']

        if 'dataBreach' in incident.payload['entitySummary']:
            artifact['cef']['deviceExternalId'] = incident.payload['entitySummary']['dataBreach']['id']

        if 'internal' in incident.payload:
            artifact['cef'][' Internal'] = incident.payload['internal']
        if 'restrictedContent' in incident.payload:
            artifact['cef'][' Restricted'] = incident.payload['restrictedContent']
        artifact['cef']['Dates'] = dict()
        if 'alerted' in incident.payload:
            artifact['cef']['Dates']['alerted'] = incident.payload['alerted']
        if 'verified' in incident.payload:
            artifact['cef']['Dates']['verified'] = incident.payload['verified']
        if 'occurred' in incident.payload:
            artifact['cef']['Dates']['occurred'] = incident.payload['occurred']
        if 'modified' in incident.payload:
            artifact['cef']['Dates']['modified'] = incident.payload['modified']
        # artifact['cef']['Dates']['published'] = incident.payload['published']
        artifact['cef']['deviceCustomeDate1'] = incident.payload['published']

        artifact['cef_types'] = dict()
        artifact['cef_types']['deviceAddress'] = ['url']

        return artifact

    def _prepare_container(self, breach):
        """
        Create a container from Digital Shadows Data Breach.

        :param breach: DataBreach
        :return: dict
        """
        container = dict()
        container['label'] = self._container_label
        container['name'] = 'Digital Shadows Data Breach {}'.format(breach.id)
        container['description'] = '{}'.format(breach.incident_title)
        container['severity'] = self._ds_to_phantom_severity_transform(breach.incident_severity)
        container['source_data_identifier'] = breach.id
        container['start_time'] = breach.published
        container['ingest_app_id'] = self._connector.get_app_id()
        return container

    def _prepare_artifact(self, container_id, container_severity, breach, breach_record):
        """
        Create an artifact from Digital Shadows Data Breach Record.

        :param container_id: int
        :param breach: DataBreach
        :param breach_record: DataBreachRecord
        :return: dict
        """
        source_host_name = urlparse(breach.source_url).hostname if breach.source_url is not None else None
        link_to_incident = "{}/client/incidents/{}".format(ds_api_host, breach.incident_id)

        artifact = dict()
        artifact['container_id'] = container_id
        artifact['label'] = self._container_label
        artifact['name'] = 'Digital Shadows Data Breach Record {}'.format(breach_record.id)
        artifact['type'] = 'data breach record'
        artifact['severity'] = container_severity
        artifact['start_time'] = breach_record.published
        artifact['source_data_identifier'] = breach_record.id
        artifact['cef'] = {
            'suser': '{}'.format(breach_record.username),
            'sourceHostName': '{}'.format(source_host_name),
            'cs1Label': 'Password',
            'cs1': '{}'.format(breach_record.password),
            'cs2Label': 'Source Url',
            'cs2': '{}'.format(breach.source_url),
            'cs3Label': 'Link to Incident',
            'cs3': link_to_incident,
            'cn1Label': 'Digital Shadows Incident Id',
            'cn1': '{}'.format(breach.incident_id)
        }
        return artifact

    def _ds_to_phantom_severity_transform(self, severity):
        """
        Map Digital Shadows severity to Phantom severity.

        :param severity: DS Severity: VERY_HIGH, HIGH, MEDIUM, LOW, VERY_LOW, NONE
        :return: Phantom Severity: high, medium, low
        """
        return {
            'VERY_HIGH': 'high',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low',
            'VERY_LOW': 'low',
            'NONE': 'low'
        }.get(severity)
