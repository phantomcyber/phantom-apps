# File: deepsight_connector.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault
import phantom.rules as ph_rules

# Local imports
from deepsight_consts import *

import requests
import json
import os
import tempfile
import shutil
import hashlib


class DeepSightConnector(BaseConnector):
    ACTION_ID_URL_REPUTATION = "url_reputation"
    ACTION_ID_IP_REPUTATION = "ip_reputation"
    ACTION_ID_DOMAIN_REPUTATION = "domain_reputation"
    ACTION_ID_FILE_REPUTATION = "file_reputation"
    ACTION_ID_HUNT_FILE = "hunt_file"
    ACTION_ID_HUNT_EMAIL = "hunt_email"
    ACTION_ID_GET_REPORT = "get_report"
    ACTION_ID_ON_POLL = "on_poll"

    def __init__(self):

        # Call the BaseConnectors init first
        super(DeepSightConnector, self).__init__()
        self._api_key = None
        self._state = {}
        self._download_pdf_config = None
        return

    def initialize(self):

        # Load the state of app at init
        self.load_state()
        config = self.get_config()
        self._api_key = config[DEEPSIGHT_JSON_API_KEY]
        self._download_pdf_config = config.get(DEEPSIGHT_DOWNLOAD_PDF_CONFIG)
        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state of app after each action
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, action_result, accept_header=None, method="get"):

        """ Function that makes the REST call to the device,
            generic function that can be called from various action handlers
        """

        rest_resp = None

        error_resp_dict = {
            DEEPSIGHT_REST_RESP_RESOURCE_INCORRECT: DEEPSIGHT_REST_RESP_RESOURCE_INCORRECT_MSG,
            DEEPSIGHT_REST_RESP_ACCESS_DENIED: DEEPSIGHT_REST_RESP_ACCESS_DENIED_MSG,
            DEEPSIGHT_REST_RESP_LIC_EXCEED: DEEPSIGHT_REST_RESP_LIC_EXCEED_MSG,
            DEEPSIGHT_REST_RESP_OVERLOADED: DEEPSIGHT_REST_RESP_OVERLOADED_MSG
        }

        # get or post or put, whatever the caller asked us to use,
        #    if not specified the default will be 'get'
        try:
            request_func = getattr(requests, method)
        except:
            self.debug_print(DEEPSIGHT_ERR_API_UNSUPPORTED_METHOD.format(method=method))
            # set the action_result status to error, the handler function
            # will most probably return as is
            return (action_result.set_status(phantom.APP_ERROR),
                    rest_resp)

        headers = {
            'API-KEY': self._api_key
        }

        if accept_header:
            headers.update(accept_header)

        # Make the call
        try:
            r = request_func(DEEPSIGHT_BASE_URL + endpoint,
                             headers=headers)
        except Exception as e:
            self.debug_print(DEEPSIGHT_ERR_SERVER_CONNECTION)
            # set the action_result status to error, the handler function
            # will most probably return as is
            return (action_result.set_status(phantom.APP_ERROR, DEEPSIGHT_ERR_SERVER_CONNECTION, e),
                    rest_resp)

        if r.status_code in error_resp_dict:
            self.debug_print(DEEPSIGHT_ERR_FROM_SERVER.format(status=r.status_code,
                                                              detail=error_resp_dict[r.status_code]))
            # set the action_result status to error, the handler function
            # will most probably return as is
            return (action_result.set_status(phantom.APP_ERROR, DEEPSIGHT_ERR_FROM_SERVER, status=r.status_code,
                                             detail=error_resp_dict[r.status_code]),
                    rest_resp)

        # Return code 404 is not considered as failed action.
        # The requested resource is unavailable
        if r.status_code == DEEPSIGHT_REST_RESP_RESOURCE_NOT_FOUND:
            return (phantom.APP_SUCCESS, {DEEPSIGHT_JSON_RESOURCE_NOT_FOUND: True})

        # Try parsing the json, even in the case of an HTTP error the data might
        # contain a json of details 'message'
        try:
            content_type = r.headers['content-type']
            if content_type.find('pdf') != -1:
                rest_resp = r.content
            elif content_type.find('json') != -1:
                rest_resp = r.json()
            else:
                rest_resp = r.text
        except Exception as e:
            # r.text is guaranteed to be NON None, it will be empty,
            # but not None
            msg_string = DEEPSIGHT_ERR_JSON_PARSE.format(raw_text=r.text)
            self.debug_print(msg_string)
            # set the action_result status to error, the handler function
            # will most probably return as is
            return (action_result.set_status(phantom.APP_ERROR, msg_string, e), rest_resp)

        if r.status_code == DEEPSIGHT_REST_RESP_SUCCESS:
            return (phantom.APP_SUCCESS, {DEEPSIGHT_JSON_RESPONSE: rest_resp})

        # see if an error message is present
        message = rest_resp.get('message', DEEPSIGHT_REST_RESP_OTHER_ERROR_MSG)
        self.debug_print(DEEPSIGHT_ERR_FROM_SERVER.format(status=r.status_code, detail=message))
        # All other response codes from Rest call
        # set the action_result status to error, the handler function
        # will most probably return as is
        return (action_result.set_status(phantom.APP_ERROR, DEEPSIGHT_ERR_FROM_SERVER, status=r.status_code,
                                         detail=message),
                rest_resp)

    def _test_connectivity(self, param):

        action_result = ActionResult()
        self.save_progress(DEEPSIGHT_TEST_ENDPOINT)

        return_val, json_resp = self._make_rest_call(DEEPSIGHT_ENDPOINT_USAGE_LIMIT,
                                                     action_result)

        if (phantom.is_fail(return_val)):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, DEEPSIGHT_TEST_CONNECTIVITY_FAIL)
            return action_result.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, DEEPSIGHT_TEST_CONNECTIVITY_PASS)

        return action_result.get_status()

    def _domain_reputation(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        domain = param[DEEPSIGHT_JSON_DOMAIN]

        # Convert URL to domain
        if phantom.is_url(domain):
            domain = phantom.get_host_from_url(domain)

        return_val, resp = self._make_rest_call(DEEPSIGHT_ENDPOINT_DOMAINS.format(domain=domain),
                                                action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_val):
            return action_result.get_status()

        # Resource not found is treated as app success
        if (resp.get(DEEPSIGHT_JSON_RESOURCE_NOT_FOUND)):
            return action_result.set_status(phantom.APP_SUCCESS, DEEPSIGHT_REST_RESP_RESOURCE_NOT_FOUND_MSG)

        json_resp = resp.get(DEEPSIGHT_JSON_RESPONSE)

        action_result.add_data(json_resp)

        if 'reputation' in json_resp:
            summary_data['reputation'] = json_resp['reputation']
        if 'confidence' in json_resp:
            summary_data['confidence'] = json_resp['confidence']
        if 'hostility' in json_resp:
            summary_data['hostility'] = json_resp['hostility']
        if 'whitelisted' in json_resp:
            summary_data['whitelisted'] = json_resp['whitelisted']
        if 'lastSeen' in json_resp:
            summary_data['last_seen'] = json_resp['lastSeen']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _file_reputation(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        filehash = param[DEEPSIGHT_JSON_FILE]

        return_val, resp = self._make_rest_call(DEEPSIGHT_ENDPOINT_FILEHASH.format(hash=filehash),
                                                action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_val):
            return action_result.get_status()

        # Resource not found is treated as app success
        if (resp.get(DEEPSIGHT_JSON_RESOURCE_NOT_FOUND)):
            return action_result.set_status(phantom.APP_SUCCESS, DEEPSIGHT_REST_RESP_RESOURCE_NOT_FOUND_MSG)

        json_resp = resp.get(DEEPSIGHT_JSON_RESPONSE)

        action_result.add_data(json_resp)

        if 'reputation' in list(json_resp.keys()):
            summary_data['reputation'] = json_resp['reputation']
        if 'matiReports' in list(json_resp.keys()):
            summary_data['total_reports'] = len(json_resp['matiReports'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _url_reputation(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        url = param[DEEPSIGHT_JSON_URL]

        return_val, resp = self._make_rest_call(DEEPSIGHT_ENDPOINT_URL.format(url=url),
                                                action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_val):
            return action_result.get_status()

        # Resource not found is treated as app success
        if (resp.get(DEEPSIGHT_JSON_RESOURCE_NOT_FOUND)):
            return action_result.set_status(phantom.APP_SUCCESS, DEEPSIGHT_REST_RESP_RESOURCE_NOT_FOUND_MSG)

        json_resp = resp.get(DEEPSIGHT_JSON_RESPONSE)

        action_result.add_data(json_resp)

        if 'whitelisted' in list(json_resp.keys()):
            summary_data['whitelisted'] = json_resp['whitelisted']
        if 'lastSeen' in list(json_resp.keys()):
            summary_data['last_seen'] = json_resp['lastSeen']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _ip_reputation(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        ip = param[DEEPSIGHT_JSON_IP]

        return_val, resp = self._make_rest_call(DEEPSIGHT_ENDPOINT_IP.format(ip=ip),
                                                action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_val):
            return action_result.get_status()

        # Resource not found is treated as app success
        if (resp.get(DEEPSIGHT_JSON_RESOURCE_NOT_FOUND)):
            return action_result.set_status(phantom.APP_SUCCESS, DEEPSIGHT_REST_RESP_RESOURCE_NOT_FOUND_MSG)

        json_resp = resp.get(DEEPSIGHT_JSON_RESPONSE)

        action_result.add_data(json_resp)

        if 'reputationValues' in list(json_resp.keys()):
            rep_val_dict = json_resp['reputationValues']
            if 'reputation' in list(rep_val_dict.keys()):
                summary_data['reputation'] = rep_val_dict['reputation']
            if 'confidence' in list(rep_val_dict.keys()):
                summary_data['confidence'] = rep_val_dict['confidence']
            if 'hostility' in list(rep_val_dict.keys()):
                summary_data['hostility'] = rep_val_dict['hostility']

        if 'whitelisted' in list(json_resp.keys()):
            summary_data['whitelisted'] = json_resp['whitelisted']
        if 'lastSeen' in list(json_resp.keys()):
            summary_data['last_seen'] = json_resp['lastSeen']

        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        filehash = param[DEEPSIGHT_JSON_FILE]

        return_val, resp = self._make_rest_call(DEEPSIGHT_ENDPOINT_MATI_FILE.format(hash=filehash),
                                                action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_val):
            return action_result.get_status()

        # Resource not found is treated as app success
        if (resp.get(DEEPSIGHT_JSON_RESOURCE_NOT_FOUND)):
            return action_result.set_status(phantom.APP_SUCCESS, DEEPSIGHT_REST_RESP_RESOURCE_NOT_FOUND_MSG)

        json_resp = resp.get(DEEPSIGHT_JSON_RESPONSE)

        # Fetching report data and summary for each report id
        for mati_report in json_resp:
            mati_report_id = mati_report['id']
            # Fetch detailed report
            rep_return_val, rep_resp = self._make_rest_call(
                DEEPSIGHT_ENDPOINT_MATI_REPORT.format(mati_id=mati_report_id),
                action_result)

            # Something went wrong with the request
            if phantom.is_fail(rep_return_val):
                return action_result.get_status()

            if (rep_resp.get(DEEPSIGHT_JSON_RESPONSE)):
                rep_json_resp = rep_resp[DEEPSIGHT_JSON_RESPONSE]
                mati_report[DEEPSIGHT_JSON_REPORT_DATA] = rep_json_resp

            # Add individual report data to action_result
            action_result.add_data(mati_report)

        summary_data['total_reports'] = len(json_resp)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _hunt_email(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        email = param[DEEPSIGHT_JSON_EMAIL]

        return_val, resp = self._make_rest_call(DEEPSIGHT_ENDPOINT_MATI_EMAIL.format(email=email),
                                                action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_val):
            return action_result.get_status()

        # Resource not found is treated as app success
        if (resp.get(DEEPSIGHT_JSON_RESOURCE_NOT_FOUND)):
            return action_result.set_status(phantom.APP_SUCCESS, DEEPSIGHT_REST_RESP_RESOURCE_NOT_FOUND_MSG)

        json_resp = resp.get(DEEPSIGHT_JSON_RESPONSE)

        # Fetching report data for each report id
        for mati_report in json_resp:
            mati_report_id = mati_report['id']
            # Fetch detailed report
            rep_return_val, rep_resp = self._make_rest_call(
                DEEPSIGHT_ENDPOINT_MATI_REPORT.format(mati_id=mati_report_id),
                action_result)

            # Something went wrong with the request
            if phantom.is_fail(rep_return_val):
                return action_result.get_status()

            if (rep_resp.get(DEEPSIGHT_JSON_RESPONSE)):
                rep_json_resp = rep_resp.get(DEEPSIGHT_JSON_RESPONSE)
                mati_report[DEEPSIGHT_JSON_REPORT_DATA] = rep_json_resp

            # Add individual report data to action_result
            action_result.add_data(mati_report)

        summary_data['total_reports'] = len(json_resp)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_report(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Getting mandatory input params
        mati_id = param[DEEPSIGHT_JSON_MATI_ID]

        return_val, resp = self._make_rest_call(DEEPSIGHT_ENDPOINT_MATI_REPORT.format(mati_id=mati_id),
                                                action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_val):
            return action_result.get_status()

        # Resource not found is treated as app success
        if (resp.get(DEEPSIGHT_JSON_RESOURCE_NOT_FOUND)):
            return action_result.set_status(phantom.APP_SUCCESS, DEEPSIGHT_REST_RESP_RESOURCE_NOT_FOUND_MSG)

        json_resp = resp.get(DEEPSIGHT_JSON_RESPONSE)

        # Fetching summary data
        summ_return_val, summ_resp = self._make_rest_call(
            DEEPSIGHT_ENDPOINT_MATI_REPORT_SUMMARY.format(mati_id=mati_id),
            action_result)

        # Something went wrong with the request
        if phantom.is_fail(summ_return_val):
            return action_result.get_status()

        if (summ_resp.get(DEEPSIGHT_JSON_RESPONSE)):
            summ_json_resp = summ_resp.get(DEEPSIGHT_JSON_RESPONSE)
            json_resp[DEEPSIGHT_JSON_REPORT_SUMMARY_DATA] = summ_json_resp
            summary_data['summary_title'] = summ_json_resp['title']

        action_result.add_data(json_resp)

        # Download pdf and save to vault if enabled
        if param.get(DEEPSIGHT_JSON_DOWNLOAD_REPORT, False):
            download_ret_value = self._download_report_pdf(mati_id, self.get_container_id(), action_result,
                                                           summary_data)
            # Something went wrong with the request
            if phantom.is_fail(download_ret_value):
                return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to ingest reports data into phantom
    def _on_poll(self, param):

        config = self.get_config()
        action_result = self.add_action_result(ActionResult(dict(param)))
        max_containers = None
        last_report_id = None
        report_list = None

        # Getting optional parameters
        container_id = param.get(DEEPSIGHT_JSON_CONTAINER_ID)
        poll_now_max_count = int(
            param.get(phantom.APP_JSON_CONTAINER_COUNT, DEEPSIGHT_DEFAULT_POLL_NOW_CONTAINER_COUNT))
        first_ingestion_count = int(config.get(DEEPSIGHT_JSON_FIRST_INGEST_COUNT, DEEPSIGHT_DEFAULT_FIRST_INGEST_COUNT))

        if self.is_poll_now():
            # Splitting the report ids comma separated
            if container_id:
                report_list = container_id.split(',')

            self.save_progress("Ignoring the maximum artifacts count")
            max_containers = poll_now_max_count

        else:
            if self._state.get('first_run', True):
                self._state['first_run'] = False
                max_containers = first_ingestion_count

            last_report_id = self._state.get(DEEPSIGHT_JSON_LAST_REPORT_ID)

        self.save_progress("Getting list of available reports")

        ret_val, list_reports_data = self._get_report_updates(last_report_id, report_list, max_containers,
                                                              action_result=action_result)

        # Something went wrong with the request
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for report_data in list_reports_data:
            self.send_progress("Ingesting data for report id {report}", report=report_data['id'])
            ingest_ret_val = self._ingest_report_data(report_data)

            # Something went wrong while ingesting data
            # Continue to the next report data
            if phantom.is_fail(ingest_ret_val):
                continue

            # Updating the last_report_id after ingesting report data
            # in case of scheduled ingestion
            if not self.is_poll_now():
                if report_data['id'] > self._state.get(DEEPSIGHT_JSON_LAST_REPORT_ID, 0):
                    self._state[DEEPSIGHT_JSON_LAST_REPORT_ID] = report_data['id']

        if not list_reports_data:
            self.save_progress("No new or matching reports found")

        return action_result.set_status(phantom.APP_SUCCESS)

    # Function to create containers and artifacts
    def _ingest_report_data(self, report_data):

        # Not adding action_result to base connector, use this object for rest calls only
        # even if individual report ingestion fails, ingestion should continue for other reports
        action_result = ActionResult()
        # Not adding summary_data to action_result of base connector
        # use this object for download pdf function call
        summary_data = {}

        container = {}

        # Getting report details
        return_val, resp = self._make_rest_call(DEEPSIGHT_ENDPOINT_MATI_REPORT.format(mati_id=report_data['id']),
                                                action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_val):
            self.debug_print(DEEPSIGHT_REPORT_ERROR.format(report=report_data['id'],
                                                           message=action_result.get_message()))
            self.save_progress(DEEPSIGHT_REPORT_ERROR, report=report_data['id'], message=action_result.get_message())
            return action_result.get_status()

        if (resp.get(DEEPSIGHT_JSON_RESOURCE_NOT_FOUND)):
            return phantom.APP_SUCCESS

        report_detail = resp.get(DEEPSIGHT_JSON_RESPONSE)

        container["name"] = report_data['title']
        container['data'] = report_detail
        container['description'] = 'Report ID {report}'.format(report=str(report_data['id']))
        container['source_data_identifier'] = str(report_data['id'])

        ret_val, response, container_id = self.save_container(container)

        # Create Report Artifact with report id
        self._create_report_artifact(str(report_data['id']), container_id)

        # Something went wrong while creating container
        if phantom.is_fail(ret_val):
            self.debug_print(DEEPSIGHT_CONTAINER_ERROR.format(report=report_data['id']), response)
            self.save_progress(DEEPSIGHT_CONTAINER_ERROR, report=report_data['id'])
            return action_result.set_status(phantom.APP_ERROR)

        # Create File Artifacts
        self._create_file_artifacts(report_detail, container_id)

        # Get Discrete entities ip, url, domain and email
        discrete_urls, discrete_ips, discrete_domains, discrete_emails = self._get_descrete_entities(report_detail)

        # Create URL Artifacts
        self._create_url_artifacts(discrete_urls, container_id)

        # Create IP Artifacts
        self._create_ip_artifacts(discrete_ips, container_id)

        # Create Domain Artifacts
        self._create_domain_artifacts(discrete_domains, container_id)

        # Create Email Artifacts
        self._create_email_artifacts(discrete_emails, container_id)

        # Download report pdf if enabled
        # Save the pdf to vault
        if self._download_pdf_config:
            # Fetching summary data
            summ_return_val, summ_resp = self._make_rest_call(
                DEEPSIGHT_ENDPOINT_MATI_REPORT_SUMMARY.format(mati_id=report_data['id']),
                action_result)

            # Something went wrong with the request
            if phantom.is_fail(summ_return_val):
                self.debug_print(DEEPSIGHT_REPORT_PDF_ERROR.format(report=report_data['id'],
                                                                   message=action_result.get_message()))
                self.save_progress(DEEPSIGHT_REPORT_PDF_ERROR, report=report_data['id'],
                                   message=action_result.get_message())
                return action_result.get_status()

            if summ_resp.get(DEEPSIGHT_JSON_RESPONSE):
                summ_report_detail = summ_resp.get(DEEPSIGHT_JSON_RESPONSE)
                report_detail[DEEPSIGHT_JSON_REPORT_SUMMARY_DATA] = summ_report_detail

            action_result.add_data(report_detail)

            download_ret_value = self._download_report_pdf(report_data['id'], container_id,
                                                           action_result, summary_data)

            if phantom.is_fail(download_ret_value):
                return action_result.get_status()

        return phantom.APP_SUCCESS

    # This function fetches descrete entities from report details
    # Discrete Entities - ip, domain, url and email
    def _get_descrete_entities(self, report_detail):

        discrete_urls = set()
        discrete_ips = set()
        discrete_domains = set()
        discrete_emails = set()

        for report_key in ['files', 'ips', 'domains', 'emails']:
            for report_entity in report_detail.get(report_key, []):
                for url in report_entity.get('relatedUrls', []):
                    discrete_urls.add(url)
                for ip in report_entity.get('relatedIps', []):
                    discrete_ips.add(ip)
                if report_entity.get('ip'):
                    discrete_ips.add(report_entity['ip'])
                for domain in report_entity.get('relatedDomains', []):
                    discrete_domains.add(domain)
                if report_entity.get('domain'):
                    discrete_domains.add(report_entity['domain'])
                if report_entity.get('from'):
                    discrete_emails.add(report_entity['from'])

        return discrete_urls, discrete_ips, discrete_domains, discrete_emails

    # This function creates report artifact
    def _create_report_artifact(self, report_id, container_id):
        cef = {'deepsightReportId': report_id}
        cef_types = {'deepsightReportId': ['deepsight report id']}
        self._create_artifact(container_id, 'Report Artifact', cef, cef_types)

    # This function creates artifacts for url
    def _create_url_artifacts(self, discrete_urls, container_id):

        for url in discrete_urls:
            cef = {}
            cef_types = {}
            cef['requestURL'] = url
            cef_types['requestURL'] = ['url']
            self._create_artifact(container_id, 'URL Artifact', cef, cef_types)

    # This function creates artifacts for ip
    def _create_ip_artifacts(self, discrete_ips, container_id):

        for ip in discrete_ips:
            cef = {}
            cef_types = {}
            cef['deviceAddress'] = ip
            cef_types['deviceAddress'] = ['ip']
            self._create_artifact(container_id, 'IP Artifact', cef, cef_types)

    # This function creates artifacts for domain
    def _create_domain_artifacts(self, discrete_domains, container_id):

        for domain in discrete_domains:
            cef = {}
            cef_types = {}
            cef['deviceHostName'] = domain
            cef_types['deviceHostName'] = ['domain']
            self._create_artifact(container_id, 'Domain Artifact', cef, cef_types)

    # This function creates artifacts for email
    def _create_email_artifacts(self, discrete_emails, container_id):

        for email in discrete_emails:
            cef = {}
            cef_types = {}
            cef['emailAddress'] = email
            cef_types['emailAddress'] = ['email']
            self._create_artifact(container_id, 'Email Address Artifact', cef, cef_types)

    # This function parses the file data from list of file data
    # and creates File Artifact in the container
    # Each File Artifact contains all the related file hashes
    def _create_file_artifacts(self, report_detail, container_id):

        # Iterate each email data for fileHashes
        for email in report_detail.get('emails', []):
            cef = {}
            cef_types = {}

            discrete_email_md5 = set()
            discrete_email_sha256 = set()
            for filehash in email.get('relatedFileHashes', []):
                if phantom.is_md5(filehash):
                    discrete_email_md5.add(filehash)
                if phantom.is_sha256(filehash):
                    discrete_email_sha256.add(filehash)

            # Create cefs for each filehash found in emails
            for md5 in discrete_email_md5:
                cef['fileHashMd5'] = md5
                cef_types['fileHashMd5'] = ['hash', 'md5']

            for sha256 in discrete_email_sha256:
                cef['fileHashSha256'] = sha256
                cef_types['fileHashSha256'] = ['hash', 'sha256']

            if cef:
                self._create_artifact(container_id, 'File Artifact', cef, cef_types)

        # Iterate each file data
        for file_data in report_detail.get('files', []):
            cef = {}
            cef_types = {}

            # Create a set of unique md5 and sha256 hash to be added as cef in artifact
            discrete_md5 = set()
            discrete_sha256 = set()

            # Getting all the md5 from file_data
            if file_data.get('md5'):
                discrete_md5.add(file_data['md5'])
            for parentmd5 in file_data.get('parentMd5s', []):
                discrete_md5.add(parentmd5)
            for parentmd5 in file_data.get('childMd5s', []):
                discrete_md5.add(parentmd5)

            # Getting all the sha256 from file_data
            if file_data.get('sha256'):
                discrete_sha256.add(file_data['sha256'])

            # Create md5 cefs
            for md5 in discrete_md5:
                cef['fileHashMd5'] = md5
                cef_types['fileHashMd5'] = ['hash', 'md5']

            # Create sha256 cefs
            for sha256 in discrete_sha256:
                cef['fileHashSha256'] = sha256
                cef_types['fileHashSha256'] = ['hash', 'sha256']

            # Adding file size
            if file_data.get('size'):
                cef['fileSize'] = file_data['size']

            # Create file name cefs
            # Create a new artifact for each file name
            for file_name in file_data.get('filename', []):
                # Create copy of cef and cef_types to be re-used for
                # each file name
                file_cef = cef.copy()
                file_cef_types = cef_types.copy()
                file_cef['fileName'] = file_name
                file_cef_types['fileName'] = ['file name']
                self._create_artifact(container_id, 'File Artifact', file_cef, file_cef_types)

            # Create Artifact without filename cef if not present
            if not file_data.get('filename'):
                self._create_artifact(container_id, 'File Artifact', cef, cef_types)

    # This function saves artifacts
    # Creates cef as provided in input
    def _create_artifact(self, container_id, artifact_name, cef, cef_types):

        artifact = {}
        artifact['description'] = DEEPSIGHT_ARTIFACTS_DESC
        artifact["cef_types"] = cef_types
        artifact['name'] = artifact_name
        artifact['cef'] = cef
        artifact['container_id'] = container_id
        artifact['source_data_identifier'] = self._create_dict_hash(artifact)

        ret_val, status_string, artifact_id = self.save_artifact(
            artifact)

        # Something went wrong while creating artifacts
        # In case of error while saving artifact
        # continue with the next artifact. Dont return to helper function
        if phantom.is_fail(ret_val):
            self.debug_print(DEEPSIGHT_ARTIFACTS_ERROR, artifact)
            self.save_progress(DEEPSIGHT_ARTIFACTS_ERROR)

    # This function gets the list of reports depending on the last_report_id
    def _get_report_updates(self, last_report_id, report_id_list, max_reports_cnt, action_result):

        list_report_updates = None

        return_val, resp = self._make_rest_call(DEEPSIGHT_ENDPOINT_MATI_REPORT_LIST, action_result)

        # Something went wrong with the request
        if phantom.is_fail(return_val):
            return action_result.get_status(), list_report_updates

        # Resource not found treated as app success
        if (resp.get(DEEPSIGHT_JSON_RESOURCE_NOT_FOUND)):
            return phantom.APP_SUCCESS, list_report_updates

        json_resp = resp.get(DEEPSIGHT_JSON_RESPONSE, [])
        # Sorting the list of reports based on
        json_resp.sort(key=lambda x: x['id'])
        list_report_updates = json_resp

        # If container id provided, fetch specific report ids
        if report_id_list:
            # Stripping whitespaces
            report_id_list = [x.strip() for x in report_id_list]
            self.save_progress(DEEPSIGHT_INGEST_CONTAINER_ID, container=report_id_list)
            list_report_updates = [x for x in json_resp if str(x['id']) in report_id_list]

        elif last_report_id:
            self.save_progress(DEEPSIGHT_INGEST_LATEST_REPORT_ID, report=last_report_id)
            list_report_updates = [x for x in json_resp if x['id'] > int(last_report_id)]

        # Fetch last {max_reports_cnt} reports
        if max_reports_cnt:
            list_report_updates = list_report_updates[-max_reports_cnt:]

        return phantom.APP_SUCCESS, list_report_updates

    def _download_report_pdf(self, report_id, container_id, action_result, summary_data):

        file_name = 'deepsight_report_{}.pdf'.format(report_id)

        self.send_progress(DEEPSIGHT_MSG_DOWNLOADING_REPORT)

        pdf_accept_headers = {
            "Accept": "application/pdf"
        }

        return_val, resp = self._make_rest_call(DEEPSIGHT_ENDPOINT_MATI_REPORT_PDF.format(mati_id=report_id),
                                                action_result, accept_header=pdf_accept_headers)

        # Something went wrong with the request
        if phantom.is_fail(return_val):
            return action_result.get_status()

        # Generate pdf from response content
        if (resp.get(DEEPSIGHT_JSON_RESPONSE)):
            pdf_resp = resp.get(DEEPSIGHT_JSON_RESPONSE)
            temp_dir = tempfile.mkdtemp()
            file_path = os.path.join(temp_dir, file_name)
            with open(file_path, 'wb') as fw:
                fw.write(pdf_resp)

            # Check if the report pdf with same file name is already available in vault
            success, message, vault_list = ph_rules.vault_info(vault_id=None, file_name=None, container_id=container_id)
            # Iterate through each vault item in the container and compare name and size of file
            for vault in vault_list:
                if vault.get('name') == file_name and vault.get('size') == os.path.getsize(file_path):
                    self.send_progress(DEEPSIGHT_REPORT_PDF_ALREADY_AVAILABLE)
                    vault_details = {}
                    vault_details[phantom.APP_JSON_SIZE] = vault.get('size')
                    vault_details[phantom.APP_JSON_TYPE] = DEEPSIGHT_REPORT_FILE_TYPE
                    vault_details[phantom.APP_JSON_CONTAINS] = [DEEPSIGHT_REPORT_FILE_TYPE]
                    vault_details[phantom.APP_JSON_ACTION_NAME] = self.get_action_name()
                    vault_details[phantom.APP_JSON_APP_RUN_ID] = self.get_app_run_id()
                    vault_details[phantom.APP_JSON_VAULT_ID] = vault.get('vault_id')
                    vault_details[DEEPSIGHT_JSON_REPORT_FILE_NAME] = file_name
                    json_data = action_result.get_data()
                    json_data[0].update({'vault': vault_details})
                    summary_data.update({'vault_id': vault.get('vault_id')})
                    summary_data['pdf_availability'] = True
                    return phantom.APP_SUCCESS

            ret_val = self._move_file_to_vault(container_id, os.path.getsize(file_path),
                                               DEEPSIGHT_REPORT_FILE_TYPE, file_path,
                                               action_result, summary_data)
            shutil.rmtree(temp_dir)

            # Something went wrong while moving file to vault
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            summary_data['pdf_availability'] = True

        else:
            # If pdf not available, treated as app success
            self.send_progress(DEEPSIGHT_REPORT_PDF_UNAVAILABLE)
            summary_data['pdf_availability'] = False

        return phantom.APP_SUCCESS

    def _move_file_to_vault(self, container_id, file_size, type_str, local_file_path, action_result, summary_data):

        self.send_progress(phantom.APP_PROG_ADDING_TO_VAULT)
        vault_details = {}

        if not file_size:
            file_size = os.path.getsize(local_file_path)

        vault_details[phantom.APP_JSON_SIZE] = file_size
        vault_details[phantom.APP_JSON_TYPE] = type_str
        vault_details[phantom.APP_JSON_CONTAINS] = [type_str]
        vault_details[phantom.APP_JSON_ACTION_NAME] = self.get_action_name()
        vault_details[phantom.APP_JSON_APP_RUN_ID] = self.get_app_run_id()

        file_name = os.path.basename(local_file_path)
        # Adding report pdf to vault
        vault_ret_dict = Vault.add_attachment(local_file_path, container_id, file_name, vault_details)
        self.send_progress(DEEPSIGHT_SUCC_FILE_ADD_TO_VAULT, vault_id=vault_ret_dict[phantom.APP_JSON_HASH])

        # Updating report data with vault details
        if vault_ret_dict['succeeded']:
            vault_details[phantom.APP_JSON_VAULT_ID] = vault_ret_dict[phantom.APP_JSON_HASH]
            vault_details[DEEPSIGHT_JSON_REPORT_FILE_NAME] = file_name
            json_data = action_result.get_data()
            json_data[0].update({'vault': vault_details})
            summary_data.update({'vault_id': vault_ret_dict[phantom.APP_JSON_HASH]})

            return phantom.APP_SUCCESS

        # Error while adding report pdf to vault
        self.debug_print('ERROR: Adding file to vault:', vault_ret_dict)
        action_result.append_to_message('. ' + vault_ret_dict['message'])

        # set the action_result status to error, the handler function
        # will most probably return as is
        return action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT)

    def _create_dict_hash(self, input_dict):

        input_dict_str = None

        if (not input_dict):
            return None

        try:
            input_dict_str = json.dumps(input_dict, sort_keys=True).encode('utf-8')
        except Exception as e:
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str).hexdigest()

    def handle_action(self, param):

        action = self.get_action_identifier()
        return_val = phantom.APP_SUCCESS

        if action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            return_val = self._test_connectivity(param)

        elif action == self.ACTION_ID_DOMAIN_REPUTATION:
            return_val = self._domain_reputation(param)

        elif action == self.ACTION_ID_FILE_REPUTATION:
            return_val = self._file_reputation(param)

        elif action == self.ACTION_ID_URL_REPUTATION:
            return_val = self._url_reputation(param)

        elif action == self.ACTION_ID_IP_REPUTATION:
            return_val = self._ip_reputation(param)

        elif action == self.ACTION_ID_HUNT_FILE:
            return_val = self._hunt_file(param)

        elif action == self.ACTION_ID_HUNT_EMAIL:
            return_val = self._hunt_email(param)

        elif action == self.ACTION_ID_GET_REPORT:
            return_val = self._get_report(param)

        elif action == self.ACTION_ID_ON_POLL:
            return_val = self._on_poll(param)

        return return_val


if __name__ == '__main__':
    import sys
    import pudb

    pudb.set_trace()
    if len(sys.argv) < 2:
        print('No test json specified as input')
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = DeepSightConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
