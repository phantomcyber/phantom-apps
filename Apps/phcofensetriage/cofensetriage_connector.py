# File: cofensetriage_connector.py
# Copyright (c) 2020-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
# Phantom App imports
import phantom.app as phantom
import phantom.rules as ph_rules
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

import requests
import json
import tempfile
import default_timezones
import dateutil.parser
import calendar
from bs4 import BeautifulSoup
from datetime import timedelta
from cofensetriage_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CofenseTriageConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CofenseTriageConnector, self).__init__()

        self._state = None
        self._action_result = None
        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = ERROR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERROR_CODE_MSG
                error_msg = ERROR_MSG_UNAVAILABLE
        except:
            error_code = ERROR_CODE_MSG
            error_msg = ERROR_MSG_UNAVAILABLE

        try:
            if error_code in ERROR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(
                    error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing error message")
            error_text = PARSE_ERR_MSG

        return error_text

    def _validate_integer(self, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return "Please provide a valid integer value in the {}".format(key), None

                parameter = int(parameter)
            except:
                return "Please provide a valid integer value in the {}".format(key), None

            if parameter < 0:
                return "Please provide a valid non-negative integer value in the {}".format(key), None

        return True, parameter

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Status Code: {0}. Empty response and no information in the header".format(response.status_code)), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
            message = 'Status Code: {0}. Data from server:\n{1}\n'.format(status_code, error_text)
            message = message.replace('{', '{{').replace('}', '}}')
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            message = "Status Code: {0}. Error occurred while parsing the error details in the data from server. Error: {1}".format(
                status_code, err)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(err)), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # preempt adding binary downloads to debug data
        if int(r.status_code) == 200 and (r.headers.get('Content-Transfer-Encoding') == "binary" or r.headers.get('Content-Type') == "application/octet-stream"):
            return RetVal(phantom.APP_SUCCESS, r.content)

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        if not isinstance(kwargs.get('headers'), dict):
            kwargs['headers'] = dict()
        kwargs['headers'].update({
            "Authorization": self._auth_string,
            "Accept": "application/json"
        })

        # Create a URL to connect to
        # handle cases which is missing the api.
        if 'api/' not in endpoint:
            url = "{0}/api/public/v1/{1}".format(self._base_url, endpoint.strip().strip('/'))
        else:
            url = "{0}{1}".format(self._base_url, endpoint)

        action_result.update_summary({'requests_url': url})
        action_result.update_summary({'requests_params': kwargs.get('params')})

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            r = request_func(
                url,
                verify=self._verify,
                **kwargs)
            self._r = r
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            if "token" in err:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error connecting to server. Please check the parameters"), resp_json)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. {0}".format(err)), resp_json)
        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = CONNECTION_TEST_ENDPOINT
        self.save_progress("Connecting to endpoint")
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    # this is quick and dirty utility function. It is expected to abend if "definition" is not the expected dict(). Don't abuse it.

    def _determine_value(self, definition, search, category, return_none=False):
        if search is None:
            if return_none:
                return True, None
            else:
                return "Error: invalid value passed {}; entered value: {}".format(category if category else "", search), None
        search = str(search).strip().lower().replace('_', ' ').replace('-', ' ')
        for k, v in list(definition.items()):
            if search in v:
                return True, None if k == "_none_" else k
        return "Error: invalid value passed {}; entered value: {}".format(category if category else "", search), None

    def _remap_cef(self, cef=None, cef_mapping=None):

        if not cef or not isinstance(cef, dict):
            return dict()

        if not cef_mapping or not isinstance(cef_mapping, dict):
            return cef.copy()

        newcef = dict()
        for key, value in list(cef.items()):
            newkey = cef_mapping.get(key, key)
            newcef[newkey] = value

        return newcef

    def _parse_datetime(self, datestring, category=""):

        if datestring is None:
            return True, None

        # *** always default into utc if timezone is not specified ***
        # default_time = dateutil.parser.parse("00:00Z").replace(tzinfo=dateutil.tz.tzlocal())
        default_time = dateutil.parser.parse("00:00Z")
        tzinfos = default_timezones.timezones()
        try:
            dt = dateutil.parser.parse(
                datestring.upper(), tzinfos=tzinfos, default=default_time, fuzzy=True)
            utcdt = dt.astimezone(dateutil.tz.tzutc())
            return True, {
                'datetime': utcdt,
                'epoch': calendar.timegm(utcdt.timetuple()),
                'iso': utcdt.isoformat(),
                'date': utcdt.strftime("%a %b %d %H:%M:%S %Y %Z %z")
            }
        except:
            return "Error: invalid date/time string passed for parsing {}; entered value: {}".format(category if category else "", datestring), None

    def _get_user_info(self):

        url = "{}{}".format(self._get_phantom_base_url().strip('/'), "/rest/user_info")
        r = requests.get(url, verify=False)
        try:
            ret_val = r.json()
        except:
            ret_val = {'message': r.text}

        if int(r.status_code) != 200:
            return "Error: failed to get user_info; {}".format(ret_val.get('message', "REST error")), None

        return True, ret_val

    def _validate_label(self, label=None):

        if not label:
            return True, None

        if not self._user_info:
            ret_val, self._user_info = self._get_user_info()
            if ret_val is not True:
                return ret_val, None

        if 'labels' not in self._user_info:
            return "Error: labels data not in user_info", None

        if label not in self._user_info['labels']:
            return "Error: label not valid; entered value: {}".format(label), None

        return True, label

    def _validate_tenant(self, tenant=None):

        if tenant is None:
            return True, None

        tenant = tenant.lower()

        if not self._user_info:
            ret_val, self._user_info = self._get_user_info()
            if ret_val is not True:
                return ret_val, None

        if 'tenants' not in self._user_info:
            return "Error: tenant data not in user_info", None

        for x in self._user_info['tenants']:
            if tenant == str(x['name']).lower() or tenant == str(x['id']):
                return True, x['name']

        return "Error: tenant not valid; entered value: {}".format(tenant), None

    def _associate_container_ids(self, data=None, stats=None):

        if not data or not stats:
            return

        for x in data:
            for y in stats:
                if int(x['id']) == (y['ingest_id']):
                    x['container_id'] = y.get('container_id')
                    break

    def _save_artifact(self, artifact=None):

        if not artifact:
            return "Error: unable to save artifact; artifact details not provided", None

        url = "{}{}".format(self._get_phantom_base_url().strip('/'), "/rest/artifact")
        r = requests.post(url, json.dumps(artifact), verify=False)

        try:
            ret_val = r.json()
        except:
            ret_val = {'message': r.text}

        existing_artifact_id = ret_val.get('existing_artifact_id', False)
        if existing_artifact_id:
            return "existing_artifact_id", existing_artifact_id

        if int(r.status_code) != 200 or ret_val.get('success') is not True:
            return "Error: failed to save artifact; {}".format(ret_val.get('message', "REST Error")), None

        return True, ret_val['id']

    def _save_email_artifact(self, source_data_identifier=None, filename=None, content=None):

        if not source_data_identifier or not filename or not content:
            return "Error: one or more arguments are null value", None, None

        ret_val, artifact_id = self._save_artifact(artifact={
            'name': "Email Artifact",
            'source_data_identifier': source_data_identifier,
            'container_id': self.get_container_id(),
            'type': "email",
            'cef': {
                '_raw_email': content.decode("utf-8"),
                'filename': filename,
            }
        })

        # is a duplicated artifact a success?
        if ret_val is not True and ret_val != "existing_artifact_id":
            return ret_val, None, None
        if ret_val == "existing_artifact_id":
            self.save_progress("Notice: duplicated artifact; {}".format(artifact_id))

        summary = {
            'artifact_id': artifact_id,
            'filename': filename,
        }

        data = summary.copy()
        data['size'] = len(content)

        return True, summary, data

    def _vault_file(self, filename=None, content=None, makeartifact=False):

        if not filename or not content:
            return "Error: one or more arguments are null value", None, None

        if hasattr(Vault, 'get_vault_tmp_dir'):
            tmp = tempfile.NamedTemporaryFile(mode="wb", dir=Vault.get_vault_tmp_dir(), delete=False)
        else:
            tmp = tempfile.NamedTemporaryFile(mode="wb", dir=PHANTOM_VAULT_DIR, delete=False)

        tmp.write(content)
        tmp.close()

        try:
            # Adding file to vault
            success, _, vault_id = ph_rules.vault_add(file_location=tmp.name, container=self.get_container_id(), file_name=filename)
        except:
            return "Error: Unable to add the file to vault", None, None

        if not success:
            return "Error: Unable to add the file to vault", None, None

        try:
            _, _, fileinfo = ph_rules.vault_info(vault_id=vault_id, container_id=self.get_container_id())
            fileinfo = list(fileinfo)
        except:
            return "Error: Vault file error, newly vaulted file not found; {}".format(vault_id), None, None

        if len(fileinfo) == 0:
            return "Error: Vault file error, newly vaulted file not found; {}".format(vault_id), None, None
        fileinfo = fileinfo[0]

        summary = {
            'vault_id': vault_id,
            'filename': filename,
        }

        data = {
            'vault_id': vault_id,
            'filename': fileinfo['name'],
            'size': fileinfo['size'],
            'sha1': fileinfo['metadata']['sha1'],
            'sha256': fileinfo['metadata']['sha256'],
            'md5': fileinfo['metadata']['md5'],
            'vaulted': fileinfo['path'],
        }

        if makeartifact:
            ret_val, artifact_id = self._save_artifact(artifact={
                'name': "Vault Artifact",
                'source_data_identifier': makeartifact,
                'container_id': self.get_container_id(),
                'type': "vault",
                'cef': data,
            })
            # is a duplicated artifact a success?
            if ret_val is not True and ret_val != "existing_artifact_id":
                return ret_val, None, None
            if ret_val == "existing_artifact_id":
                self.save_progress("Notice: duplicated artifact; {}".format(artifact_id))

            summary['artifact_id'] = artifact_id
            data['artifact_id'] = artifact_id

        return True, summary, data

    def _ingest_reports(self, reports=None, label=None, tenant=None, ingest_subfields=False, cef_mapping=False):

        if not label:
            return "Error: label parameter not provided", None

        if not reports or not isinstance(reports, list) or len(reports) == 0:
            return "Error: reports must be a list with a least one row", None

        if not cef_mapping:
            cef_mapping = self.get_config().get('cef_mapping')

        if cef_mapping:
            try:
                cef_mapping = json.loads(cef_mapping)
            except:
                pass

        if not isinstance(cef_mapping, dict) or len(cef_mapping) == 0:
            cef_mapping = False

        stats = list()

        for x in reports:

            report_id = str(x.get('id'))

            ret_val, severity = self._determine_value(CATEGORY_ID_TO_SEVERITY, x.get('category_id'), 'for mapping severity')
            if ret_val is not True:
                severity = "low"

            artifacts = []
            container = {
                'label': label,
                'name': x.get('report_subject'),
                "source_data_identifier": "report id {}".format(report_id),
                'severity': severity,
                'artifacts': artifacts,
            }
            if tenant is not None:
                container['tenant_id'] = tenant

            cef = self._remap_cef(x, cef_mapping)
            artifacts += [{
                "source_data_identifier": "report id {}".format(report_id),
                "name": "Report Artifact",
                "cef": cef,
            }]

            if ingest_subfields:

                email_urls = x.get("email_urls")
                if isinstance(email_urls, list):
                    urls = [z for z in [y.get('url') for y in email_urls] if z]
                    for y in urls:
                        cef = self._remap_cef(cef={'url': y}, cef_mapping=cef_mapping)
                        artifacts += [{
                            "source_data_identifier": "report id {}".format(report_id),
                            "name": "Url Artifact",
                            "cef": cef
                        }]

                tags = x.get("tags")
                if isinstance(tags, list):
                    for y in tags:
                        cef = self._remap_cef(cef={'tag': y}, cef_mapping=cef_mapping)
                        artifacts += [{
                            "source_data_identifier": "report id {}".format(report_id),
                            "name": "Tag Artifact",
                            "cef": cef
                        }]

                rules = x.get("rules")
                if isinstance(rules, list):
                    for y in rules:
                        cef = self._remap_cef(cef=y, cef_mapping=cef_mapping)
                        artifacts += [{
                            "source_data_identifier": "report id {}".format(report_id),
                            "name": "Rule Artifact",
                            "cef": cef
                        }]

                email_attachments = x.get("email_attachments")
                if isinstance(email_attachments, list):
                    for y in email_attachments:
                        cef = self._remap_cef(cef=y, cef_mapping=cef_mapping)
                        artifacts += [{
                            "source_data_identifier": "report id {}".format(report_id),
                            "name": "Attachment Artifact",
                            "cef": cef
                        }]
                        cef = self._remap_cef(
                            cef=y.get('email_attachment_payload'), cef_mapping=cef_mapping)
                        artifacts += [{
                            "source_data_identifier": "email attachment id {}".format(str(y.get('id'))),
                            "name": "Payload Artifact",
                            "cef": cef
                        }]
            artifacts = container.pop("artifacts")
            status, message, container_id = self.save_container(container)
            if container_id:
                for artifact in artifacts:
                    artifact['container_id'] = container_id
                ret_val, _, _ = self.save_artifacts(artifacts)

            self.save_progress("DEBUG: report_id ({}) reported_at ({})".format(x.get('id'), x.get('reported_at')))
            self.save_progress("DEBUG: container: report_id ({}) status ({}) message ({}) container_id ({})".format(x.get('id'), status, message, container_id))

            stats += [{'ingest_id': x.get('id'), 'container_id': container_id, 'num_artifacts': len(artifacts), 'status': status, 'message': message}]

        return True, stats

    def _ingest_threat_indicators(self, threat_indicators=None, label=None, tenant=None, ingest_subfields=False, cef_mapping=False):

        if not label:
            return "Error: label parameter not provided", None

        if not threat_indicators or not isinstance(threat_indicators, list) or len(threat_indicators) == 0:
            return "Error: threat_indicators must be a list with a least one row", None

        if not cef_mapping:
            cef_mapping = self.get_config().get('cef_mapping')

        if cef_mapping:
            try:
                cef_mapping = json.loads(cef_mapping)
            except:
                pass

        if not isinstance(cef_mapping, dict) or len(cef_mapping) == 0:
            cef_mapping = False

        stats = list()

        for x in threat_indicators:

            indicator_id = str(x.get('id'))

            ret_val, severity = self._determine_value(
                THREAT_LEVEL_TO_SEVERITY, x.get('threat_level'), 'for mapping severity')
            if ret_val is not True:
                severity = "low"

            artifacts = []
            container = {
                'label': label,
                'name': "Threat Indicator ID {}".format(indicator_id),
                "source_data_identifier": "threat indicator id {}".format(indicator_id),
                'severity': severity,
                'artifacts': artifacts,
            }
            if tenant is not None:
                container['tenant_id'] = tenant

            cef = self._remap_cef(x, cef_mapping)
            artifacts += [{
                "source_data_identifier": "threat indicator id {}".format(indicator_id),
                "name": "Threat Indicator Artifact",
                "cef": cef,
            }]

            status, message, container_id = self.save_container(container)
            self.save_progress("DEBUG: threat indicator ({}) create_at ({})".format(
                x.get('id'), x.get('created_at')))
            self.save_progress("DEBUG: container: threat_indicator_id ({}) status ({}) message ({}) container_id ({})".format(
                x.get('id'), status, message, container_id))
            stats += [{'ingest_id': x.get('id'), 'container_id': container_id, 'num_artifacts': len(
                artifacts), 'status': status, 'message': message}]

        return True, stats


# network errors will raise "ConnectionError" all the way to the spawn process

    def _get_pages_from_endpoint(self, action_result, endpoint=None, start_date=None, end_date=None,
                                 match_priority=None, category_id=None, vip=None, email=None, tags=None, threat_type=None,
                                 threat_level=None, page=0, page_dir="1 first", results_dir=None, per_page=None, max_results=None):

        if page == "all" or page is None:
            page = 0

        if per_page == 0 or per_page is None:
            per_page = MAX_PER_PAGE

        # ensure all page/per_page comparisons are done int to int

        ret_val, page = self._validate_integer(page, PAGE_KEY)
        if ret_val is not True:
            return ret_val, None
        ret_val, per_page = self._validate_integer(per_page, PER_PAGE_KEY)
        if ret_val is not True:
            return ret_val, None
        ret_val, max_results = self._validate_integer(
            max_results, MAX_RESULTS_KEY)
        if ret_val is not True:
            return ret_val, None
        ret_val, match_priority = self._validate_integer(
            match_priority, MATCH_PRIORITY_KEY)
        if ret_val is not True:
            return ret_val, None

        if per_page == 0:
            return "Error: 'per_page' parameter must be greater than zero; entered value {}".format(per_page), None

        if per_page > MAX_PER_PAGE:
            return "Error: 'per_page' parameter must be less than or equal to {}; entered value {}".format(MAX_PER_PAGE, per_page), None

        if max_results == 0:
            return "Error: 'max_results' parameter must be greater than zero; entered value: {}".format(max_results), None

        params = {
            'match_priority': match_priority,
            'category_id': category_id,
            'vip': str(vip).lower() if vip else None,
            'email': email,
            'tags': tags,
            'type': threat_type,
            'level': threat_level,
            'start_date': start_date['datetime'].strftime("%d/%m/%YT%H:%M:%S") if start_date else None,
            'end_date': end_date['datetime'].strftime("%d/%m/%YT%H:%M:%S") if end_date else None,
            'per_page': per_page,
        }
        params = {k: v for k, v in list(params.items()) if v or v == 0}

        status = True
        downloaded_results = []
        downloaded_pages = []

        # if indicated, get the requested page
        if page != 0:
            params['page'] = page
            self.save_progress("Retrieving page {}".format(params['page']))
            ret_val, response = self._make_rest_call(
                endpoint, action_result, params=params)
            if phantom.is_fail(ret_val):
                error_text = "Error: failed to retrieve results; REST error"
                message = action_result.get_message() + error_text
                return message, None
            downloaded_results += response
            downloaded_pages += [page]

        else:
            params['page'] = 1
            self.save_progress("Retrieving page {}".format(params['page']))
            ret_val, first_page = self._make_rest_call(
                endpoint, action_result, params=params)
            if phantom.is_fail(ret_val):
                error_text = "Error: failed to retrieve results; REST error"
                message = action_result.get_message() + error_text
                return message, None

            try:
                if per_page != int(self._r.headers.get('Per-Page')):
                    # this doesn't make sense, return as error, discard downloaded results
                    return "Error: requested results per page doesn't match actual results per page; requested ({}) actual ({})".format(per_page, self._r.headers.get('Per-Page')), None
            except:
                return "Error: Actual per page is not an integer", None
            # figure out which pages to download and in what order
            try:
                total_results = int(self._r.headers['Total'])
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return err, None
            # we can actually get the last page from the headers but will calculate it instead
            total_pages = total_results // per_page
            if total_results % per_page != 0:
                total_pages += 1

            desired_pages = list(range(1, total_pages + 1))

            if page_dir != "1st_page first":
                desired_pages = reversed(desired_pages)

            # Fallback to a default rate limit if the Cofense Triage API does
            # not respond with the X-RateLimit-Remaining header.
            try:
                ratelimit = int(self._r.headers.get(
                    'X-RateLimit-Remaining', DEFAULT_COFENSE_TRIAGE_RATE_LIMIT))
            except Exception as e:
                err = self._get_error_message_from_exception(e)
                return err, None

            for page in desired_pages:

                params['page'] = page

                if page == 1:
                    # tack on the first page we initially downloaded
                    self.save_progress(
                        "Recovering first page downloaded {}".format(params['page']))
                    response = first_page

                else:
                    # try and get the next page

                    if ratelimit <= 0:
                        status = "Zero remaining. Unable to continue retrieval of results"
                        self.save_progress(status)
                        break

                    self.save_progress(
                        "Retrieving page {}".format(params['page']))
                    ret_val, response = self._make_rest_call(
                        endpoint, action_result, params=params)

                    if phantom.is_fail(ret_val):
                        error_text = "Error: failed to retrieve results; REST error"
                        status = action_result.get_message() + error_text
                        break

                downloaded_pages += [page]
                downloaded_results += response
                downloaded_length = len(downloaded_results)
                try:
                    ratelimit = int(self._r.headers.get(
                        'X-RateLimit-Remaining', DEFAULT_COFENSE_TRIAGE_RATE_LIMIT))
                except Exception as e:
                    err = self._get_error_message_from_exception(e)
                    return err, None

                self.save_progress("Retrieved page {} with {} results. Retrieved {} of {} total results. {} limit of {} max results".format(
                    params['page'], len(response), downloaded_length, total_results, "Reached" if downloaded_length >= max_results else "Not at", max_results))
                self.save_progress("{} remaining".format(ratelimit))

                if downloaded_length >= max_results:
                    # we downloaded the maximum number of results we want, stop here
                    break

        if results_dir == "oldest first":
            downloaded_results.sort(key=lambda x: x['id'])
        else:
            downloaded_results.sort(key=lambda x: x['id'], reverse=True)

        downloaded_results = downloaded_results[:max_results]
        return status, {'downloaded_results': downloaded_results, 'downloaded_pages': downloaded_pages}

    # flake8: noqa: C901

    def _handle_get_threat_indicators(self, param):

        if self.get_action_identifier() != "on_poll":
            self.save_progress("In action handler for: {0}".format(
                self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, direction = self._determine_value(DATE_SORT_DIRECTION, param.get(
            'date_sort'), 'to date_sort parameter', return_none=True)
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        # observation indicates for /triage_threat_indicators endpoint, page=1 has the oldest entries
        if direction == "oldest first":
            page_dir = "1st_page first"
        else:
            page_dir = "last_page first"

        ret_val, threat_type = self._determine_value(
            THREAT_TYPE_VALUES, param.get('type'), 'to type parameter')
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        ret_val, level = self._determine_value(THREAT_LEVEL_VALUES, param.get(
            'level'), 'to level parameter', return_none=True)
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        ret_val, start_date = self._parse_datetime(param.get('start_date'), "start_date parameter")
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        ret_val, end_date = self._parse_datetime(param.get('end_date'), "end_date parameter")
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        if param.get('all_pages', True) is False:
            page = param.get('page')
            per_page = param.get('per_page')
        else:
            page = 0
            per_page = 0

        ret_val, label = self._validate_label(param.get('ingest_to_label'))
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        if label:
            # to accomandate on_poll ingestion which does not provide a tenant id
            if param.get('tenant') == "__NONE__":
                tenant = None
            else:
                ret_val, tenant = self._validate_tenant(param.get('tenant', None))
                if ret_val is not True:
                    if self.get_action_identifier() != "on_poll":
                        self.save_progress(ret_val)
                    return action_result.set_status(phantom.APP_ERROR, ret_val)

                if tenant is None:
                    e = "Error: tenant parameter is required to ingest threat indicators(s)"
                    if self.get_action_identifier() != "on_poll":
                        self.save_progress(e)
                    return action_result.set_status(phantom.APP_ERROR, e)

        max_results = param.get('max_results')

        endpoint = "/triage_threat_indicators"
        ret_val, response = self._get_pages_from_endpoint(action_result=action_result, endpoint=endpoint, start_date=start_date, end_date=end_date,
                                                          threat_type=threat_type, threat_level=level,
                                                          page=page, per_page=per_page, page_dir=page_dir, results_dir=direction, max_results=max_results)

        # most likely rest error
        if ret_val is not True:
            if response is None or len(response['downloaded_results']) == 0:
                # no results retrieved
                if self.get_action_identifier() != "on_poll":
                    self.save_progress(ret_val)
                return action_result.set_status(phantom.APP_ERROR, ret_val)
            # but we got some data! try and process it, but still fail the action
            func_ret_val = phantom.APP_ERROR
        else:
            func_ret_val = phantom.APP_SUCCESS

        downloaded_results = response['downloaded_results']
        downloaded_pages = response['downloaded_pages']
        action_result.update_summary({
            'downloaded_threat_indicators': len(downloaded_results),
            'downloaded_pages': str(downloaded_pages),
            'available_results': self._r.headers.get('Total', "unknown"),
            'ratelimits_remaining': "{}".format(self._r.headers.get('X-RateLimit-Remaining', "unknown")),
        })
        action_result.add_extra_data({'headers': dict(self._r.headers)})
        action_result.update_summary({'headers': dict(self._r.headers)})

        for x in downloaded_results:
            action_result.add_data(x)

        if label:
            ret_val, response = self._ingest_threat_indicators(threat_indicators=downloaded_results, label=label, tenant=tenant,
                                                               cef_mapping=param.get('cef_mapping'))
            if ret_val is not True:
                if self.get_action_identifier() != "on_poll":
                    self.save_progress(ret_val)
                return action_result.set_status(phantom.APP_ERROR, ret_val)
            self._associate_container_ids(action_result.get_data(), response)
            action_result.update_summary({'ingest_stats': response})
            if ret_val == phantom.APP_ERROR:
                func_ret_val = phantom.APP_ERROR

        self._action_result = action_result
        return action_result.set_status(func_ret_val)

    def _handle_get_reports(self, param):

        if self.get_action_identifier() != "on_poll":
            self.save_progress("In action handler for: {0}".format(
                self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, direction = self._determine_value(DATE_SORT_DIRECTION, param.get(
            'date_sort'), 'to date_sort parameter', return_none=True)
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        # observation indicates for /reports endpoint, page=last has the oldest entries, reversed from /triage_threat_indicators
        if direction == "oldest first":
            page_dir = "last_page first"
        else:
            page_dir = "1st_page first"

        ret_val, endpoint = self._determine_value(
            ENDPOINT_TYPE_VALUES, param['type'], 'to type parameter')
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        ret_val, category_id = self._determine_value(CATEGORY_ID_VALUES, param.get(
            'category_id'), 'to category_id parameter', return_none=True)
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        tags = param.get('tags')
        if tags:
            tags = [x.strip() for x in tags.split(",")]
            tags = ",".join(list([tag for tag in tags if tag]))

        ret_val, start_date = self._parse_datetime(
            param.get('start_date'), "start_date parameter")
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        ret_val, end_date = self._parse_datetime(
            param.get('end_date'), "end_date parameter")
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        if param.get('all_pages', True) is False:
            page = param.get('page')
            per_page = param.get('per_page')
        else:
            page = 0
            per_page = 0

        ret_val, label = self._validate_label(param.get('ingest_to_label'))
        if ret_val is not True:
            if self.get_action_identifier() != "on_poll":
                self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        if label:
            if param.get('tenant') == "__NONE__":
                tenant = None
            else:
                ret_val, tenant = self._validate_tenant(param.get('tenant', None))
                if ret_val is not True:
                    if self.get_action_identifier() != "on_poll":
                        self.save_progress(ret_val)
                    return action_result.set_status(phantom.APP_ERROR, ret_val)

                if tenant is None:
                    e = "Error: tenant parameter is required to ingest report(s)"
                    if self.get_action_identifier() != "on_poll":
                        self.save_progress(e)
                    return action_result.set_status(phantom.APP_ERROR, e)

        max_results = param.get('max_results')

        ret_val, response = self._get_pages_from_endpoint(action_result=action_result, endpoint=endpoint, start_date=start_date, end_date=end_date,
                                                          match_priority=param.get('match_priority'), category_id=category_id, tags=tags,
                                                          page=page, per_page=per_page, page_dir=page_dir, results_dir=direction, max_results=max_results)

        # most likely rest error
        if ret_val is not True:
            if response is None or len(response['downloaded_results']) == 0:
                if self.get_action_identifier() != "on_poll":
                    self.save_progress(ret_val)
                return action_result.set_status(phantom.APP_ERROR, ret_val)
            # but we got some data! try and process it, but still fail the action
            func_ret_val = phantom.APP_ERROR
        else:
            func_ret_val = phantom.APP_SUCCESS

        downloaded_results = response['downloaded_results']
        downloaded_pages = response['downloaded_pages']
        action_result.update_summary({
            'downloaded_reports': len(downloaded_results),
            'downloaded_pages': str(downloaded_pages),
            'available_results': self._r.headers.get('Total', "unknown"),
            'ratelimits_remaining': "{}".format(self._r.headers.get('X-RateLimit-Remaining', "unknown")),
        })
        action_result.add_extra_data({'headers': dict(self._r.headers)})
        action_result.update_summary({'headers': dict(self._r.headers)})

        for x in downloaded_results:
            action_result.add_data(x)

        if label:
            ret_val, response = self._ingest_reports(reports=downloaded_results, label=label, tenant=tenant,
                                                     ingest_subfields=param.get('ingest_subfields', False), cef_mapping=param.get('cef_mapping'))
            if ret_val is not True:
                if self.get_action_identifier() != "on_poll":
                    self.save_progress(ret_val)
                return action_result.set_status(phantom.APP_ERROR, ret_val)
            self._associate_container_ids(action_result.get_data(), response)
            action_result.update_summary({'ingest_stats': response})
            if ret_val == phantom.APP_ERROR:
                func_ret_val = phantom.APP_ERROR

        self._action_result = action_result
        return action_result.set_status(func_ret_val)

    def _handle_get_report(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        report_id = param['report_id']
        ret_val, report_id = self._validate_integer(report_id, REPORT_ID_KEY)
        if ret_val is not True:
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        ret_val, label = self._validate_label(param.get('ingest_to_label'))
        if ret_val is not True:
            self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        if label:
            ret_val, tenant = self._validate_tenant(param.get('tenant', None))
            if ret_val is not True:
                self.save_progress(ret_val)
                return action_result.set_status(phantom.APP_ERROR, ret_val)

            if tenant is None:
                e = "Error: tenant parameter is required to ingest report(s)"
                self.save_progress(e)
                return action_result.set_status(phantom.APP_ERROR, e)

        endpoint = "/reports/{0}".format(str(report_id))
        self.save_progress("Retrieving report id {}".format(report_id))
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Error: failed to retrieve report; REST error")
            return action_result.get_status()

        if len(response) == 0:
            e = "Error: retrieved zero length response; report_id: {}".format(report_id)
            self.save_progress(e)
            return action_result.set_status(phantom.APP_ERROR, e)

        action_result.add_data(response[0])

        if label:
            ret_val, response = self._ingest_reports(reports=response, label=label, tenant=tenant,
                                                     ingest_subfields=param.get('ingest_subfields', False), cef_mapping=param.get('cef_mapping', None))
            if ret_val is not True:
                self.save_progress(ret_val)
                return action_result.set_status(phantom.APP_ERROR, ret_val)
            self._associate_container_ids(action_result.get_data(), response)
            action_result.update_summary({'ingest_stats': response})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_email(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        report_id = param['report_id']
        ret_val, report_id = self._validate_integer(report_id, REPORT_ID_KEY)
        if ret_val is not True:
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        endpoint = "/reports/{0}.txt".format(str(report_id))
        self.save_progress(
            "Downloading raw email of report id {}".format(report_id))
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(
                "Error: failed to download raw email; REST error")
            return action_result.get_status()

        ret_val, method = self._determine_value(
            DOWNLOAD_METHOD_VALUES, param['download_method'], "for download_method parameter")
        if ret_val is not True:
            self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        filename = self._r.headers.get(
            'Content-Disposition', "").split('filename=')[-1].strip('"')
        source_data_identifier = "report id  {0}".format(str(report_id))

        if method == "artifact":
            ret_val, summary, data = self._save_email_artifact(
                source_data_identifier=source_data_identifier, filename=filename, content=response)
            if ret_val is not True:
                self.save_progress(ret_val)
                return action_result.set_status(phantom.APP_ERROR, ret_val)

        else:
            ret_val, summary, data = self._vault_file(filename=filename, content=response,
                                                      makeartifact=source_data_identifier if param.get('create_vaulted_file_artifact', False) else None)
            if ret_val is not True:
                self.save_progress(ret_val)
                return action_result.set_status(phantom.APP_ERROR, ret_val)

        summary['report_id'] = report_id
        data['report_id'] = report_id
        action_result.update_summary(summary)
        action_result.add_data(data)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        attachment_id = param['attachment_id']
        ret_val, attachment_id = self._validate_integer(
            attachment_id, ATTACHMENT_ID_KEY)
        if ret_val is not True:
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        endpoint = "/attachment/{0}".format(str(attachment_id))
        self.save_progress(
            "Downloading attachment id {}".format(attachment_id))
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(
                "Error: failed to download raw email; REST error")
            return action_result.get_status()

        filename = self._r.headers.get(
            'Content-Disposition', "").split('filename=')[-1].strip('"')
        source_data_identifier = "attachment_id {0}".format(str(attachment_id))

        ret_val, summary, data = self._vault_file(filename=filename, content=response,
                                                  makeartifact=source_data_identifier if param.get('create_vaulted_file_artifact', False) else None)
        if ret_val is not True:
            self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        summary['attachment_id'] = attachment_id
        data['attachment_id'] = attachment_id
        action_result.update_summary(summary)
        action_result.add_data(data)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_reporters(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, direction = self._determine_value(DATE_SORT_DIRECTION, param.get(
            'date_sort'), 'to date_sort parameter', return_none=True)
        if ret_val is not True:
            self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        # observation indicates for /reports endpoint, page=last has the oldest entries, reversed from /triage_threat_indicators
        if direction == "oldest first":
            page_dir = "last_page first"
        else:
            page_dir = "1st_page first"

        ret_val, start_date = self._parse_datetime(param.get('start_date'), "start_date parameter")
        if ret_val is not True:
            self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        ret_val, end_date = self._parse_datetime(param.get('end_date'), "end_date parameter")
        if ret_val is not True:
            self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        if param.get('all_pages', True) is False:
            page = param.get('page')
            per_page = param.get('per_page')
        else:
            page = 0
            per_page = 0

        max_results = param.get('max_results')

        endpoint = "/reporters"
        ret_val, response = self._get_pages_from_endpoint(action_result=action_result, endpoint=endpoint, start_date=start_date, end_date=end_date,
                                                          vip=param.get('vip', False),
                                                          email=param.get('email'),
                                                          page=page, per_page=per_page, page_dir=page_dir, results_dir=direction, max_results=max_results)

        # most likely rest error
        if ret_val is not True:
            if response is None or len(response['downloaded_results']) == 0:
                self.save_progress(ret_val)
                return action_result.set_status(phantom.APP_ERROR, ret_val)
            # but we got some data! try and process it, but still fail the action
            func_ret_val = phantom.APP_ERROR
        else:
            func_ret_val = phantom.APP_SUCCESS

        downloaded_results = response['downloaded_results']
        downloaded_pages = response['downloaded_pages']
        action_result.update_summary({
            'downloaded_reporters': len(downloaded_results),
            'downloaded_pages': str(downloaded_pages),
            'available_results': self._r.headers.get('Total', "unknown"),
            'ratelimits_remaining': "{}".format(self._r.headers.get('X-RateLimit-Remaining', "unknown")),
        })
        action_result.add_extra_data({'headers': dict(self._r.headers)})

        for x in downloaded_results:
            action_result.add_data(x)

        return action_result.set_status(func_ret_val)

    def _handle_get_reporter(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        reporter_id = param['reporter_id']
        ret_val, reporter_id = self._validate_integer(
            reporter_id, REPORTER_ID_KEY)
        if ret_val is not True:
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        endpoint = "/reporters/{0}".format(str(reporter_id))
        self.save_progress("Retrieving reporter id {}".format(reporter_id))
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(
                "Error: failed to retrieve reporter; REST error")
            return action_result.get_status()

        if len(response) == 0:
            e = "Error: retrieved zero length response; reporter_id: {}".format(reporter_id)
            self.save_progress(e)
            return action_result.set_status(phantom.APP_ERROR, e)

        action_result.add_data(response[0])
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_query(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, method = self._determine_value(
            RUN_QUERY_METHOD_VALUES, param['query_type'], "for query_type parameter")
        if ret_val is not True:
            self.save_progress(ret_val)
            return action_result.set_status(phantom.APP_ERROR, ret_val)

        search = param['search_term']

        endpoint = "/integration_search"
        self.save_progress("Retrieving {}: {}".format(method, search))
        ret_val, response = self._make_rest_call(
            endpoint, action_result, params={method: search})

        if phantom.is_fail(ret_val):
            self.save_progress(
                "Error: failed to run the query; REST error")
            return action_result.get_status()

        if 'message' in response:
            e = "Error: {}".format(response['message'])
            self.save_progress(e)
            return action_result.set_status(phantom.APP_ERROR, e)

        for i, x in enumerate(response.get('integration_submissions', [])):

            decoded = None
            try:
                decoded = json.loads(x.get('result', ''))
            except:
                pass

            if decoded:
                x['_raw_result'] = x['result']
                x['result'] = decoded

        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):

        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))
        self._action_result = None
        config = self.get_config()

        ret_val, method = self._determine_value(INGESTION_METHOD_VALUES, config.get(
            'ingestion_method'), "for ingestion_method configuration")
        if ret_val is not True:
            self.save_progress(ret_val)
            return self.add_action_result(ActionResult(dict(param))).set_status(phantom.APP_ERROR, ret_val)

        if method == "threat":
            self.save_progress("Ingesting Threat Indicators")

            # get the last ingested date from the app state if not the first run.
            # otherwise check for initial ingest date from the config.
            # otherwise use the product default, currently 6 days.
            saved_date = 'threat_last_ingested_date'

            action_param = {
                'start_date': self._state.get(saved_date, config.get('start_date')),
                'max_results': param.get('container_count', config.get('max_results')),
                'date_sort': config.get('date_sort'),
                'type': config.get('threat_type'),
                'level': config.get('threat_level'),
                'cef_mapping': config.get('cef_mapping'),
                'ingest_to_label': config.get('ingest', {}).get('container_label'),
                'tenant': "__NONE__",
                'all_pages': True,
            }
            ingest_on = "created_at"

            if self._state.get(saved_date):
                self.save_progress("Starting ingestion from saved last ingested time {}".format(
                    action_param['start_date']))
            elif config.get('start_date'):
                self.save_progress("Initialing new ingestion from configured start time {}".format(
                    action_param['start_date']))
            else:
                self.save_progress(
                    "Initialing new ingestion from default product time range")

            ret_val = self._handle_get_threat_indicators(action_param)

        elif method == "reports":
            self.save_progress("Ingesting Reports")

            # get the last ingested date from the app state if not the first run.
            # otherwise check for initial ingest date from the config.
            # otherwise use the product default, currently 6 days.
            saved_date = 'report_last_ingested_date'

            action_param = {
                'start_date': self._state.get(saved_date, config.get('start_date')),
                'max_results': param.get('container_count', config.get('max_results')),
                'date_sort': config.get('date_sort'),
                'type': config.get('report_type'),
                'match_priority': config.get('report_match_priority'),
                'category_id': config.get('report_category_id'),
                'tags': config.get('report_tags'),
                'cef_mapping': config.get('cef_mapping'),
                'ingest_to_label': config.get('ingest', {}).get('container_label'),
                'ingest_subfields': config.get('report_ingest_subfields', False),
                'tenant': "__NONE__",
                'all_pages': True,
            }
            ingest_on = "reported_at"

            if self._state.get(saved_date):
                self.save_progress("Starting ingestion from saved last ingested time {}".format(
                    action_param['start_date']))
            elif config.get('start_date'):
                self.save_progress("Initialing new ingestion from configured start time {}".format(
                    action_param['start_date']))
            else:
                self.save_progress(
                    "Initialing new ingestion from default product time range")

            ret_val = self._handle_get_reports(action_param)

        else:
            e = "Error: unimplemented ingestion type; {}".format(method)
            self.save_progress(e)
            return self.add_action_result(ActionResult(dict(param))).set_status(phantom.APP_ERROR, e)

        if ret_val is not True:
            return ret_val

        # ---
        # threat indicators are ordered by created_at date
        # reports are ordered by reported_at date
        # ---
        # To get the last ingested date, get the relevant time of the highest ingested id.
        # todo: change to use last ingested result id to determine which ids to download

        downloaded_results = [
            x for x in self._action_result.get_data() if x.get('container_id')]
        if len(downloaded_results) > 0:
            downloaded_results.sort(key=lambda x: x['id'], reverse=True)
            ret_val, last_ingested_date = self._parse_datetime(
                downloaded_results[0][ingest_on])
            if ret_val is not True:
                self.save_progress(ret_val)
                return self._action_result.set_status(phantom.APP_ERROR, ret_val)

            last_ingested_date['datetime'] += timedelta(microseconds=1000)
            self.save_progress("Saving last ingested time from result id ({}) container id ({}) of time ({})".format(
                downloaded_results[0]['id'], downloaded_results[0]['container_id'], last_ingested_date['datetime'].isoformat()))
            self._state = self.load_state()
            self._state[saved_date] = last_ingested_date['datetime'].isoformat()
            self.save_state(self._state)
        else:
            self.save_progress(
                "No successfully ingested containers, no last ingested time to save")
        return ret_val

    def handle_action(self, param):

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary Mapping for each supported action
        supported_actions = {
            'test_connectivity': self._handle_test_connectivity,
            'get_threat_indicators': self._handle_get_threat_indicators,
            'get_reports': self._handle_get_reports,
            'get_report': self._handle_get_report,
            'get_email': self._handle_get_email,
            'get_file': self._handle_get_file,
            'get_reporters': self._handle_get_reporters,
            'get_reporter': self._handle_get_reporter,
            'run_query': self._handle_run_query,
            'on_poll': self._handle_on_poll
        }

        if action_id in supported_actions:
            return supported_actions[action_id](param)
        else:
            return phantom.APP_SUCCESS

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config['base_url'].rstrip("/")
        self._api_email = config['api_email']
        self._api_token = config['api_token']
        self._auth_string = 'Token token={0}:{1}'.format(
            self._api_email, self._api_token)
        self._verify = config.get('verify_server_cert', False)

        self._user_info = None

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


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
        try:
            login_url = CofenseTriageConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
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
            r2 = requests.post(login_url, verify=False,
                               data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CofenseTriageConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
