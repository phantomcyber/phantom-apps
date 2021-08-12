# File: hackerone_connector.py
# Copyright (c) 2020-2021 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#
import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from hackerone_consts import *
import datetime
import requests
import json
import os
import re
from bs4 import UnicodeDammit


class HackerOneConnector(BaseConnector):

    is_polling_action = False

    def __init__(self):
        super(HackerOneConnector, self).__init__()
        return

    def __print(self, object):
        message = 'Failed to cast message to string'
        try:
            message = str(object)
        except:
            pass

        if self.is_polling_action:
            self.debug_print('HackerOne {}'.format(message))
        else:
            self.save_progress(message)

    def _validate_integer(self, action_result, parameter, key):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, INT_VALIDATION_ERR_MSG.format(key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, INT_VALIDATION_ERR_MSG.format(key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, NEG_INT_VALIDATION_ERR_MSG.format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _handle_unicode_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: encoded input_str
        """

        try:
            if input_str:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
                input_str = input_str.decode('utf-8')
        except:
            self.debug_print("Error occurred while encoding input string")

        return input_str

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
                    error_code = ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = ERR_CODE_MSG
                error_msg = ERR_MSG_UNAVAILABLE
        except:
            error_code = ERR_CODE_MSG
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            error_msg = self._handle_unicode_for_input_str(error_msg)
        except TypeError:
            error_msg = TYPE_ERR_MSG
        except:
            error_msg = ERR_MSG_UNAVAILABLE

        try:
            if error_code in ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing error message")
            error_text = PARSE_ERR_MSG

        return error_text

    def _get_auth(self):
        u = self.get_config()['api_identifier']
        p = self.get_config()['api_token']
        return u, p

    def _get_headers(self):
        HEADERS = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        return HEADERS

    def _get_phantom_headers(self):
        config = self.get_config()
        HEADERS = { "ph-auth-token": config['phantom_api_token'] }
        return HEADERS

    def _get_phantom_data(self, endpoint):
        self.__print('Start: _get_phantom_data(): {0}'.format(datetime.datetime.now()))
        try:
            self.__print(endpoint)
            response = requests.get(endpoint, headers=self._get_phantom_headers(), verify=False)
            try:
                content = json.loads(response.text)
            except Exception as e:
                self.__print("Error parsing JSON Object: {}".format(self._get_error_message_from_exception(e)))
                return None
            code = response.status_code
            if code == 200:
                self.__print('Finish: _get_phantom_data(): {0}'.format(datetime.datetime.now()))
                return content
            else:
                self.__print(code)
                self.__print(content)
                self.__print('Finish: _get_phantom_data(): {0}'.format(datetime.datetime.now()))
                return None
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print(err)
            self.__print('Finish: _get_phantom_data(): {0}'.format(datetime.datetime.now()))
            return None

    def _post_phantom_data(self, url, dictionary):
        self.__print('Start: _post_phantom_data(): {0}'.format(datetime.datetime.now()))
        try:
            self.__print(url)
            response = requests.post(url, headers=self._get_phantom_headers(), json=dictionary, verify=False)
            try:
                content = json.loads(response.text)
            except Exception as e:
                self.__print("Error parsing JSON Object: {}".format(self._get_error_message_from_exception(e)))
                return None
            code = response.status_code
            if code >= 200 and code < 300:
                self.__print('Finish: _post_phantom_data(): {0}'.format(datetime.datetime.now()))
                return code
            else:
                self.__print(code)
                self.__print(content)
                self.__print('Finish: _post_phantom_data(): {0}'.format(datetime.datetime.now()))
                return None
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print(err)
            return None

    def _delete_phantom_data(self, url):
        self.__print('Start: _delete_phantom_data(): {0}'.format(datetime.datetime.now()))
        try:
            self.__print(url)
            response = requests.delete(url, headers=self._get_phantom_headers(), verify=False)
            try:
                content = json.loads(response.text)
            except Exception as e:
                self.__print("Error parsing JSON Object: {}".format(self._get_error_message_from_exception(e)))
                return None
            code = response.status_code
            if code >= 200 and code < 300:
                self.__print('Finish: _delete_phantom_data(): {0}'.format(datetime.datetime.now()))
                return code
            else:
                self.__print(code)
                self.__print(content)
                self.__print('Finish: _delete_phantom_data(): {0}'.format(datetime.datetime.now()))
                return None
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print(err)
            return None

    def _get_rest_data(self, url, url_params):
        self.debug_print('Start: _get_rest_data(): {0}'.format(datetime.datetime.now()))
        try:
            self.__print("Connecting to endpoint '{}'".format(url))
            u, p = self._get_auth()
            if url_params:
                response = requests.get(url, auth=(u, p), params=url_params, headers=self._get_headers(), verify=False)
            else:
                response = requests.get(url, auth=(u, p), headers=self._get_headers(), verify=False)
            try:
                content = json.loads(response.text)
            except Exception as e:
                self.__print("Error parsing JSON Object: {}".format(self._get_error_message_from_exception(e)))
                return None, None
            code = response.status_code
            if code == 200:
                if 'links' in content:
                    return content['data'], content['links']
                else:
                    return content['data'], None
            else:
                self.debug_print(code)
                self.debug_print(content)
                return None, None
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print(err)
            return None, None

    def _put_rest_data(self, url, dictionary):
        self.__print('Start: _put_rest_data(): {0}'.format(datetime.datetime.now()))
        try:
            self.__print(url)
            u, p = self._get_auth()
            response = requests.put(url, auth=(u, p), headers=self._get_headers(), json=dictionary, verify=False)
            content = response.text
            code = response.status_code
            if code >= 200 and code < 300:
                self.__print('Finish: _put_rest_data(): {0}'.format(datetime.datetime.now()))
                return code
            else:
                self.__print(code)
                self.__print(content)
                self.__print('Finish: _put_rest_data(): {0}'.format(datetime.datetime.now()))
                return None
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print(err)
            return None

    def _post_rest_data(self, url, dictionary):
        self.__print('Start: _post_rest_data(): {0}'.format(datetime.datetime.now()))
        try:
            self.__print(url)
            u, p = self._get_auth()
            response = requests.post(url, auth=(u, p), headers=self._get_headers(), json=dictionary, verify=False)
            content = response.text
            code = response.status_code
            if code >= 200 and code < 300:
                self.__print('Finish: _post_rest_data(): {0}'.format(datetime.datetime.now()))
                return code
            else:
                self.__print(code)
                self.__print(content)
                self.__print('Finish: _post_rest_data(): {0}'.format(datetime.datetime.now()))
                return None
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print(err)
            return None

    def _add_report_artifact(self, report):
        self.__print('_add_report_artifact()')
        artifact = {}
        artifact['container_id'] = self.get_container_id()
        artifact['label'] = 'Report'
        artifact['name'] = 'HackerOne Report - {0}'.format(report['id'])
        artifact['source_data_identifier'] = report['id']
        artifact['severity'] = 'medium'
        artifact['cef'] = report
        self.save_artifact(artifact)

    def _add_report_artifacts(self, reports):
        self.__print('_add_report_artifacts()')
        artifacts = []
        for report in reports:
            cef = report
            artifact = {}
            artifact['container_id'] = self.get_container_id()
            artifact['label'] = 'Report'
            artifact['name'] = 'HackerOne Report - {0}'.format(cef['id'])
            artifact['source_data_identifier'] = '{0}-{1}'.format(cef['id'], self.get_container_id())
            artifact['severity'] = 'medium'
            artifact['cef'] = cef
            artifacts.append(artifact)
        self.save_artifacts(artifacts)

    def _update_tracking_id(self, param, action_result):
        self.__print('_update_tracking_id()')
        report_id = self._handle_unicode_for_input_str(param.get('report_id'))
        tracking_id = self._handle_unicode_for_input_str(param.get('tracking_id'))
        try:
            data = {
                "data": {
                    "type": "issue-tracker-reference-id",
                    "attributes": {
                        "reference": tracking_id
                    }
                }
            }
            url = "https://api.hackerone.com/v1/reports/{0}/issue_tracker_reference_id".format(report_id)
            if self._post_rest_data(url, data):
                self.__print('Successfully updated tracking id')
                return action_result.set_status(phantom.APP_SUCCESS, 'Successfully updated tracking id')
            else:
                self.__print('Failed to update tracking id.')
                return action_result.set_status(phantom.APP_ERROR, 'Failed to update tracking id')
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print('Exception occurred while updating tracking id')
            action_result.add_exception_details(err)
            return action_result.set_status(phantom.APP_ERROR, 'Exception occurred while updating tracking id')

    def _unassign_report(self, param, action_result):
        self.__print('_unassign_report()')
        report_id = self._handle_unicode_for_input_str(param.get('report_id'))
        try:
            data = {
                "data": {
                    "type": "nobody"
                }
            }
            url = "https://api.hackerone.com/v1/reports/{0}/assignee".format(report_id)
            if self._put_rest_data(url, data):
                self.__print('Successfully removed report assignment')
                return action_result.set_status(phantom.APP_SUCCESS, 'Successfully removed report assignment')
            else:
                self.__print('Failed to remove report assignment')
                return action_result.set_status(phantom.APP_ERROR, 'Failed to remove report assignment')
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print('Exception occurred while updating tracking id')
            action_result.add_exception_details(err)
            return action_result.set_status(phantom.APP_ERROR, 'Exception occurred while updating tracking id')

    def _uppercase(self, string):
        output = ''
        for value in string.split(' '):
            output = '{0}{1}'.format(output, value[:1].upper())
        return output

    def _parse_list(self, string):
        output = []
        for value in string.split(','):
            output.append(value.strip())
        return output

    def _get_leaves(self, template, report, output):
        for key in template:
            if isinstance(template[key], dict):
                try:
                    self._get_leaves(template[key], report[key], output)
                except:
                    pass
            elif isinstance(template[key], list):
                list_content = []
                i = 0
                for list_entry in report[key]:
                    try:
                        entry = {}
                        self._get_leaves(template[key][1], report[key][i], entry)
                        list_content.append(entry)
                    except:
                        pass
                    i += 1
                output[template[key][0]] = list_content
            else:
                try:
                    output[template[key]] = report[key]
                except:
                    pass
        return output

    def _get_cvf(self, core_report):
        try:
            core_report['severity_cvf'] = 'CVSS:3.0/AV:{0}/AC:{1}/PR:{2}/UI:{3}/S:{4}/C:{5}/I:{6}/A:{7}'.format(
                self._uppercase(core_report['severity_attack_vector']),
                self._uppercase(core_report['severity_attack_complexity']),
                self._uppercase(core_report['severity_privileges_required']),
                self._uppercase(core_report['severity_user_interaction']),
                self._uppercase(core_report['severity_scope']),
                self._uppercase(core_report['severity_confidentiality']),
                self._uppercase(core_report['severity_integrity']),
                self._uppercase(core_report['severity_availability'])
            )
        except:
            pass

    def _parse_report(self, report):
        self.__print('_parse_report()')
        core_report = {}
        report_template = None
        __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        with open(os.path.join(__location__, 'templates', 'hackerone_report_template.json')) as json_file:
            report_template = json.load(json_file)
        report_template = eval(json.dumps(report_template))
        self._get_leaves(report_template, report, core_report)
        self._get_cvf(core_report)
        return core_report

    def _get_complete_report(self, report_id):
        self.__print('_get_complete_report()')
        report, links = self._get_rest_data('https://api.hackerone.com/v1/reports/{0}'.format(report_id), None)
        report = self._parse_report(report)
        return report

    def _get_filtered_reports(self, program, state, assignment, add_comments, date):
        self.__print('_get_filtered_reports()')
        try:
            url_params = {}

            self.__print('Get program filter:')
            url_params['filter[program][]'] = program
            self.__print(json.dumps(url_params))

            self.__print('Get state filter:')
            if state:
                url_params['filter[state][]'] = self._parse_list(state)
                self.__print(json.dumps(url_params))

            self.__print('Get assignment filter:')
            if assignment:
                url_params['filter[assignee][]'] = self._parse_list(assignment)
                self.__print(json.dumps(url_params))

            self.__print('Get date filter:')
            if date:
                url_params['filter[last_activity_at__gt]'] = date
                self.__print(json.dumps(url_params))

            url_params['page[size]'] = 100
            self.__print(json.dumps(url_params))

            report_set = []
            self.__print('get rest data')
            reports, links = self._get_rest_data('https://api.hackerone.com/v1/reports', url_params)
            self.__print(len(reports) if reports else 0)
            self.__print('Entering paging')
            while True:
                self.__print('loop')
                if not reports or reports == []:
                    self.__print('No reports for the range')
                    break
                for report in reports:
                    if add_comments:
                        full_report = self._get_complete_report(report['id'])
                        report_set.append(full_report)
                    else:
                        report_set.append(self._parse_report(report))
                try:
                    reports, links = self._get_rest_data(links['next'], None)
                    self.__print('Next page')
                except:
                    break
            return report_set
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print('Exception occurred while gathering reports')
            self.__print(err)
            return None

    def _get_report(self, param, action_result):
        try:
            id = self._handle_unicode_for_input_str(param.get('report_id'))
            report = self._get_complete_report(id)
            if not report:
                self.__print('No report found')
                return action_result.set_status(phantom.APP_ERROR, 'Failed to get report')
            action_result.add_data(report)
            self._add_report_artifact(report)
            self.__print('Successfully collected report')
            return action_result.set_status(phantom.APP_SUCCESS, 'Successfully collected report')
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print('Failed to get report')
            action_result.add_exception_details(err)
            return action_result.set_status(phantom.APP_ERROR, 'Failed to get report')

    def _get_reports(self, param, action_result):
        try:
            config = self.get_config()
            program = self._handle_unicode_for_input_str(config['program_name'])
            state = self._handle_unicode_for_input_str(param.get('state_filter'))
            assignment = self._handle_unicode_for_input_str(param.get('assignment_filter'))
            add_comments = param.get('full_comments', False)
            reports = self._get_filtered_reports(program, state, assignment, add_comments, None)
            if not reports:
                self.__print('No reports found')
                return action_result.set_status(phantom.APP_ERROR, "Failed to get reports")
            action_result.add_data({'reports': reports, 'count': len(reports)})
            self._add_report_artifacts(reports)
            self.__print('Successfully collected reports')
            return action_result.set_status(phantom.APP_SUCCESS, 'Successfully collected reports')
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print('Failed to get reports')
            action_result.add_exception_details(err)
            return action_result.set_status(phantom.APP_ERROR, 'Failed to get reports')

    def _get_updated_reports(self, param, action_result):
        try:
            config = self.get_config()
            program = self._handle_unicode_for_input_str(config['program_name'])
            state = self._handle_unicode_for_input_str(param.get('state_filter'))
            assignment = self._handle_unicode_for_input_str(param.get('assignment_filter'))
            add_comments = param.get('full_comments', False)
            # Integer Validation for 'range' parameter
            minutes = param.get('range')
            ret_val, minutes = self._validate_integer(action_result, minutes, RANGE_KEY)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            self.debug_print("There might be timezone variance. Please check for the timezone variance.")
            date = (datetime.datetime.now() - datetime.timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            reports = self._get_filtered_reports(program, state, assignment, add_comments, date)
            if not reports:
                self.__print('No reports found')
                return action_result.set_status(phantom.APP_ERROR, 'Failed to get reports')
            action_result.add_data({'reports': reports, 'count': len(reports)})
            self._add_report_artifacts(reports)
            self.__print('Successfully collected reports')
            return action_result.set_status(phantom.APP_SUCCESS, 'Successfully collected reports')
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            self.__print('Failed to get reports')
            action_result.add_exception_details(err)
            return action_result.set_status(phantom.APP_ERROR, 'Failed to get reports')

    def _extract_urls(self, source):
        artifacts = []
        url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        domain_pattern = re.compile(r'^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+)')
        invalid_pattern = re.compile(r'[^a-zA-Z0-9\.\-]')
        for value in re.finditer(url_pattern, source):
            url = value.group(0)
            domain = None
            for match in re.finditer(domain_pattern, url):
                domain = match.group(1)
                break
            if domain and len(re.findall(invalid_pattern, domain)) == 0:
                artifact = {}
                artifact['label'] = 'extracted url'
                artifact['name'] = 'extracted url'
                artifact['source_data_identifier'] = 'Hacker1 url - {0}'.format(url[:60])
                artifact['severity'] = 'medium'
                cef = {}
                cef['requestURL'] = url
                cef['domain'] = domain
                artifact['cef'] = cef
                artifacts.append(artifact)
        return artifacts

    def _test(self, action_result, param):
        self.debug_print('_test()')
        try:
            config = self.get_config()
            url_params = {'filter[program][]': self._handle_unicode_for_input_str(config['program_name']), 'page[size]': 1}
            reports, _ = self._get_rest_data('https://api.hackerone.com/v1/reports', url_params)
            if reports:
                return action_result.set_status(phantom.APP_SUCCESS, 'Test connectivity passed')
            else:
                return action_result.set_status(phantom.APP_ERROR, 'Test connectivity failed')
        except Exception as e:
            err = self._get_error_message_from_exception(e)
            action_result.add_exception_details(err)
            return action_result.set_status(phantom.APP_ERROR, 'Test connectivity failed')

    def _on_poll(self, param):
        self.__print('_on_poll()')
        self.debug_print("There might be timezone variance. Please check for the timezone variance.")
        current_time_marker = datetime.datetime.utcnow()
        previous_time_marker = None
        self.load_state()
        current_state = self.get_state()
        try:
            previous_time_marker = current_state['time_marker']
        except:
            current_state['time_marker'] = current_time_marker.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        login_url = self._get_phantom_base_url()
        config = self.get_config()
        # Integer Validation for 'container_count' parameter
        hours = param.get('container_count')
        ret_val, hours = self._validate_integer(self, hours, CONTAINER_COUNT_KEY)
        if phantom.is_fail(ret_val):
            return self.get_status()

        date = None
        if self.is_poll_now():
            self.debug_print("There might be timezone variance. Please check for the timezone variance.")
            date = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        else:
            date = previous_time_marker
        program = config['program_name']
        try:
            state = config['state_filter']
        except:
            state = None
        try:
            assignment = config['assignment_filter']
        except:
            assignment = None
        add_comments = config.get('full_comments', False)
        reports = self._get_filtered_reports(program, state, assignment, add_comments, date)
        if reports is not None:
            self.save_progress('{0} reports were returned'.format(len(reports)))
            for report in reports:
                existing_container = None
                container_name = 'H1 {0}: {1}'.format(report['id'], re.sub(r'[^\x00-\x7f]', r'', report['title']))
                endpoint = '{0}/rest/container?_filter_name__startswith="H1 {1}"'.format(login_url, report['id'])
                containers = self._get_phantom_data(endpoint)
                if containers['count'] > 0:
                    existing_container = containers['data'][0]['id']
                container = {}
                container['source_data_identifier'] = 'HackerOne Report - {0}'.format(report['id'])
                container['name'] = container_name
                artifacts = []
                artifact = {}
                artifact['label'] = 'report'
                artifact['name'] = 'HackerOne Report - {0}'.format(report['id'])
                artifact['source_data_identifier'] = '{0}-{1}'.format(report['id'], self.get_container_id())
                artifact['severity'] = 'medium'
                artifact['cef'] = report
                artifacts.append(artifact)
                try:
                    for comment in report['comments']:
                        artifact = {}
                        artifact['label'] = 'report comment'
                        artifact['name'] = 'Comment - {0}'.format(comment['id'])
                        artifact['source_data_identifier'] = 'HackerOne report - {0}: Comment - {1}'.format(report['id'], comment['id'])
                        artifact['severity'] = 'medium'
                        artifact['cef'] = comment
                        artifacts.append(artifact)
                except:
                    pass
                try:
                    for attachment in report['attachments']:
                        artifact = {}
                        artifact['label'] = 'report attachment'
                        artifact['name'] = 'Attachment - {0}'.format(attachment['id'])
                        artifact['source_data_identifier'] = 'HackerOne report - {0}: Attachment - {1}'.format(report['id'], attachment['id'])
                        artifact['severity'] = 'medium'
                        artifact['cef'] = attachment
                        artifacts.append(artifact)
                except:
                    pass
                try:
                    url_artifacts = self._extract_urls(report['vulnerability_information'])
                    for artifact in url_artifacts:
                        artifacts.append(artifact)
                except:
                    pass
                if not existing_container:
                    container['artifacts'] = artifacts
                    self.save_container(container)
                else:
                    endpoint = '{0}/rest/container/{1}/artifacts?page_size=0'.format(login_url, existing_container)
                    container_artifacts = self._get_phantom_data(endpoint)['data']
                    duplicates = {}
                    updated_report = False
                    for container_artifact in container_artifacts:
                        if 'report' == container_artifact['label']:
                            endpoint = '{0}rest/artifact/{1}'.format(login_url, container_artifact['id'])
                            self._delete_phantom_data(endpoint)
                            updated_report = True
                        else:
                            duplicates[container_artifact['name']] = container_artifact['id']
                    added_report = False
                    for artifact in artifacts:
                        if 'report' == artifact['label']:
                            if not added_report:
                                artifact['cef']['updated'] = updated_report
                                artifact['container_id'] = existing_container
                                artifact['run_automation'] = True
                                artifact['source_data_identifier'] = '{0}-HackerOne-Report'.format(report['id'])
                                status, message, artid = self.save_artifact(artifact)
                                self.__print(status)
                                self.__print(message)
                                self.__print(artid)
                                added_report = True
                        if artifact['name'] not in duplicates:
                            artifact['container_id'] = existing_container
                            self.save_artifact(artifact)
                self.__print('Successfully stored report container')

            current_state['time_marker'] = current_time_marker.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            self.save_state(current_state)
            return self.set_status(phantom.APP_SUCCESS, 'Successfully stored report data')
        else:
            self.__print('Failed to connect to HackerOne')
            self.save_progress('Failed to connect to HackerOne')
            return self.set_status(phantom.APP_ERROR, 'Failed to connect to HackerOne')

    def handle_action(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS

        if action == ACTION_ID_GET_ALL:
            ret_val = self._get_reports(param, action_result)

        if action == ACTION_ID_GET_UPDATED:
            ret_val = self._get_updated_reports(param, action_result)

        elif action == ACTION_ID_GET_ONE:
            ret_val = self._get_report(param, action_result)

        elif action == ACTION_ID_UPDATE:
            ret_val = self._update_tracking_id(param, action_result)

        elif action == ACTION_ID_UNASSIGN:
            ret_val = self._unassign_report(param, action_result)

        elif action == ACTION_ID_ON_POLL:
            self.is_polling_action = True
            ret_val = self._on_poll(param)

        elif action == ACTION_ID_TEST:
            ret_val = self._test(action_result, param)

        return ret_val


if __name__ == '__main__':
    import sys
    import pudb
    pudb.set_trace()
    if len(sys.argv) < 2:
        print('No test json specified as input')
        exit(0)
    with open(sys.argv[1]) as (f):
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = HackerOneConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    exit(0)
