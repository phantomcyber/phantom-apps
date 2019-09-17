# File: sumologic_connector.py
# Copyright (c) 2016-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

# Phantom imports
import time

import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

import sumologic_parser
import sumologic
from sumologic_consts import *
import requests
import json

import imp


class SumoLogicConnector(BaseConnector):
    # List of all the actions that this app supports
    ACTION_ID_RUN_QUERY = 'run_query'
    ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'
    ACTION_ID_GET_RESULTS = 'get_results'
    ACTION_ID_ON_POLL = 'on_poll'

    def __init__(self):

        # Call the super class
        super(SumoLogicConnector, self).__init__()

        # Initialize the sumo obj as None for checking later
        self._sumo = None
        self._state = {}

    def initialize(self):
        self._state = self.load_state()
        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _connect(self):

        # Check if this app is already connected
        if (self._sumo is not None):
            return phantom.APP_SUCCESS

        # Get the configuration for the environment
        config = self.get_config()

        # Retrieve the needed parameters for the SumoLogic object
        environment = config[SUMOLOGIC_JSON_ENVIRONMENT]
        access_id = config[SUMOLOGIC_JSON_ACCESS_ID]
        access_key = config[SUMOLOGIC_JSON_ACCESS_KEY]
        # collector_endpoint = SUMOLOGIC_COLLECTOR_ENDPOINT

        # Configure the endpoints to use based upon the environment set
        if environment == 'us1':
            api_endpoint = SUMOLOGIC_US1_API_ENDPOINT
        else:
            api_endpoint = SUMOLOGIC_OTHER_API_ENDPOINT.format(environment=environment)

        # Try to make the sumologic object
        try:
            if hasattr(self, 'get_phantom_home'):
                self._sumo = sumologic.SumoLogic(access_id, access_key, endpoint=api_endpoint, cookieFile=self.get_phantom_home() + '/apps/sumologic_8e235e70-57eb-4292-9b7c-6cc44847d837/cookies.txt')  # noqa
            else:
                self._sumo = sumologic.SumoLogic(access_id, access_key, endpoint=api_endpoint, cookieFile='/opt/phantom/apps/sumologic_8e235e70-57eb-4292-9b7c-6cc44847d837/cookies.txt')  # noqa
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, SUMOLOGIC_ERR_CONNECTION_FAILED, e)

        # Return success so that the other actions can be continued after they call connect
        return phantom.APP_SUCCESS

    def _delete_job(self, param):

        if (phantom.is_fail(self._connect())):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:

            self.save_progress("deleting search job: {}".format(param[SUMOLOGIC_JSON_JOB_ID]))
            status = self._sumo.delete("/search/jobs/{}".format(param[SUMOLOGIC_JSON_JOB_ID]))

        except Exception as e:

            return action_result.set_status(phantom.APP_ERROR,
                                            "Could not find the specified job.  It may have been deleted by Sumo Logic.",
                                            e)

        self.save_progress("deleted search job: {}".format(param[SUMOLOGIC_JSON_JOB_ID]))
        return action_result.set_status(phantom.APP_SUCCESS)


    def _get_results(self, param):

        if (phantom.is_fail(self._connect())):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        search_job = {"id": param[SUMOLOGIC_JSON_JOB_ID]}
        try:

            status = self._sumo.search_job_status(search_job)

        except Exception as e:

            return action_result.set_status(phantom.APP_ERROR,
                                            "Could not find the specified job.  It may have been deleted by Sumo Logic.",
                                            e)

        self.save_progress(SUMOLOGIC_PROG_POLLING_JOB)

        status = self._poll_job(status, search_job, action_result)

        if status['state'] == 'DONE GATHERING RESULTS':

            try:
                response = self._sumo.search_job_messages(search_job, 10000)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "The specified job could not be retreived.", e)

            action_result.add_data(response)
            action_result.add_data({"search_id": search_job['id']})
            action_result.set_summary({"total_objects": len(response["messages"])})
            return action_result.set_status(phantom.APP_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_ERROR, 'Error while getting results')

    def _test_connectivity(self):

        self.save_progress("Attempting to connect to API endpoint...")

        if phantom.is_fail(self._connect()):
            return self.set_status(phantom.APP_ERROR)

        self.save_progress("Requesting a single collector...")

        try:
            self._sumo.collectors(limit=1)
        except Exception as e:
            self.save_progress("Test Connectivity Failed")
            return self.set_status(phantom.APP_ERROR, str(e))

        self.save_progress("Connection to Sumo Logic with the specified environment has succeeded.")
        self.save_progress("Test Connectivity Passed")

        return self.set_status(phantom.APP_SUCCESS)

    def _poll_job(self, status, search_job, action_result, end=True):

        delay = 2

        # Poll the Search Job until it is done
        while status['state'] != 'DONE GATHERING RESULTS':

            # App error when the state changes to cancelled
            if status['state'] == 'CANCELLED':

                action_result.set_status(phantom.APP_ERROR, "Search Job was cancelled before finishing")
                return status

            if status['state'] == 'PAUSED' or status['state'] == 'FORCE PAUSED':

                action_result.set_status(phantom.APP_ERROR, "Search job has been paused")
                return status

            # Don't want to be polling forever, so just succeed and give the actionable ID as a result
            elif end and delay >= SUMOLOGIC_POLLING_TIME_LIMIT:

                action_result.set_summary({'search_id': search_job['id']})

                action_result.set_status(phantom.APP_SUCCESS)
                return status

            # Add a delay so that the server doesn't get overloaded
            time.sleep(delay)
            delay *= 2
            status = self._sumo.search_job_status(search_job)

        return status

    def _run_query(self, param):

        if (phantom.is_fail(self._connect())):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))
        search_string = param[SUMOLOGIC_JSON_QUERY]
        from_time = param.get(SUMOLOGIC_JSON_FROM_TIME, self._five_days_ago())
        to_time = param.get(SUMOLOGIC_JSON_TO_TIME, self._now())

        # Convert to milliseconds if not already
        if from_time == "0" or to_time == "0":
            return action_result.set_status(phantom.APP_ERROR, "Time range cannot start or end with zero")

        from_time = self._to_milliseconds(int(from_time))
        to_time = self._to_milliseconds(int(to_time))

        limit = param.get(SUMOLOGIC_JSON_LIMIT, SUMOLOGIC_JSON_DEFAULT_RESPONSE_LIMIT)
        resp_type = param.get(SUMOLOGIC_JSON_TYPE, SUMOLOGIC_JSON_DEFAULT_RESPONSE_TYPE)
        self.save_progress(SUMOLOGIC_PROG_CREATING_SEARCH_JOB)

        try:
            search_job = self._sumo.search_job(search_string, str(from_time), str(to_time))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                            "Could not create the job with {} {} {}".format(search_string, from_time,
                                                                                            to_time), e)

        status = self._sumo.search_job_status(search_job)

        self.save_progress(SUMOLOGIC_PROG_POLLING_JOB)

        status = self._poll_job(status, search_job, action_result)

        if status['state'] == 'DONE GATHERING RESULTS':

            try:

                if resp_type == "messages":

                    response = self._sumo.search_job_messages(search_job, limit=limit)

                    action_result.set_summary(
                        {"total_objects": len(response["messages"]), "search_id": search_job['id']})

                elif resp_type == "records":

                    response = self._sumo.search_job_records(search_job, limit=limit)

                    action_result.set_summary(
                        {"total_objects": len(response["records"]), "search_id": search_job['id']})
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "The specified job could not be retrieved.  "
                                                                   "If the response type was 'records', make sure that the query supplied is an aggregation query.")

            action_result.add_data(response)

            return action_result.set_status(phantom.APP_SUCCESS)

        else:

            return action_result.set_status(phantom.APP_ERROR, 'Error while getting results')

    def _on_poll(self, param):

        if (phantom.is_fail(self._connect())):
            return self.get_status()

        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()

        job_type = config['type']
        if self.is_poll_now():
            limit = int(param.get('artifact_count', 100))
        else:
            limit = int(config.get('max_messages', 10000))

        self.debug_print("limit: ", limit)

        if limit > 10000:
            limit = 10000

        from_time = self._state.get('last_query', self._to_milliseconds(self._first_run_time()))
        to_time = self._now()
        to_time = self._to_milliseconds(int(to_time))

        query = config.get('on_poll_query', '*')

        self.save_progress("Creating a search job")
        try:
            if config.get('search_by_receipt_time', False):
                # sumo.search_job doesn't have a byReceiptTime parameter. Just replicate search_job function here.
                params = {'query': query, 'from': int(from_time), 'to': int(to_time), 'timeZone': "UTC", 'byReceiptTime': True}
                r = self._sumo.post('/search/jobs', params)
                search_job = json.loads(r.text)
            else:
                search_job = self._sumo.search_job(query, int(from_time), int(to_time))

            self.save_progress("Created search job ({})".format(search_job['id']))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Failed to start job search: {0}".format(str(e)))
        self.save_progress("Waiting for search results")

        status = self._sumo.search_job_status(search_job)

        status = self._poll_job(status, search_job, action_result, end=False)
        if status['state'] == 'DONE GATHERING RESULTS':
            try:
                if job_type == "messages":
                    response = self._sumo.search_job_messages(search_job, limit=limit)
                elif job_type == "records":
                    response = self._sumo.search_job_records(search_job, limit=limit)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Invalid job type: {0}".format(job_type))

                try:
                    if config.get('delete_job_when_finished', False):
                        self.save_progress("Success with search job ({}). Deleting".format(search_job['id']))
                        self._sumo.delete("/search/jobs/{}".format(search_job['id']))
                except Exception as e:
                    self.save_progress("Error deleting search job. Continuing: " + str(e))

            except Exception as e:

                try:
                    if config.get('delete_job_when_finished', False):
                        self.save_progress("Error with search job ({}). Deleting".format(search_job['id']))
                        self._sumo.delete("/search/jobs/{}".format(search_job['id']))
                except Exception as e:
                    self.save_progress("Error deleting search job: " + str(e))

                return action_result.set_status(phantom.APP_ERROR, 'Error while getting results')

        else:  # Job Status is something other than DONE GATHERING RESULTS
            self.save_progress("Search job ({}) not completed, returning: {}".format(search_job['id'], status['state']))
            return action_result.get_status()

        self.save_progress("Processing response")

        if not self.is_poll_now():
            self._state['last_query'] = to_time + 1

        parser = config.get('message_parser')
        if parser:
            parser_name = config['message_parser__filename']
            self.save_progress("Using specified parser: {0}".format(parser_name))

            message_parser = imp.new_module("custom_parser")  # noqa
            try:
                exec parser in message_parser.__dict__
                ret_dict_list = message_parser.message_parser(response, query)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Unable to execute message parser: {0}".format(str(e)))
        else:  # No parser method provided, use default one instead
            ret_dict_list = sumologic_parser.message_parser(response, query)

        max_container = param.get('container_count')

        if (max_container > 0):
            ret_dict_list = ret_dict_list[:max_container]

        for container_dict in ret_dict_list:
            resp = self._save_container(container_dict, action_result)
            if phantom.is_fail(resp):
                return resp

        return action_result.set_status(phantom.APP_SUCCESS)

    def _save_container(self, container_dict, action_result):

        container = container_dict.get('container')

        ret_val, message, container_id = self.save_container(container)

        if (not ret_val):
            return action_result.set_status(phantom.APP_ERROR, message)

        artifacts = container_dict.get('artifacts')

        for artifact in artifacts:
            artifact['container_id'] = container_id
        if artifacts:
            artifacts[-1]['run_automation'] = True

        if (hasattr(self, 'save_artifacts')):
            status, message, artifact_id = self.save_artifacts(artifacts)
            if phantom.is_fail(status):
                return action_result.set_status(phantom.APP_ERROR, message)
        else:
            for artifact in artifacts:
                status, message, artifact_id = self.save_artifact(artifact)
            if phantom.is_fail(status):
                return action_result.set_status(phantom.APP_ERROR, message)

        return phantom.APP_SUCCESS

    def _five_days_ago(self):
        return int(time.mktime(time.localtime())) - SUMOLOGIC_FIVE_DAYS_IN_SECONDS

    def _first_run_time(self):
        config = self.get_config()
        days = int(config.get('first_run_previous_days', 5))
        if (days < 1):
            self.save_progress("Going 1 day in the past")
            days = 1
        return int(time.mktime(time.localtime()) - (days * 24 * 60 * 60))

    def _now(self):
        return int(time.mktime(time.localtime()))

    def _to_milliseconds(self, time):
        now = self._now()
        if time <= now:
            return int(time) * 1000
        return int(time)

    def handle_action(self, param):

        action = self.get_action_identifier()

        if (action == self.ACTION_ID_RUN_QUERY):
            result = self._run_query(param)
        elif (action == self.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            result = self._test_connectivity()
        elif (action == self.ACTION_ID_GET_RESULTS):
            result = self._get_results(param)
        elif (action == self.ACTION_ID_ON_POLL):
            return self._on_poll(param)
        elif (action == "delete job"):
            return self._handle_delete_job(param)

        return result


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

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
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

            print ("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SumoLogicConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
