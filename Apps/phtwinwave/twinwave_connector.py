# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom import vault
from phantom.vault import Vault

# Usage of the consts file is recommended
from phtwinwave import Twinwave
from twinwave_exceptions import TwinwaveConnectionException
import requests
import json
import time


class RetVal(tuple):

    def __new__(cls, val1, val2=None):

        return tuple.__new__(RetVal, (val1, val2))


class TwinWaveConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TwinWaveConnector, self).__init__()
        self._state = None
        self._base_url = None

    def initialize(self):

        # Load the state in initialize, use it to store data that needs to be accessed across actions
        self._state = self.load_state()

        # Get the asset config from Phantom
        config = self.get_config()

        # Use the config to initialize fortisiem object to handle connections to the fortisiem server
        self._twinwave = Twinwave(config)

        return phantom.APP_SUCCESS

    def _add_to_vault(self, data, job_id):
        # this temp directory uses "V" since this function is from the CLASS instance not the same as the "v" vault instance
        container_id = self.get_container_id()
        Vault.create_attachment(data, container_id, file_name="Artifact from Job:{}".format(job_id))

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")

        try:
            self._twinwave.get_engines()

        except TwinwaveConnectionException:
            # the call to the 3rd party device or service failed
            # action result should contain all the error details so just return from here
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed.")
        return action_result.set_status(phantom.APP_SUCCESS)

    # def handle_exception(self, params):

    def _handle_search_across_jobs(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")

        try:
            terms = params.get('terms')
            field = params.get('field')
            count = params.get('count')
            shared_only = params.get('shared_only')
            submitted_by = params.get('submitted_by')
            timeframe = params.get('timeframe')
            page = params.get('page')
            type = params.get('type')
            search_results = self._twinwave.search_across_jobs_and_resources(terms, field, count, shared_only, submitted_by, timeframe, page, type)

        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to search across jobs")
            return action_result.get_status()

        action_result.add_data(search_results)
        self.save_progress("Search results found")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_artifacts_url(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")

        try:
            artifact_url = params.get("path")
            job_id = params.get("job_id")
            artifact_data = self._twinwave.get_artifact_url(artifact_url)
            self._add_to_vault(artifact_data, job_id)

        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to retrieve artifact urls")
            return action_result.get_status()

        self.save_progress("Sending temp URL for artifact")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_download_submitted_resource(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")

        try:
            job_id = params.get("job_id")
            sha256 = params.get('sha256')
            resource = self._twinwave.download_submitted_resources(job_id, sha256)

            # this temp directory uses "V" since this function is from the CLASS instance not the same as the "v" vault instance
            vault_tmp_dir = Vault.get_vault_tmp_dir()
            file_path = "{}/{}".format(vault_tmp_dir, sha256)
            with open(file_path, 'wb') as temp_file:
                temp_file.write(resource)
            self._add_to_vault(file_path, job_id)

        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to download the submitted resource")
            return action_result.get_status()

        self.save_progress("Downloaded submitted resource")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_task_raw_forensics(self, params):
        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")

        try:
            job_id = params.get("job_id")
            task_id = params.get("task_id")
            get_task = self._twinwave.get_task_raw_forensics(job_id, task_id)

        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to get forensics")
            return action_result.get_status()

        action_result.add_data(get_task)
        self.save_progress("Task Naw Forensics Retrieved")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_task_normalized_forensics(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")

        try:
            job_id = params.get("job_id")
            task_id = params.get("task_id")
            get_task = self._twinwave.get_task_normalized_forensics(job_id, task_id)

        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to retrieve forensics")
            return action_result.get_status()

        action_result.add_data(get_task)
        self.save_progress("Task Normal Forensics Retrieved")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_job_normalized_forensics(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")

        try:
            job_id = params.get("job_id")
            job_fore = self._twinwave.get_job_normalized_forensics(job_id)

        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to retrieve forensics")
            return action_result.get_status()

        action_result.add_data(job_fore)
        self.save_progress("Job Normal Forensics Retrieved")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_resubmit_job(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")

        try:
            job_id = params.get("job_id")
            resubmit = self._twinwave.resubmit_job(job_id)

        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to resubmit job")
            return action_result.get_status()

        action_result.add_data(resubmit)
        self.save_progress("Job Normal Forensics Retrieved")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_submit_file(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")

        try:
            file = params.get("file")
            success, message, info = vault.vault_info(vault_id=file)
            file_path = info[0]['path']
            file_name = info[0]['name']
            f = open(file_path, "rb")
            file_data = f.read()
            res = self._twinwave.submit_file(file_name, file_data)
            # self.save_progress(str(re))
            job_id = res['JobID']
            job_summary = self._twinwave.get_job(job_id)
            timeout = time.time() + 60 * 30
            self.debug_print('THIS IS THE JOB ID!!', dump_object=job_id)
            while job_summary['State'] != "done":
                job_summary = self._twinwave.get_job(job_id)
                time.sleep(10)
                self.debug_print('status = {}, current time = {}'.format(job_summary['State'], timeout))
                if time.time() > timeout:
                    raise TwinwaveConnectionException('Job status time exceeded 30 minutes')
        except TwinwaveConnectionException as err:
            self.save_progress(str(err))
            self.save_progress("Unable to submit file")
            return action_result.get_status()
        job_summary['url'] = 'https://app.twinwave.io/job/{}'.format(job_id)
        action_result.add_data(job_summary)
        self.debug_print('results', dump_object=job_summary)
        self.save_progress("Submitted File")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_submit_url(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")

        try:
            url = params.get("url")
            url_result = self._twinwave.submit_url(url)
            job_id = url_result['JobID']
            job_summary = self._twinwave.get_job(job_id)
            timeout = time.time() + 60 * 30
            self.debug_print('THIS IS THE JOB ID!!', dump_object=job_id)
            while job_summary['State'] != "done":
                job_summary = self._twinwave.get_job(job_id)
                time.sleep(10)
                # self.debug_print('status = {}, current time = {}'.format(job_summary['State'], timeout))
                if time.time() > timeout:
                    raise TwinwaveConnectionException('Job Status time exceeded 30 minutes')
        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to resubmit url")
            return action_result.get_status()
        job_summary['url'] = 'https://app.twinwave.io/job/{}'.format(job_id)
        action_result.add_data(job_summary)
        self.debug_print('results', dump_object=job_summary)
        self.save_progress("Submitted URL")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_engines(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")

        try:
            response = self._twinwave.get_engines()

        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to get engines")
            return action_result.get_status()

        action_result.add_data(response)
        self.save_progress("Submitted URL")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_recent_jobs(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")
        # save_state load_state to get last run job date to reference
        # after save the run now as last run
        # parameter uses an integer from how many days back you want
        # parameter count uses start at 100 if applicable if not start at 0
        # paremter pull for "DONE" jobs
        try:
            list = self._twinwave.get_recent_jobs(params)

        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to get jobs")
            return action_result.get_status()

        action_result.add_data(list)
        self.save_progress("Gathered Recent Jobs")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_poll_recent_jobs(self, params):
        action_result = self.add_action_result(ActionResult(dict(params)))
        state_dict = self.load_state()
        next_token = state_dict.get("token", None)
        try:
            payload = self._twinwave.poll_for_done_jobs(next_token)
        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to get jobs")
            return action_result.get_status()
        jobs = payload.get("Jobs")
        if jobs:
            for job in jobs:
                container = {}
                job_id = job["ID"]
                url = job["Submission"]["Name"]
                container['name'] = url
                container['source_data_identifier'] = job_id
                container['run_automation'] = True
                container['url'] = url
                ret_val, msg, cid = self.save_container(container)
                if phantom.is_fail(ret_val):
                    self.save_progress("Error saving container: {}".format(msg))
                    self.debug_print("Error saving container: {} -- CID: {}".format(msg, cid))
            self.debug_print('payload!!!!!!!!!!!!!!!!!!!!!', dump_object=url)
        else:
            self.debug_print('payload_empty')
        state_dict["token"] = payload.get("NextToken")
        self.save_state(state_dict)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_job_summary(self, params):

        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to endpoint")

        try:
            job_id = params.get("job_id")
            job_summery = self._twinwave.get_job(job_id)

        except TwinwaveConnectionException:
            self.save_progress(str(TwinwaveConnectionException))
            self.save_progress("Unable to get job")
            return action_result.get_status()

        action_result.add_data(job_summery)
        self.save_progress("Job Summary Retrieved")
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        self.save_progress("action_id={}".format(action_id))

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'twinwave_search_across_jobs_and_resources':
            ret_val = self._handle_search_across_jobs(param)

        elif action_id == 'twinwave_get_artifact_url':
            ret_val = self._handle_get_artifacts_url(param)

        elif action_id == 'twinwave_download_submitted_resource':
            ret_val = self._handle_download_submitted_resource(param)

        elif action_id == 'twinwave_get_task_raw_forensics':
            ret_val = self._handle_get_task_raw_forensics(param)

        elif action_id == 'twinwave_get_task_normalized_forensics':
            ret_val = self._handle_get_task_normalized_forensics(param)

        elif action_id == 'twinwave_get_job_normalized_forensics':
            ret_val = self._handle_get_job_normalized_forensics(param)

        elif action_id == 'twinwave_get_job_summary':
            ret_val = self._handle_get_job_summary(param)

        elif action_id == 'twinwave_list_recent_jobs':
            ret_val = self._handle_list_recent_jobs(param)

        elif action_id == 'twinwave_resubmit_job':
            ret_val = self._handle_resubmit_job(param)

        elif action_id == 'twinwave_submit_file':
            ret_val = self._handle_submit_file(param)

        elif action_id == 'twinwave_submit_url':
            ret_val = self._handle_submit_url(param)

        elif action_id == 'twinwave_get_engines':
            ret_val = self._handle_get_engines(param)

        elif action_id == 'on_poll':
            ret_val = self._handle_poll_recent_jobs(param)
        return ret_val

    def finalize(self):
        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
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
            login_url = "https://127.0.0.1" + '/login'

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
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TwinWaveConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
