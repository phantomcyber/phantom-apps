import requests
import json
import time
from datetime import datetime, timedelta

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_HOST = "https://api.twinwave.io"
API_VERSION = "v1"
EXPIRE_SECONDS = 86400
URL_REGEX = r'(?:(?:https?|ftp|hxxps?):\/\/|www\[?\.\]?|ftp\[?\.\]?)(?:[-\w\d]+\[?\.\]?)+[-\w\d]+(?::\d+)?' \
            r'(?:(?:\/|\?)[-\w\d+&@#\/%=~_$?!\-:,.\(\);]*[\w\d+&@#\/%=~_$\(\);])?'


class AuthenticationException(Exception):
    pass


class Twinwave():

    def __init__(self, config):
        self._host = f"{API_HOST}/{API_VERSION}"
        self._base_url = 'https://app.twinwave.io/'
        self._api_key = "{}".format(config.get('api_token'))
        self._proxy = None
        self._verify = config.get('verify')
        self._since = int(config.get('since'))

    def get_token(self):
        auth_url = f"{self._host}/accesstoken"
        resp = requests.get(auth_url, verify=self._verify, proxies=self._proxy)
        if resp.ok:
            return resp.json()
        else:
            raise AuthenticationException("Error getting access token, Please check the username and password")

    def get_header(self):
        return {'X-API-KEY': self._api_key}

    def get_recent_jobs(self, num_jobs=10, username=None, source=None, state=None):
        url = f"{self._host}/jobs/recent"
        params = {}
        params["count"] = num_jobs
        if username:
            params["username"] = username
        if source:
            params["source"] = source
        if state:
            params["state"] = state
        resp = requests.get(url, params=params, headers=self.get_header(), verify=self._verify,
                            proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def poll_for_done_jobs(self, token):
        url = f"{self._host}/jobs/poll"
        time_now = datetime.now()
        if token:
            resp = requests.get(url, params={"token": token}, headers=self.get_header())
        else:
            since = self._since
            if not since:
                since = 0
                epoch_convert_time = time_now.timestamp()
            else:
                prev_date = time_now - timedelta(hours=since)
                epoch_convert_time = prev_date.timestamp()
            try:
                resp = requests.get(url, params={"since": int(epoch_convert_time)}, headers=self.get_header())
            except Exception:
                time.sleep(10)
            payload = resp.json()
        return payload

    def get_engines(self):
        url = f"{self._host}/engines"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def get_job(self, job_id):
        url = f"{self._host}/jobs/{job_id}"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def get_task_normalized_forensics(self, job_id, task_id):
        url = f"{self._host}/jobs/{job_id}/tasks/{task_id}/forensics"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def get_job_normalized_forensics(self, job_id):
        url = f"{self._host}/jobs/{job_id}/forensics"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def get_task_raw_forensics(self, job_id, task_id):
        url = f"{self._host}/jobs/{job_id}/tasks/{task_id}/rawforensics"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)

        # do not raise an exception for 404
        if resp.status_code == 404:
            return resp.json()
        resp.raise_for_status()
        return resp.json()

    def submit_url(self, scan_url, engine_list=[], parameters=None, priority=None, profile=None):
        url = f"{self._host}/jobs/urls"
        req = {"url": scan_url, "engines": engine_list, "parameters": parameters}
        if priority:
            req['priority'] = priority
        if profile:
            req['profile'] = profile

        resp = requests.post(url, json=req, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def submit_file(self, file_name, file_obj, engine_list=[], priority=None, profile=None):
        url = f"{self._host}/jobs/files"
        payload = {}
        file_dict = {"filedata": file_obj}
        payload["engines"] = (None, json.dumps(engine_list))
        payload['filename'] = (None, file_name)
        payload['priority'] = priority
        payload['profile'] = profile

        resp = requests.post(url, data=payload, files=file_dict, headers=self.get_header(), verify=self._verify,
                             proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def resubmit_job(self, job_id):
        url = f"{self._host}/jobs/{job_id}/reanalyze"
        resp = requests.post(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.json()

    def download_submitted_resources(self, job_id, sha256):
        url = f"{self._host}/jobs/{job_id}/resources/{sha256}"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy, stream=True)
        resp.raise_for_status()
        return resp.content

    def get_artifact_url(self, path):
        url = f"{self._host}/jobs/artifacts/{path}"
        resp = requests.get(url, headers=self.get_header(), verify=self._verify, proxies=self._proxy)
        resp.raise_for_status()
        return resp.content

    def search_across_jobs_and_resources(self, term, field, count, shared_only, submitted_by, timeframe, page, type):
        query_params = {}
        if term:
            query_params['term'] = term
        if field:
            query_params['field'] = field
        if count:
            query_params['count'] = count
        if shared_only:
            query_params['shared_only'] = shared_only
        if submitted_by:
            query_params['submitted_by'] = submitted_by
        if timeframe:
            query_params['timeframe'] = timeframe
        if page:
            query_params['page'] = page
        if type:
            query_params['type'] = type
        url = f"{self._host}/jobs/search"
        resp = requests.get(url, headers=self.get_header(), params=query_params, verify=self._verify,
                            proxies=self._proxy)
        resp.raise_for_status()

        return resp.json()


if __name__ == '__main__':

    config = {
        'api_key': '50e6a672fbef8dc5a68c74c3c671a5ef736ab49036789726',
        'verify': False
    }
    twinwave = Twinwave(config)
    # twinwave.poll_for_done_jobs()
