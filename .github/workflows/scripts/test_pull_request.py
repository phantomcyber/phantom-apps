#!/usr/bin/env python3

import argparse
import datetime
import json
import os

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_SERVER_URL = os.environ['APPS_TEST_SERVER_URI']
API_SERVER_KEY = os.environ['APPS_TEST_SERVER_API_KEY']

DEFAULT_REQUEST_TIMEOUT = datetime.timedelta(seconds=30)
DEFAULT_QUERY_TIMEOUT = datetime.timedelta(seconds=60)

TEST_REQUEST_URL = f'https://{API_SERVER_URL}/pull_request/'
TEST_RESULTS_URL = f'https://{API_SERVER_URL}/pull_request/result/'

HEADERS = {
    'Authorization': f'Bearer {API_SERVER_KEY}',
}


def request_test(pr_number, requester=None, publish_results=False):
    data = {
        'id': pr_number,
        'requester': requester,
        'publish_results': publish_results,
    }

    return requests.post(TEST_REQUEST_URL,
                         verify=False,
                         data=data,
                         headers=HEADERS,
                         timeout=round(DEFAULT_REQUEST_TIMEOUT.total_seconds()))

def query_test_results(results_id, query_timeout=None):
    params = {
        'results_id': results_id,
    }

    default_request_timeout = round(DEFAULT_REQUEST_TIMEOUT.total_seconds())
    if query_timeout:
        request_timeout = max(default_request_timeout, query_timeout)
        params['timeout'] = query_timeout
    else:
        request_timeout = default_request_timeout

    return requests.get(TEST_RESULTS_URL,
                        verify=False,
                        params=params,
                        headers=HEADERS,
                        timeout=request_timeout)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('pull_request_id', type=int, help='the PR ID to request testing for')
    parser.add_argument('--requester', help='the username to ping on any github comments')
    parser.add_argument('--publish-results',
                        action='store_true',
                        help='whether to post results in a comment with a Google Drive link')
    args = parser.parse_args()

    print(f'Requesting testing of pull request number {args.pull_request_id} for "{args.requester}"')
    test_request_response = request_test(args.pull_request_id,
                                         requester=args.requester,
                                         publish_results=args.publish_results)
    test_request_response.raise_for_status()
    test_request_response_json = test_request_response.json()
    results_id = test_request_response_json['results_id']

    print(f'Querying for results with results ID "{results_id}"')
    query_timeout = round(DEFAULT_QUERY_TIMEOUT.total_seconds())
    query_results_response = query_test_results(results_id, query_timeout=query_timeout)
    query_results_response.raise_for_status()
    query_results_response_json = query_results_response.json()

    results = json.loads(query_results_response_json['results'])

    report = results.get('report')
    if report:
        print(f'TEST RESULTS REPORT:\n{report}', flush=True)

    success = results['success']
    if not success:
        error_message = results.get('message')
        if error_message:
            test_failure_message = f'Tests have failed with error message: "{error_message}"'
        else:
            test_failure_message = 'Tests have failed. Please review the report and make corrections as needed.'
        raise Exception(test_failure_message)

    print('Tests have succeeded.')
