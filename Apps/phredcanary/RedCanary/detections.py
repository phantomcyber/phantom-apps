# File: detections.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

import requests

PAGE_SIZE = 50
DETECTIONS = []
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class RCDetections():
    """
    Class for enriching detections from Red Canary's API
    """

    def __init__(self, detections, token):
        """
        Parameters:
            :detections:    List of detections returned by RC API
            :token:         RC API token
        """

        # super(RCDetections, self).__init__()
        self.Detections = detections
        self.headers = self._generate_headers(token)

        # Dictionary that track state of detection enrichment selections
        self.state = dict({
            "user_info": False,
            "endpoint_info": False,
            "detection_info": False,
            "detector_info": False
        })

    def _generate_headers(self, token):
        """
        Returns dictionary for headers used in Red Canary API request
        """
        return {'X-Api-Key': token}

    def _make_url_get_request(self, url, headers):
        """
        Makes API get request and returns raw response

        Parameters:
            :url:       Address to query
            :headers:   Headers to use in request. Must contain API key
        Returns:
            :return: raw respnose from request
        """
        print(f"Making API request to {url}")
        try:
            return requests.get(url, headers=headers)
        except:
            print(f"Exception occurred making request to {url} with headers {headers}")
            raise

    def _parse_user_details(self, json_response):
        """
        Parses json response and returns tuple of success/error and attribute dictionary

        Parameters:
            :json_response: Response from https://{domain}.my.redcanary.co/openapi/v3/endpoint_users
        Returns:
            :return: Tuple(True/False, dictionary of user details)
        """
        user_dict = dict()

        # We assume there is only ever a single user entry
        # If that's not the case we will fail and return the data
        if json_response.get('meta').get('total_items') != 1:

            return False, user_dict

        try:
            rc_uid = json_response.get('data')[0].get('id')

            user_data = json_response.get('data')[0].get('attributes')

            user_dict.update({rc_uid: {
                'rc_uid': json_response.get('data')[0].get('id'),
                'username': user_data.get('username'),
                'uid': user_data.get('uid'),
                'domain': user_data.get('reporting_tags').get('domain'),
                'local_account': user_data.get('reporting_tags').get('local_account')
            }})

            self.Users.update(user_dict)

        except Exception:
            return False, user_dict

        return True, user_dict

    def _parse_endpoint_details(self, json_response):
        """
        Parses json response and returns tuple of success/error and attribute dictionary

        Parameters:
            :json_response: Response from https://{domain}.my.redcanary.co/openapi/v3/endpoints
        Returns:
            :return: Tuple(True/False, dictionary of endpoint details)
        """
        endpoint_dict = dict()

        # We assume there is only ever a single user entry
        # If that's not the case we will fail and return the data
        try:
            if json_response.get('meta').get('total_items') != 1:
                return False, endpoint_dict

            rc_enid = json_response.get('data')[0].get('id')
            endpoint_dict.update({rc_enid: json_response.get('data')[0]})

            self.Endpoints.update(endpoint_dict)

        except Exception:
            return False, endpoint_dict

        return True, endpoint_dict

    def _gen_user_details(self, detection):
        """
        Generates dictionary of user details
        Will add dictionary to user list

        Parameters:
            :detection: single detection item
        Returns:
            :return: Tuple(True/False, dictionary of user details)
        """

        rc_uid = detection.get('relationships', {}).get('related_endpoint_user', {}).get('data', {}).get('id')

        if rc_uid in self.Users:
            return True, self.Users.get(rc_uid)

        user_link = detection.get('relationships', {}).get('related_endpoint_user', {}).get('links', {}).get('related')

        response = self._make_url_get_request(user_link, self.headers)

        return self._parse_user_details(response.json())

    def _gen_endpoint_details(self, detection):
        """
        Generates dictionary of endpoint details
        Will add dictionary to endpoint list

        Parameters:
            :detection: single detection item
        Returns:
            :return: Tuple(True/False, dictionary of endpoint details)
        """

        rc_enid = detection.get('relationships', {}).get('affected_endpoint', {}).get('data', {}).get('id')

        if rc_enid in self.Endpoints:
            return True, self.Endpoints.get(rc_enid)

        endpoint_link = detection.get('relationships', {}).get('affected_endpoint', {}).get('links', {}).get('related')

        response = self._make_url_get_request(endpoint_link, self.headers)

        return self._parse_endpoint_details(response.json())

    def _gen_detection_details(self, detection):
        """
        Generates dictionary of detection details and adds to detection dictionary

        Parameters:
            :detection: single detection item
        Returns:
            :return: None
        """

        detection_link = detection.get('links', {}).get('activity_timeline', {}).get('href')

        response = self._make_url_get_request(detection_link, self.headers)

        detection.update(
            {'detection_details': response.json().get('data')}
        )

    def _gen_detector_details(self, detection):
        """
        Generates dictionary of detector details and adds to detection dictionary

        Parameters:
            :detection: single detection item
        Returns:
            :return: None
        """

        detection_link = detection.get('links', {}).get('detectors', {}).get('href')

        response = self._make_url_get_request(detection_link, self.headers)
        detection.update(
            {'detector_details': response.json().get('data')}
        )

    def get_user_details(self):

        # Create empty list of users
        print("getting user details")
        self.Users = dict()

        self.state["user_info"] = True

        for detection in self.Detections:
            # dictionary of user information
            status, user_details = self._gen_user_details(detection)

            if status:
                detection.update({'user_details': user_details})

        return True

    def get_detection_timeline(self):

        # Create empty list of users
        self.state["detection_info"] = True
        for detection in self.Detections:
            self._gen_detection_details(detection)

        return None

    def get_endpoint_details(self):

        # Create empty list of endpoints
        print("getting endpoint details")
        self.Endpoints = dict()

        self.state["endpoint_info"] = True

        for detection in self.Detections:
            # dictionary of user information
            status, endpoint_details = self._gen_endpoint_details(detection)

            if status:
                detection.update({'endpoint_details': endpoint_details})

        return True

    def get_detector_details(self):

        # Create empty list of endpoints
        print("getting detector details")
        self.Detectors = dict()

        self.state["detector_info"] = True

        for detection in self.Detections:
            self._gen_detector_details(detection)

        return None

    def get_all_details(self):
        """
        Calls all enriching function
        Returns list of all detections
        """

        self.get_detector_details()
        self.get_detection_timeline()
        self.get_user_details()
        self.get_endpoint_details()

        return self.Detections
