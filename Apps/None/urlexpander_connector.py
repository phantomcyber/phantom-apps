# --
# File: urlexpander_connector.py
#
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Imports local to this App
from urlexpander_consts import *

import simplejson as json
import datetime
import requests


def _json_fallback(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj


# Define the App Class
class urlexpanderConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(urlexpanderConnector, self).__init__()

    def _test_connectivity(self, param):

        # goo.gl connectivity test

        config = self.get_config()

        # get the server and key data
        googl_server = config.get(URLEXPANDER_JSON_GOOGL_SERVER)
        googl_apikey = config.get(URLEXPANDER_JSON_GOOGL_APIKEY)

        if (not googl_server):
            self.save_progress("Goo.gl server not set")
            return self.get_status()

        # Progress
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, googl_server)
        # www.googleapis.com/urlshortener/v1/url?
        try:
            r = requests.get('https://{}/urlshortener/v1/url?'.format(googl_server), params={'key': googl_apikey, 'shortUrl': 'http://goo.gl/fbsS'}, verify=True)
            if r.status_code == 200:
                self.save_progress(URLEXPANDER_SUCC_CONNECTIVITY_TEST)
                self.set_status(phantom.APP_SUCCESS)
            else:
                self.set_status_save_progress(phantom.APP_ERROR, "Test failed: HTTPS Post returned code: {}".format(r.status_code))

        except Exception as e:
            self.set_status(phantom.APP_ERROR, URLEXPANDER_ERR_SERVER_CONNECTION, e)
            self.append_to_message(URLEXPANDER_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        # bit.ly connectivity test

        # get the server and key data
        bitly_server = config.get(URLEXPANDER_JSON_BITLY_SERVER)
        bitly_apikey = config.get(URLEXPANDER_JSON_BITLY_APIKEY)

        if (not bitly_server):
            self.save_progress("Bit.ly server not set")
            return self.get_status()

        # Progress
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, bitly_server)
        # api-ssl.bitly.com

        try:
            r = requests.post('https://{}/v3/expand?'.format(bitly_server), data={'access_token': bitly_apikey, 'shortUrl': 'http://bit.ly/1RmnUT'}, verify=True)
            if r.status_code == 200:
                self.set_status(self.get_status())
            else:
                return self.set_status(phantom.APP_ERROR, "Test failed: HTTPS Post returned code: {}".format(r.status_code))

        except Exception as e:
            self.set_status(phantom.APP_ERROR, URLEXPANDER_ERR_SERVER_CONNECTION, e)
            self.append_to_message(URLEXPANDER_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(self.get_status(), URLEXPANDER_SUCC_CONNECTIVITY_TEST)

    def _expand_url(self, param):

        # Get the config
        config = self.get_config()

        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        # Get url and test for service
        shortUrl = param.get(URLEXPANDER_URL)

        # Search for goo.gl short link
        if shortUrl.find('goo.gl', 0, 20) > 0:
            # Get the server
            server = config.get(URLEXPANDER_JSON_GOOGL_SERVER)
            apikey = config.get(URLEXPANDER_JSON_GOOGL_APIKEY)

            if (not server):
                self.save_progress("Goo.gl server not set")
                return self.get_status()

            self.save_progress("Querying goo.gl server")

            # Progress
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, server)

            try:
                response = requests.get('https://{}/urlshortener/v1/url?'.format(server), params={'key': apikey, 'shortUrl': shortUrl}, verify=True)
                if response.status_code == 200:
                    action_result.set_status(phantom.APP_SUCCESS)

            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, URLEXPANDER_ERR_SERVER_CONNECTION, e)
                action_result.append_to_message(URLEXPANDER_ERR_CONNECTIVITY_TEST)
                return action_result.get_status()

            data = response.json()
            try:
                longUrl = data['longUrl']
                results = {
                    "longUrl": longUrl,
                    "raw": data
                }
            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, 'API Error', e)
                results = {'raw': data}
            self.debug_print(results)
            action_result.add_data(results)

        # Search for bit.ly short link
        elif shortUrl.find('bit.ly', 0, 20) > 0:
            # Get the server
            server = config.get(URLEXPANDER_JSON_BITLY_SERVER)
            apikey = config.get(URLEXPANDER_JSON_BITLY_APIKEY)

            if (not server):
                self.save_progress("Bit.ly server not set")
                return self.get_status()

            self.save_progress("Querying Bit.ly server")

            # Progress
            self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, server)

            try:
                url = "https://{}/v3/expand".format(server)
                params = {"access_token": "{}".format(apikey), "shortUrl": shortUrl}
                headers = {'cache-control': "no-cache"}
                response = requests.post(url, headers=headers, params=params)
                action_result.set_status(phantom.APP_SUCCESS)

            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, URLEXPANDER_ERR_SERVER_CONNECTION, e)
                action_result.append_to_message(URLEXPANDER_ERR_CONNECTIVITY_TEST)
                return action_result.get_status()

            data = response.json()
            # self.debug_print('RES_DEBUG: {}'.format(data))
            try:
                bitly_dict = data['data']['expand'][0]
                longUrl = bitly_dict['long_url']
                results = {
                    "longUrl": longUrl,
                    "raw": data
                }
            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, 'API Error', e)
                results = {'raw': data}
            self.debug_print(results)
            action_result.add_data(results)

        return action_result.get_status()

    def handle_action(self, param):

        action = self.get_action_identifier()
        self.debug_print("action_id", self.get_action_identifier())

        if (action == "expand_url"):
            ret_val = self._expand_url(param)
        elif (action == "test_asset_connectivity"):
            ret_val = self._test_connectivity(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = urlexpanderConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
