# File: corelight_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from twitter_consts import *
import requests
import json
import datetime

# Library information: https://pypi.org/project/twitter/
from twitter import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TwitterConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(TwitterConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    # returns the current date - 7 days as this is the max twitter allows for the limit
    def _get_date_limit(self):
        d = datetime.datetime.now() - datetime.timedelta(days=7)

        # Converting date into YYYY-MM-DD
        return d.strftime('%Y-%m-%d')

    # creates and returns the twitter object for api. does not take any args
    def _create_twitter_object(self):
        config = self.get_config()
        token = config.get("token")
        token_secret = config.get("token_secret")
        consumer_key = config.get("consumer_key")
        consumer_secret = config.get("consumer_secret")

        t = Twitter(auth=OAuth(token, token_secret, consumer_key, consumer_secret))

        return t

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # create and auth twitter object
        t = self._create_twitter_object()

        self.save_progress("Connecting to endpoint")

        # get the list of tweets from the users timeline
        try:
            t.statuses.home_timeline(count=1)
        except Exception as e:
            self.save_progress(str(e))
            return action_result.set_status(phantom.APP_ERROR)

        self.save_progress("Successfully connected and authenticated")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_run_query(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # get the string to query twitter for
        query = param['query']

        # auth and search twitter
        t = self._create_twitter_object()

        # get time for searching
        time_limit = self._get_date_limit()

        try:
            search_results = t.search.tweets(q=query, until=time_limit)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, str(e))

        # store the full results returned
        action_result.add_extra_data(search_results)

        search_results = search_results['statuses']

        # create an empty dictionary to store tweet information
        twitter_results = []

        # The Twitter api returns a lot of information across tweets and re-tweets.
        # This condenses everything and formats some of the tweets
        # If you need the full results they are stored as extra data
        for i in search_results:
            tweet_info = {}
            # gets the actual tweet. remove new line charactes
            tweet_info["tweet"] = i['text'].replace("\n", "")
            tweet_info["username"] = i["user"]["screen_name"]
            if "retweeted_status" in i:
                tweet_info["retweeted status"] = i["retweeted_status"]["text"]
            else:
                tweet_info["retweeted status"] = ""
            hashtags = []
            for tags in i["entities"]["hashtags"]:
                hashtags.append(tags["text"])
            tweet_info["hashtags"] = hashtags

            tweet_urls = []
            for url in i["entities"]["urls"]:
                tweet_urls.append(url["expanded_url"])
            tweet_info["urls"] = tweet_urls
            # create a link to the actual tweet
            tweet_info["Tweet Link"] = "https://twitter.com/%s/status/%s" % (i["user"]["screen_name"], str(i["id"]))
            twitter_results.append(tweet_info)

        action_result.add_data(twitter_results)

        # count how many tweets for the summary
        tweet_count = 0
        print "\t\t TWEETS \t\t"
        for i in search_results:
            if i['text']:
                tweet_count = tweet_count + 1

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['Found Tweets'] = tweet_count

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'run_query':
            ret_val = self._handle_run_query(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')

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

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TwitterConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
