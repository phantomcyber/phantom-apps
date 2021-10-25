# File: cybereason_session.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)


import requests


class CybereasonSession:

    def __init__(self, connector):
        connector.save_progress("Logging in to the Cybereason console...")
        self.session = requests.Session()
        post_body = {
            "username": connector._username,
            "password": connector._password
        }
        try:
            url = "{0}/login.html".format(connector._base_url)
            res = self.session.post(url, data=post_body, verify=connector._verify_server_cert)
            if self.session.cookies.get_dict().get("JSESSIONID") is None:
                connector.save_progress("Error when logging in to the the Cybereason console: No session cookie returned")
                connector.save_progress("Status code: {}".format(res.status_code))
                connector.debug_print("Status code: {}, message: {}".format(res.status_code, res.text))
            elif res.status_code != 200:
                connector.save_progress("Error when logging in to the Cybereason console: Unknown error")
                connector.save_progress("Status code: {}".format(res.status_code))
                connector.debug_print("Status code: {}, message: {}".format(res.status_code, res.text))
            else:
                connector.save_progress("Successfully logged in to the Cybereason console")
                connector.save_progress('CybereasonSession created')
        except requests.exceptions.InvalidSchema:
            connector.save_progress("Error connecting to server. No connection adapters were found for %s" % (url))
        except requests.exceptions.InvalidURL:
            connector.save_progress("Error connecting to server. Invalid URL %s" % (url))
        except requests.exceptions.ConnectionError:
            connector.save_progress("Error Details: Connection Refused from the Server")
        except Exception as e:
            err = connector._get_error_message_from_exception(e)
            connector.save_progress("Error connecting to server. {0}".format(err))

    def get_session(self):
        return self.session

    def get_session_cookies(self):
        return self.session.cookies.get_dict()

    def post(self, **kwargs):
        return self.session.post(kwargs)
