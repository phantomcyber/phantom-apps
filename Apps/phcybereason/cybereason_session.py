import requests


class CybereasonSession:

    def __init__(self, connector):
        connector.save_progress("Logging in to the Cybereason console...")
        self.session = requests.Session()
        post_body = {
            "username": connector._username,
            "password": connector._password
        }
        config = connector.get_config()
        res = self.session.post(connector._base_url + "/login.html", data=post_body, verify=config["verify_server_cert"])
        if (self.session.cookies.get_dict().get("JSESSIONID") is None):
            connector.save_progress("Error when logging in to the the Cybereason console: No session cookie returned")
            connector.save_progress("Status code: {}, message: {}".format(res.status_code, res.text))
        elif (res.status_code != 200):
            connector.save_progress("Error when logging in to the Cybereason console: Unknown error")
            connector.save_progress("Status code: {}, message: {}".format(res.status_code, res.text))
        else:
            connector.save_progress("Successfully logged in to the Cybereason console")

    def get_session(self):
        return self.session

    def get_session_cookies(self):
        return self.session.cookies.get_dict()

    def post(self, **kwargs):
        return self.session.post(kwargs)
