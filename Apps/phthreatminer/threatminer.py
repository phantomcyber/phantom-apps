# Threat Miner Class
import requests
import logging
import json
import time

# Establish Logging.
logging.basicConfig()
logger = logging.getLogger('ThreatMiner')


class threatMiner():
    def __init__(
        self,
        # Replace the base url to the url that you need
        base_url='https://api.threatminer.org/v2/',
        prettyPrint=False
    ):
        """
        Threat Miner Python Wrapper.

        Available Functions
        - test_connect              Provides a method to test connectivity
        - get_domain                This function performs lookups against
                                    domains depending on the function
        - get_ip                    This function performs lookups against
                                    IPs depending on the function
        - get_sample                This function performs lookups against
                                    hashes depending on the functions
        - get_imphash               This function performs lookups against
                                    imphashes depending on the functions
        - get_ssdeep                This function performs lookups against
                                    ssdeep depending on the functions
        - get_ssl                   This function performs lookups against
                                    ssl depending on the functions
        - get_email                 This function performs lookups against
                                    email depending on the functions
        - get_av                    This function performs lookups against
                                    AV depending on the functions

        Usage:
        # Should match your class name.  Delete this line
        s = threatMiner()

        s.function_name(valid_variables)
        """

        # Create Requests Session
        self.session = requests.session()
        # Create Base URL variable to allow for updates in the future
        self.base_url = base_url
        # Create Pretty Print variable
        self.prettyPrint = prettyPrint

        # Create endpoint
        endpoint = '{}domain.php?q=vwrm.com&rt=1'.format(self.base_url)

        # Initiate Ping to Threat Miner Endpoint
        self.ping = self.session.get(endpoint)

        # Request failed returning false and logging an error
        if self.ping.status_code != 200:
            logger.error(
                "Error connecting to Threat Miner, error message: {}".format(
                    self.ping.text))

    def logger_out(self, level, function_name, format_var):
        if level == "warning":
            message = ("{}: Error with query to threatMiner,"
                       "error message: {}".format(function_name, format_var))
            return logger.warning(message)

    def parse_output(self, input):
        # If prettyPrint set to False
        if self.prettyPrint is False:
            return json.dumps(input)
        # If prettyPrint set to True
        elif self.prettyPrint is True:
            print json.dumps(input, indent=4)

    def test_connect(self):
        """
        Function:   Test ping to Threat Miner API

        Usage:
        s = threatMiner()
        s.test_connect()
        """

        endpoint = '{}domain.php?q=vwrm.com&rt=1'.format(self.base_url)
        # Make connection to the ping endpoint
        r = self.session.get(endpoint)
        # If the request is successful
        if r.status_code == 200:
            # Specify Output as JSON
            return True
        # Request failed returning false and logging an error
        else:
            self.logger_out("warning", "test_connect", r.text)
            return False

    def get_domain(self, domain, function):
        """
        Function:   This function performs lookups against
                    domains depending on the function

        :param function:    Required - These are the functions
                            that threat miner provide for domain lookups
        Functions
            1 - WHOIS
            2 - Passive DNS
            3 - Example Query URI
            4 - Related Samples (hash only)
            5 - Subdomains
            6 - Report tagging

        Usage:
        s = threatMiner()
        s.get_domain("vwrm.com", 1)
        """
        # URL that we are querying
        endpoint = '{}/domain.php?q={}&rt={}'.format(
                  self.base_url, domain, function)
        # Create a request
        r = self.session.get(endpoint)
        # Sleep to ensure throttling
        time.sleep(7)
        # If the request is successful
        if r.status_code == 200:
            if int(r.json()['status_code']) == 200:
                output = r.json()
                return self.parse_output(output)
            else:
                status_message = r.json()['status_message']
                self.logger_out("warning", "get_domain", status_message)
                return False
        # Request failed returning false and logging an error
        else:
            # Write a warning to the console
            status_message = r.json()['status_message']
            self.logger_out("warning", "get_domain", status_message)
            return False

    def get_ip(self, ip, function):
        """
        Function:   This function performs lookups
                    against IPs depending on the function

        :param function:    Required - These are the functions
                            that threat miner provide for ip lookups

        Functions
            1 - WHOIS
            2 - Passive DNS
            3 - URIs
            4 - Related Samples (hash only)
            5 - SSL Certificates (hash only)
            6 - Report tagging

        Usage:
        s = threatMiner()
        s.get_ip("216.58.213.110", 1)
        """
        # URL that we are querying
        endpoint = '{}/host.php?q={}&rt={}'.format(self.base_url, ip, function)
        # Create a request
        r = self.session.get(endpoint)
        # Sleep to ensure throttling
        time.sleep(7)
        # If the request is successful
        if r.status_code == 200:
            if int(r.json()['status_code']) == 200:
                output = r.json()
                return self.parse_output(output)
            else:
                # Write a warning to the console
                status_message = r.json()['status_message']
                self.logger_out("warning", "get_ip", status_message)
                return False
        # Request failed returning false and logging an error
        else:
            # Write a warning to the console
            status_message = r.json()['status_message']
            self.logger_out("warning", "get_ip", status_message)
            return False

    def get_sample(self, sample, function):
        """
        Function:   This function performs lookups against
                    hashes depending on the functions

        :param function:    Required - These are the functions that
                            threat miner provide for hash lookups

        Functions
            1 - Metadata
            2 - HTTP Traffic
            3 - Hosts (domains and IPs)
            4 - Mutants
            5 - Registry Keys
            6 - AV Detections
            7 - Report tagging

        Usage:
        s = threatMiner()
        s.get_sample("e6ff1bf0821f00384cdd25efb9b1cc09", 1)
        """
        # URL that we are querying
        endpoint = '{}/sample.php?q={}&rt={}'.format(
                    self.base_url, sample, function)
        # Create a request
        r = self.session.get(endpoint)
        # Sleep to ensure throttling
        time.sleep(7)
        # If the request is successful
        if r.status_code == 200:
            if int(r.json()['status_code']) == 200:
                output = r.json()
                return self.parse_output(output)
            else:
                # Write a warning to the console
                status_message = r.json()['status_message']
                self.logger_out("warning", "get_sample", status_message)
                return False

        # Request failed returning false and logging an error
        else:
            # Write a warning to the console
            status_message = r.json()['status_message']
            self.logger_out("warning", "get_sample", status_message)
            return False

    def get_imphash(self, imphash, function):
        """
        Function:   This function performs lookups against
                    imphashes depending on the functions

        :param function:    Required - These are the functions that
                            threat miner provide for imphashes lookups

        Functions
            1 - Samples
            2 - Report tagging

        Usage:
        s = threatMiner()
        s.get_imphash("1f4f257947c1b713ca7f9bc25f914039", 1)
        """
        # URL that we are querying
        endpoint = '{}/imphash.php?q={}&rt={}'.format(
                   self.base_url, imphash, function)
        # Create a request
        r = self.session.get(endpoint)
        # Sleep to ensure throttling
        time.sleep(7)
        # If the request is successful
        # If the request is successful
        if r.status_code == 200:
            if int(r.json()['status_code']) == 200:
                output = r.json()
                return self.parse_output(output)
            else:
                # Write a warning to the console
                status_message = r.json()['status_message']
                self.logger_out("warning", "get_imphash", status_message)
                return False
        else:
            status_message = r.json()['status_message']
            self.logger_out("warning", "get_imphash", status_message)
            return False

    def get_ssdeep(self, ssdeep, function):
        """
        Function:   This function performs lookups against
                    ssdeep depending on the functions

        :param function:    Required - These are the functions that
                            threat miner provide for ssdeep lookups

        Functions
            1 - Samples
            2 - Report tagging

        Usage:
        s = threatMiner()
        s.get_ssdeep("
        1536:TJsNrChuG2K6IVOTjWko8a9P6W3OEHBQc4w4:TJs0oG2KSTj3o8a9PFeEHn4l", 1)
        """
        # URL that we are querying
        endpoint = '{}/ssdeep.php?q={}&rt={}'.format(
                    self.base_url, ssdeep, function)
        # Create a request
        r = self.session.get(endpoint)
        # Sleep to ensure throttling
        time.sleep(7)
        # If the request is successful
        if r.status_code == 200:
            if int(r.json()['status_code']) == 200:
                output = r.json()
                return self.parse_output(output)
            else:
                # Write a warning to the console
                status_message = r.json()['status_message']
                self.logger_out("warning", "get_ssdeep", status_message)
                return False
        else:
            # Write a warning to the console
            status_message = r.json()['status_message']
            self.logger_out("warning", "get_ssdeep", status_message)
            return False

    def get_ssl(self, ssl, function):
        """
        Function:   This function performs lookups against
                    ssl depending on the functions

        :param function:    Required - These are the functions that
                            threat miner provide for ssl lookups

        Functions
            1 - Hosts
            2 - Report tagging

        Usage:
        s = threatMiner()
        s.get_ssl("42a8d5b3a867a59a79f44ffadd61460780fe58f2", 1)
        """
        # URL that we are querying
        endpoint = '{}/ssl.php?q={}&rt={}'.format(self.base_url, ssl, function)
        # Create a request
        r = self.session.get(endpoint)
        # Sleep to ensure throttling
        time.sleep(7)
        # If the request is successful
        if r.status_code == 200:
            if int(r.json()['status_code']) == 200:
                output = r.json()
                return self.parse_output(output)
            else:
                # Write a warning to the console
                status_message = r.json()['status_message']
                self.logger_out("warning", "get_ssl", status_message)
                return False
        else:
            # Write a warning to the console
            status_message = r.json()['status_message']
            self.logger_out("warning", "get_ssl", status_message)
            return False

    def get_email(self, email, function):
        """
        Function:   This function performs lookups against
                    email depending on the functions

        :param function:    Required - These are the functions that
                            threat miner provide for email lookups

        Functions
            1 - Domains

        Usage:
        s = threatMiner()
        s.get_email("7bf5721bfa009479c33f3c3cf4ea5392200f030e", 1)
        """
        # URL that we are querying
        endpoint = '{}/email.php?q={}&rt={}'.format(
                    self.base_url, email, function)
        # Create a request
        r = self.session.get(endpoint)
        # Sleep to ensure throttling
        time.sleep(7)
        # If the request is successful
        if r.status_code == 200:
            if int(r.json()['status_code']) == 200:
                output = r.json()
                return self.parse_output(output)
            else:
                # Write a warning to the console
                status_message = r.json()['status_message']
                self.logger_out("warning", "get_email", status_message)
                return False
        else:
            # Write a warning to the console
            status_message = r.json()['status_message']
            self.logger_out("warning", "get_email", status_message)
            return False

    def get_av(self, av, function):
        """
        Function:   This function performs lookups against
                    AV depending on the functions

        :param function:    Required - These are the functions that
                            threat miner provide for AV lookups

        Functions
            1 - Samples
            2 - Report tagging

        Usage:
        s = threatMiner()
        s.get_av("Trojan.Enfal", 1)
        """
        # URL that we are querying
        endpoint = '{}/av.php?q={}&rt={}'.format(self.base_url, av, function)
        # Create a request
        r = self.session.get(endpoint)
        # Sleep to ensure throttling
        time.sleep(7)
        # If the request is successful
        if r.status_code == 200:
            if int(r.json()['status_code']) == 200:
                output = r.json()
                return self.parse_output(output)
            else:
                # Write a warning to the console
                status_message = r.json()['status_message']
                self.logger_out("warning", "get_av", status_message)
                return False
        else:
            # Write a warning to the console
            status_message = r.json()['status_message']
            self.logger_out("warning", "get_av", status_message)
            return False
