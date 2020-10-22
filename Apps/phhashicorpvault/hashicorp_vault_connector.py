import phantom.app as phantom
from phantom.action_result import ActionResult
# import datetime
import json
import hvac


class AppConnectorHashicorpVault(phantom.BaseConnector):
    ACTION_ID_TEST_ASSET_CONNECTIVITY = 'test_asset_connectivity'
    ACTION_ID_SET_SECRET = 'set_secret'
    ACTION_ID_GET_SECRET = 'get_secret'
    ACTION_ID_LIST_SECRETS = 'list_secrets'

    def __init__(self):
        super(AppConnectorHashicorpVault, self).__init__()
        return

    def _get_token(self):
        self.save_progress('Getting token from asset configuration..._get_token()')
        config = self.get_config()
        try:
            token = config['vault_token']
        except:
            token = None
        return token

    def _get_url(self):
        self.save_progress('Getting vault URL from asset configuration..._get_url()')
        config = self.get_config()
        try:
            url = config['vault_url']
        except:
           url = None
        return url

    def _get_mountpoint(self):
        self.save_progress('Getting vault mountpoint from asset configuration..._get_mountpoint()')
        config = self.get_config()
        try:
            mountpoint = config['vault_mountpoint']
        except:
           mountpoint = None
        return mountpoint

    def _create_vault_client(self):
        url = self._get_url()
        token = self._get_token()
        if url and token:
            try:
                vault_client = hvac.Client(url=url, token=token)
                return vault_client
            except:
                return None
        else:
            return None

    def _test_connectivity(self, action_result):
        hvac_client = self._create_vault_client()
        if hvac_client:
            is_authenticated = hvac_client.is_authenticated()
            if is_authenticated:
                self.save_progress('Successfully connected to vault with given credentials')
                action_result.set_status(phantom.APP_SUCCESS, 'Successfully connected to Vault')
                return phantom.APP_SUCCESS
            else:
                self.save_progress('Failed to connect to vault with given credentials')
                action_result.set_status(phantom.APP_ERROR, 'Failed to connect to Vault')
                return phantom.APP_ERROR
        else:
            self.save_progress('Failed to create Vault client')
            action_result.set_status(phantom.APP_ERROR, 'Failed to create Vault client')
            return phantom.APP_ERROR

    def _set_secret(self, param, action_result):
        hvac_client = self._create_vault_client()
        mountpoint = self._get_mountpoint()
        try:
            path = param.get('location')
            secret = param.get('secret_json')
            self.save_progress(secret)
            secret = json.loads(secret)
            try:
                create_response = hvac_client.secrets.kv.v2.create_or_update_secret(mount_point=mountpoint, path=path, secret=secret)
                if create_response:
                    self.save_progress("Secret created successfully")
                    action_result.add_data({"succeeded": True})
                    action_result.set_status(phantom.APP_SUCCESS, 'Successfully added secret')
                    return phantom.APP_SUCCESS
                else:
                    self.save_progress("something went wrong")
                    action_result.set_status(phantom.APP_ERROR, "something went wrong")
                    return phantom.APP_ERROR
            except Exception as e:
                self.save_progress("There was an exception thrown while trying to store secret in vault: {}".format(str(e)))
                action_result.set_status(phantom.APP_ERROR, "There was an exception thrown while trying to store secret in vault: {}".format(str(e)))
                return phantom.APP_ERROR

        except Exception as e:
            self.save_progress("There was an error retrieving or parsing secret data: {}".format(str(e)))
            action_result.set_status(phantom.APP_ERROR, "There was an error retrieving or parsing secret data: {}".format(str(e)))
            return phantom.APP_ERROR

    def _get_secret(self, param, action_result):
        hvac_client = self._create_vault_client()
        mountpoint = self._get_mountpoint()
        try:
            path = param.get('location')
            try:
                read_response = hvac_client.secrets.kv.v2.read_secret_version(mount_point=mountpoint, path=path)
                if read_response:
                    secret_value = read_response['data']['data']
                    if secret_value:
                        self.save_progress("Secret retrieved successfully")
                        action_result.add_data({"succeeded": True, "secret_value": secret_value})
                        action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved secret')
                        return phantom.APP_SUCCESS
                    else:
                        self.save_progress("No value was returned by Vault for the specified path")
                        action_result.set_status(phantom.APP_ERROR, "No value was returned by Vault for the specified path")
                        return phantom.APP_ERROR
                else:
                    self.save_progress("There was an error obtaining value from Vault")
                    action_result.set_status(phantom.APP_ERROR, "There was an error obtaining value from Vault")
                    return phantom.APP_ERROR
            except Exception as e:
                self.save_progress("There was an exception thrown while trying to retrieve secret in vault: {}".format(str(e)))
                action_result.set_status(phantom.APP_ERROR, "There was an exception thrown while trying to retrieve secret in vault: {}".format(str(e)))
                return phantom.APP_ERROR

        except Exception as e:
            self.save_progress("There was an error retrieving or parsing location data: {}".format(str(e)))
            action_result.set_status(phantom.APP_ERROR, "There was an error retrieving or parsing location data: {}".format(str(e)))
            return phantom.APP_ERROR

    def _list_secrets(self, param, action_result):
        hvac_client = self._create_vault_client()
        mountpoint = self._get_mountpoint()
        try:
            path = param.get('location')
            try:
                list_secrets = hvac_client.secrets.kv.v2.list_secrets(mount_point=mountpoint, path=path)
                if list_secrets:
                    secrets = list_secrets['data']['keys']
                    if secrets:
                        self.save_progress("Secrets retrieved successfully")
                        action_result.add_data({"succeeded": True, "secret_values": secrets})
                        action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved secrets')
                        return phantom.APP_SUCCESS
                    else:
                        self.save_progress("No value was returned by Vault for the specified path")
                        action_result.set_status(phantom.APP_ERROR, "No value was returned by Vault for the specified path")
                        return phantom.APP_ERROR
                else:
                    self.save_progress("There was an error obtaining value from Vault")
                    action_result.set_status(phantom.APP_ERROR, "There was an error obtaining value from Vault")
                    return phantom.APP_ERROR
            except Exception as e:
                self.save_progress("There was an exception thrown while trying to retrieve secret in vault: {}".format(str(e)))
                action_result.set_status(phantom.APP_ERROR, "There was an exception thrown while trying to list secrets in vault: {}".format(str(e)))
                return phantom.APP_ERROR

        except Exception as e:
            self.save_progress("There was an error retrieving or parsing location data: {}".format(str(e)))
            action_result.set_status(phantom.APP_ERROR, "There was an error retrieving or parsing location data: {}".format(str(e)))
            return phantom.APP_ERROR

    def handle_action(self, param):
        action = self.get_action_identifier()
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = phantom.APP_SUCCESS

        if action == self.ACTION_ID_SET_SECRET:
            ret_val = self._set_secret(param, action_result)

        if action == self.ACTION_ID_GET_SECRET:
            ret_val = self._get_secret(param, action_result)

        if action == self.ACTION_ID_LIST_SECRETS:
            ret_val = self._list_secrets(param, action_result)

        if action == self.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(action_result)
        return ret_val


if __name__ == '__main__':
    import sys
    import pudb
    pudb.set_trace()
    if len(sys.argv) < 2:
        print('No test json specified as input')
        exit(0)
    with open(sys.argv[1]) as (f):
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = AppConnectorHashicorpVault()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))
    exit(0)
