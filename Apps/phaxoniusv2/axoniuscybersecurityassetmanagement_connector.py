"""Phantom app for Axonius."""
# File: axoniuscybersecurityassetmanagement_connector.py
# Phantom App imports
# import json
import os
from typing import Any, List, Optional, Union

import phantom.app as phantom
from axonius_api_client import Connect
from axonius_api_client.api.assets.asset_mixin import AssetMixin
from axonius_api_client.tools import dt_parse, strip_left
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

API_KEY: str = "api_key"
API_SECRET: str = "api_secret"
URL_KEY: str = "url"
PROXY_URL_KEY: str = "proxy_url"
SQ_NAME_KEY: str = "sq_name"
MAX_ROWS_KEY: str = "max_rows"
HOSTNAME_KEY: str = "hostname"
IP_KEY: str = "ip"
MAC_KEY: str = "mac"
MAIL_KEY: str = "mail"
USERNAME_KEY: str = "username"

MAX_ROWS: str = 25
"""Maximum number of assets to allow user to fetch."""

SKIPS: List[str] = ["specific_data.data.image"]
"""Fields to remove from each asset if found."""

FIELDS_TIME: List[str] = ["seen", "fetch", "time", "date"]
"""Fields to try and convert to date time if they have these words in them."""


def get_str_arg(param: dict, key: str, required: bool = False, default: str = "") -> str:
    """Get a key from a command arg and convert it into an str."""
    value = param.get(key, default)

    if not isinstance(value, str):
        raise ValueError(
            f"Supplied value {value!r} for argument {key!r} is not a string."
        )

    value = value.strip()

    if not value and required:
        raise ValueError(f"No value supplied for argument {key!r}")

    return value


def get_int_arg(
    param: dict,
    key: str,
    required: bool = False,
    default: Optional[Union[str, int]] = None,
) -> int:
    """Get a key from a command arg and convert it into an int."""
    value = param.get(key, default)

    if value is None and required:
        raise ValueError(f"No value supplied for argument {key!r}")

    try:
        return int(value)
    except Exception:
        raise ValueError(
            f"Supplied value {value!r} for argument {key!r} is not an integer."
        )


def parse_kv(key: str, value: Any) -> Any:
    """Parse time stamp into required format."""
    for word in FIELDS_TIME:
        if word in key:
            try:
                return dt_parse(value).isoformat()
            except Exception:
                return value
    return value


def parse_key(key: str) -> str:
    """Parse fields into required format."""
    if key.startswith("specific_data.data."):
        # specific_data.data.hostname
        # -> aggregated_hostname
        key = strip_left(obj=key, fix="specific_data.data.")
        key = f"aggregated_{key}"
    if key.startswith("adapters_data."):
        # adapters_data.aws_adapter.hostname
        # -> aws_adapter_hostname
        key = strip_left(obj=key, fix="adapters_data.")
    key = key.replace(".", "_")
    return key


def parse_asset(asset: dict) -> dict:
    """Initiate field format correction on assets."""
    return {
        parse_key(key=k): parse_kv(key=k, value=v)
        for k, v in asset.items()
        if k not in SKIPS
    }


class AxoniusConnector(BaseConnector):
    """Connector for Axonius App."""

    def __init__(self):
        """Axonius App Constructor."""
        super(AxoniusConnector, self).__init__()
        self._client: Connect = None
        self._client_args: dict = {}

    def _create_client(self, action_result: phantom.ActionResult) -> int:
        """Create an instance of Axonius API Client."""
        try:
            self.debug_print("Creating Axonius API Client")
            self._client: Connect = Connect(**self._client_args)
        except Exception as exc:
            status = f"Could not create Axonius API Client: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        return phantom.APP_SUCCESS

    def _start_client(self, action_result: phantom.ActionResult) -> int:
        """Create an instance of Axonius API Client and start it."""
        if not self._create_client(action_result):
            return action_result.get_status()

        progress = f"Trying to login to Axonius instance at {self._url}"
        self.save_progress(progress)

        try:
            self._client.start()
        except Exception as exc:
            status = f"Failed to login to Axonius instance at {self._url}: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        progress = f"Successfully logged in to Axonius {self._client}"
        self.save_progress(progress)

        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param: dict) -> int:
        """Test that we can login to Axonius using the Axonius API Client."""
        action_result: phantom.ActionResult = ActionResult(dict(param))
        self.add_action_result(action_result)

        if not self._start_client(action_result):
            return action_result.get_status()

        progress = f"Test Connectivity Passed {self._client}"
        self.save_progress(progress)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_devices_by_sq(self, param, obj_type) -> int:
        """Get devices by the name of a Saved Query in Axonius."""
        action_result: phantom.ActionResult = ActionResult(dict(param))
        self.add_action_result(action_result)

        if not self._start_client(action_result):
            return action_result.get_status()

        try:
            sq_name: str = get_str_arg(key=SQ_NAME_KEY, param=param, required=True)
            max_rows: int = get_int_arg(key=MAX_ROWS_KEY, param=param, default=MAX_ROWS)
        except Exception as exc:
            status = f"Failed to parse parameters: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        apiobj: AssetMixin = getattr(self._client, obj_type)

        progress = f"Fetching {obj_type} from Saved Query {sq_name!r}"
        self.save_progress(progress)

        try:
            assets: List[dict] = apiobj.get_by_saved_query(
                name=sq_name, max_rows=max_rows, field_null=True, field_null_value=[]
            )
        except Exception as exc:
            status = f"Failed to fetch Saved Query: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        progress = f"Fetched {len(assets)} {obj_type} from Saved Query {sq_name!r}"
        self.save_progress(progress)

        summary: dict = action_result.update_summary({})
        summary[f"total_{obj_type}"] = action_result.get_data_size()

        for asset in assets:
            action_result.add_data(parse_asset(asset=asset))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_devices_by_hostname(self, param, obj_type) -> int:
        """Get devices by hostname."""
        action_result: phantom.ActionResult = ActionResult(dict(param))
        self.add_action_result(action_result)

        if not self._start_client(action_result):
            return action_result.get_status()

        try:
            hostname: str = get_str_arg(key=HOSTNAME_KEY, param=param, required=True)
            max_rows: int = get_int_arg(key=MAX_ROWS_KEY, param=param, default=MAX_ROWS)
        except Exception as exc:
            status = f"Failed to parse parameters: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        apiobj: AssetMixin = getattr(self._client, obj_type)

        progress = f"Fetching {obj_type} with host name {hostname!r}"
        self.save_progress(progress)

        try:
            assets: List[dict] = apiobj.get_by_value(
                value=hostname,
                field="specific_data.data.hostname",
                max_rows=max_rows,
                field_null=True,
                field_null_value=[],
            )
        except Exception as exc:
            status = f"Failed to fetch device: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        progress = f"Fetched {len(assets)} {obj_type} with {hostname!r} from Axonius"
        self.save_progress(progress)

        summary: dict = action_result.update_summary({})
        summary[f"total_{obj_type}"] = action_result.get_data_size()

        for asset in assets:
            action_result.add_data(parse_asset(asset=asset))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_devices_by_ip(self, param, obj_type) -> int:
        """Get devices by IP address."""
        action_result: phantom.ActionResult = ActionResult(dict(param))
        self.add_action_result(action_result)

        if not self._start_client(action_result):
            return action_result.get_status()

        try:
            ip: str = get_str_arg(key=IP_KEY, param=param, required=True)
            max_rows: int = get_int_arg(key=MAX_ROWS_KEY, param=param, default=MAX_ROWS)
        except Exception as exc:
            status = f"Failed to parse parameters: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        apiobj: AssetMixin = getattr(self._client, obj_type)

        progress = f"Fetching {obj_type} with IP address {ip!r}"
        self.save_progress(progress)

        try:
            assets: List[dict] = apiobj.get_by_value(
                value=ip,
                field="specific_data.data.network_interfaces.ips",
                max_rows=max_rows,
                field_null=True,
                field_null_value=[],
            )
        except Exception as exc:
            status = f"Failed to fetch device: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        progress = f"Fetched {len(assets)} {obj_type} with {ip!r} from Axonius"
        self.save_progress(progress)

        summary: dict = action_result.update_summary({})
        summary[f"total_{obj_type}"] = action_result.get_data_size()

        for asset in assets:
            action_result.add_data(parse_asset(asset=asset))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_devices_by_mac(self, param, obj_type) -> int:
        """Get devices by MAC address."""
        action_result: phantom.ActionResult = ActionResult(dict(param))
        self.add_action_result(action_result)

        if not self._start_client(action_result):
            return action_result.get_status()

        try:
            mac: str = get_str_arg(key=MAC_KEY, param=param, required=True)
            max_rows: int = get_int_arg(key=MAX_ROWS_KEY, param=param, default=MAX_ROWS)
        except Exception as exc:
            status = f"Failed to parse parameters: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        apiobj: AssetMixin = getattr(self._client, obj_type)

        progress = f"Fetching {obj_type} with MAC address {mac!r}"
        self.save_progress(progress)

        try:
            assets: List[dict] = apiobj.get_by_value(
                value=mac,
                field="specific_data.data.network_interfaces.mac",
                max_rows=max_rows,
                field_null=True,
                field_null_value=[],
            )
        except Exception as exc:
            status = f"Failed to fetch device: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        progress = f"Fetched {len(assets)} {obj_type} with {mac!r} from Axonius"
        self.save_progress(progress)

        summary: dict = action_result.update_summary({})
        summary[f"total_{obj_type}"] = action_result.get_data_size()

        for asset in assets:
            action_result.add_data(parse_asset(asset=asset))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_users_by_sq(self, param, obj_type) -> int:
        """Get users by the name of a Saved Query in Axonius."""
        action_result: phantom.ActionResult = ActionResult(dict(param))
        self.add_action_result(action_result)

        if not self._start_client(action_result):
            return action_result.get_status()

        try:
            sq_name: str = get_str_arg(key=SQ_NAME_KEY, param=param, required=True)
            max_rows: int = get_int_arg(key=MAX_ROWS_KEY, param=param, default=MAX_ROWS)
        except Exception as exc:
            status = f"Failed to parse parameters: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        apiobj: AssetMixin = getattr(self._client, obj_type)

        progress = f"Fetching {obj_type} from Saved Query {sq_name!r}"
        self.save_progress(progress)

        try:
            assets: List[dict] = apiobj.get_by_saved_query(
                name=sq_name, max_rows=max_rows, field_null=True, field_null_value=[]
            )
        except Exception as exc:
            status = f"Failed to fetch Saved Query: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        progress = f"Fetched {len(assets)} {obj_type} from Saved Query {sq_name!r}"
        self.save_progress(progress)

        summary: dict = action_result.update_summary({})
        summary[f"total_{obj_type}"] = action_result.get_data_size()

        for asset in assets:
            action_result.add_data(parse_asset(asset=asset))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_users_by_mail(self, param, obj_type) -> int:
        """Get users by email address in Axonius."""
        action_result: phantom.ActionResult = ActionResult(dict(param))
        self.add_action_result(action_result)

        if not self._start_client(action_result):
            return action_result.get_status()

        try:
            mail: str = get_str_arg(key=MAIL_KEY, param=param, required=True)
            max_rows: int = get_int_arg(key=MAX_ROWS_KEY, param=param, default=MAX_ROWS)
        except Exception as exc:
            status = f"Failed to parse parameters: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        apiobj: AssetMixin = getattr(self._client, obj_type)

        progress = f"Fetching {obj_type} with email address {mail!r}"
        self.save_progress(progress)

        try:
            assets: List[dict] = apiobj.get_by_value(
                value=mail,
                field="specific_data.data.mail",
                max_rows=max_rows,
                field_null=True,
                field_null_value=[],
            )
        except Exception as exc:
            status = f"Failed to fetch users: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        progress = f"Fetched {len(assets)} {obj_type} with {mail!r} from Axonius"
        self.save_progress(progress)

        summary: dict = action_result.update_summary({})
        summary[f"total_{obj_type}"] = action_result.get_data_size()

        for asset in assets:
            action_result.add_data(parse_asset(asset=asset))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_users_by_username(self, param, obj_type) -> int:
        """Get users by username in Axonius."""
        action_result: phantom.ActionResult = ActionResult(dict(param))
        self.add_action_result(action_result)

        if not self._start_client(action_result):
            return action_result.get_status()

        try:
            username: str = get_str_arg(key=USERNAME_KEY, param=param, required=True)
            max_rows: int = get_int_arg(key=MAX_ROWS_KEY, param=param, default=MAX_ROWS)
        except Exception as exc:
            status = f"Failed to parse parameters: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        apiobj: AssetMixin = getattr(self._client, obj_type)

        progress = f"Fetching {obj_type} with username {username!r}"
        self.save_progress(progress)

        try:
            assets: List[dict] = apiobj.get_by_value(
                value=username,
                field="specific_data.data.username",
                max_rows=max_rows,
                field_null=True,
                field_null_value=[],
            )
        except Exception as exc:
            status = f"Failed to fetch users: {exc}"
            return action_result.set_status(phantom.APP_ERROR, status)

        progress = f"Fetched {len(assets)} {obj_type} with {username!r} from Axonius"
        self.save_progress(progress)

        summary: dict = action_result.update_summary({})
        summary[f"total_{obj_type}"] = action_result.get_data_size()

        for asset in assets:
            action_result.add_data(parse_asset(asset=asset))

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param: dict) -> int:
        """Launch point for Phantom actions."""
        ret_val: int = phantom.APP_SUCCESS
        action_id: str = self.get_action_identifier()
        self.debug_print("action_id", action_id)

        try:
            if action_id == "test_connectivity":
                ret_val = self._handle_test_connectivity(param)
            elif action_id == "devices_by_sq":
                ret_val = self._handle_devices_by_sq(param=param, obj_type="devices")
            elif action_id == "devices_by_hostname":
                ret_val = self._handle_devices_by_hostname(
                    param=param, obj_type="devices"
                )
            elif action_id == "devices_by_ip":
                ret_val = self._handle_devices_by_ip(param=param, obj_type="devices")
            elif action_id == "devices_by_mac":
                ret_val = self._handle_devices_by_mac(param=param, obj_type="devices")
            elif action_id == "users_by_sq":
                ret_val = self._handle_users_by_sq(param=param, obj_type="users")
            elif action_id == "users_by_mail":
                ret_val = self._handle_users_by_mail(param=param, obj_type="users")
            elif action_id == "users_by_username":
                ret_val = self._handle_users_by_username(param=param, obj_type="users")
        except Exception as exc:
            progress = f"Exception in {action_id}: {exc}"
            self.save_progress(progress)

        return ret_val

    def initialize(self) -> int:
        """Initialize the Phantom integration."""
        self._state: dict = self.load_state()
        config: dict = self.get_config()

        self._url: str = config[URL_KEY]

        self._client_args: dict = {}
        self._client_args["key"] = config[API_KEY]
        self._client_args["secret"] = config[API_SECRET]
        self._client_args["url"] = config[URL_KEY]
        self._client_args["certverify"] = False
        self._client_args["proxy"] = config.get(PROXY_URL_KEY)

        env_vars: dict = config.get("_reserved_environment_variables", {})

        # TBD Figure out a better way for this later
        os.environ.pop("REQUESTS_CA_BUNDLE", None)
        if "HTTPS_PROXY" in env_vars:
            self._client_args["proxy"] = env_vars["HTTPS_PROXY"]["value"]

        return phantom.APP_SUCCESS

    def finalize(self) -> int:
        """Finalize the Phantom integration."""
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


# if __name__ == "__main__":

#     import pudb
#     import argparse

#     pudb.set_trace()

#     argparser = argparse.ArgumentParser()

#     argparser.add_argument("input_test_json", help="Input Test JSON file")
#     argparser.add_argument("-u", "--username", help="username", required=False)
#     argparser.add_argument("-p", "--password", help="password", required=False)

#     args = argparser.parse_args()
#     session_id = None

#     username = args.username
#     password = args.password

#     if username is not None and password is None:

#         # User specified a username but not a password, so ask
#         import getpass

#         password = getpass.getpass("Password: ")

#     if username and password:
#         login_url = BaseConnector._get_phantom_base_url() + "login"
#         try:
#             print("Accessing the Login page")
#             r = requests.get(login_url, verify=False)
#             csrftoken = r.cookies["csrftoken"]

#             data = dict()
#             data["username"] = username
#             data["password"] = password
#             data["csrfmiddlewaretoken"] = csrftoken

#             headers = dict()
#             headers["Cookie"] = "csrftoken=" + csrftoken
#             headers["Referer"] = login_url

#             print("Logging into Platform to get the session id")
#             r2 = requests.post(login_url, verify=False, data=data, headers=headers)
#             session_id = r2.cookies["sessionid"]
#         except Exception as e:
#             print("Unable to get session id from the platform. Error: " + str(e))
#             exit(1)

#     with open(args.input_test_json) as f:
#         in_json = f.read()
#         in_json = json.loads(in_json)
#         print(json.dumps(in_json, indent=4))

#         connector = AwsLambdaConnector()
#         connector.print_progress_message = True

#         if session_id is not None:
#             in_json["user_session_token"] = session_id
#             connector._set_csrf_info(csrftoken, headers["Referer"])

#         ret_val = connector._handle_action(json.dumps(in_json), None)
#         print(json.dumps(json.loads(ret_val), indent=4))

#     exit(0)
