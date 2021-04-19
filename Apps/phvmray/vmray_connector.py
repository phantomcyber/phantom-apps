import base64
import os
import time
import zipfile

from typing import Any, Dict, List, Tuple, Union

# pylint: disable=E0401
from phantom.action_result import ActionResult
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.vault import Vault
import phantom.rules as phantom_rules

# pylint: enable=E0401

from vmray_consts import (  # pylint: disable=wrong-import-order
    ACTION_ID_VMRAY_DETONATE_FILE,
    ACTION_ID_VMRAY_DETONATE_URL,
    ACTION_ID_VMRAY_GET_FILE,
    ACTION_ID_VMRAY_GET_INFO,
    ACTION_ID_VMRAY_GET_REPORT,
    DEFAULT_TIMEOUT,
    SAMPLE_TYPE_MAPPING,
    VMRAY_DEFAULT_PASSWORD,
    VMRAY_ERR_ADD_VAULT,
    VMRAY_ERR_CONNECTIVITY_TEST,
    VMRAY_ERR_FILE_EXISTS,
    VMRAY_ERR_GET_SUBMISSION,
    VMRAY_ERR_MALFORMED_ZIP,
    VMRAY_ERR_MULTIPART,
    VMRAY_ERR_NO_SUBMISSIONS,
    VMRAY_ERR_OPEN_ZIP,
    VMRAY_ERR_SAMPLE_NOT_FOUND,
    VMRAY_ERR_SERVER_CONNECTION,
    VMRAY_ERR_SUBMISSION_NOT_FINISHED,
    VMRAY_ERR_SUBMIT_FILE,
    VMRAY_ERR_UNSUPPORTED_HASH,
    VMRAY_ERR_REST_API,
    VMRAY_JSON_API_KEY,
    VMRAY_JSON_DISABLE_CERT,
    VMRAY_JSON_SERVER,
    VMRAY_SUCC_CONNECTIVITY_TEST,
)

from rest_api import (  # pylint: disable=wrong-import-order, import-error
    VMRayRESTAPIError,
)
from rest_cmds import SummaryV2, VMRay  # pylint: disable=wrong-import-order


class VMRayConnector(BaseConnector):
    def __init__(self) -> None:
        # Call the BaseConnectors init first
        super().__init__()
        self._api: VMRay = None

    def _test_connectivity(self, _: Dict[str, Any]) -> bool:
        config = self.get_config()

        # get the server
        server = config.get(VMRAY_JSON_SERVER)
        api_key = config.get(VMRAY_JSON_API_KEY)
        disable_cert = config.get(VMRAY_JSON_DISABLE_CERT)

        self.save_progress("Querying server to check connectivity")

        # Progress
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, server)

        try:
            VMRay(server, api_key, not disable_cert)
        except VMRayRESTAPIError as exc:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SERVER_CONNECTION, exc)
            self.append_to_message(VMRAY_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(
            phantom.APP_SUCCESS, VMRAY_SUCC_CONNECTIVITY_TEST
        )

    def _get_api(self) -> Tuple[bool, VMRay]:
        if self._api is not None:
            return (self.get_status(), self._api)

        config = self.get_config()

        # get the server
        server = config.get(VMRAY_JSON_SERVER)
        api_key = config.get(VMRAY_JSON_API_KEY)
        disable_cert = config.get(VMRAY_JSON_DISABLE_CERT)

        try:
            self._api = VMRay(server, api_key, not disable_cert)
            return (self.get_status(), self._api)
        except VMRayRESTAPIError as exc:
            self._api = None
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SERVER_CONNECTION, exc)
            return (self.get_status(), None)

    @staticmethod
    def _get_timeout(param: Dict[str, Any]) -> int:
        try:
            timeout = int(param["timeout"])
            if timeout < 0:
                timeout = DEFAULT_TIMEOUT
        except (KeyError, TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT

        return timeout

    def _get_sample_by_hash(
        self, api: VMRay, hsh: str
    ) -> Tuple[str, List[Dict[str, Any]]]:
        self.save_progress("Searching for %s" % (hsh))

        if len(hsh) == 32:
            res = api.get_sample_by_md5(hsh)
        elif len(hsh) == 40:
            res = api.get_sample_by_sha1(hsh)
        elif len(hsh) == 64:
            res = api.get_sample_by_sha256(hsh)
        else:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_UNSUPPORTED_HASH)
            return self.get_status(), []

        if len(res) == 0:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SAMPLE_NOT_FOUND)
            return self.get_status(), []

        return phantom.APP_SUCCESS, res

    def _submission_finished_within_timeout(
        self, api: VMRay, submission_id: int, timeout: int
    ) -> bool:
        seconds_waited = 0

        while not api.is_submission_finished(submission_id):
            if timeout == 0 or seconds_waited >= timeout:
                return False

            self.send_progress("Submission is not finished yet")
            time_to_wait = min(30, timeout - seconds_waited)
            seconds_waited += time_to_wait
            self.send_progress("Waited %d/%d seconds" % (seconds_waited, timeout))
            time.sleep(time_to_wait)

        return True

    def _handle_get_file(self, param: Dict[str, Any]) -> bool:
        status, api = self._get_api()
        if api is None:
            return status

        self.debug_print("param", param)
        hsh = param["hash"]

        try:
            status, res = self._get_sample_by_hash(api, hsh)
        except VMRayRESTAPIError:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SAMPLE_NOT_FOUND)
            return self.get_status()

        if status == phantom.APP_ERROR:
            return self.get_status()

        if "sample_id" not in res[0]:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SAMPLE_NOT_FOUND)
            return self.get_status()

        if res[0]["sample_is_multipart"]:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_MULTIPART)
            return self.get_status()

        self.save_progress("Downloading file")

        vault_tmp_folder = Vault.get_vault_tmp_dir()
        zip_file_location = os.path.join(vault_tmp_folder, "%s.zip" % hsh)
        file_location = os.path.join(vault_tmp_folder, hsh)
        if os.path.exists(zip_file_location) or os.path.exists(file_location):
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_FILE_EXISTS)
            return self.get_status()

        with api.get_sample_file(res[0]["sample_id"]) as data:
            with open(zip_file_location, "wb") as fobj:
                fobj.write(data.read())

        try:
            zifi = zipfile.ZipFile(zip_file_location, "r")
        except Exception as exc:  # pylint: disable=W0703
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_OPEN_ZIP, exc)
            os.remove(zip_file_location)
            return self.get_status()

        zf_names = zifi.namelist()

        if len(zf_names) != 1:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_MALFORMED_ZIP)
            zifi.close()
            os.remove(zip_file_location)
            return self.get_status()

        self.save_progress("Extracting file")

        try:
            with zifi.open(zf_names[0], "r", VMRAY_DEFAULT_PASSWORD) as ifobj:
                with open(file_location, "wb") as ofobj:
                    ofobj.write(ifobj.read())

        except Exception as exc:  # pylint: disable=W0703
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_MALFORMED_ZIP, exc)
            if os.path.exists(file_location):
                os.remove(file_location)
            return self.get_status()

        finally:
            zifi.close()
            os.remove(zip_file_location)

        vmray_sampletypes = [x["sample_type"] for x in res]
        phantom_sampletypes = []
        for sample_type in vmray_sampletypes:
            # sample type could be `custom` or `unknown`
            if sample_type not in SAMPLE_TYPE_MAPPING.keys():
                continue

            phantom_sampletypes.append(SAMPLE_TYPE_MAPPING[sample_type])

        phantom_sampletypes = list(set(phantom_sampletypes))
        self.debug_print("phantom_sampletypes", phantom_sampletypes)

        self.save_progress("Adding file to vault")
        vlt_res = Vault.add_attachment(
            file_location,
            self.get_container_id(),
            file_name=res[0]["sample_filename"],
            metadata={
                "size": res[0]["sample_filesize"],
                "contains": phantom_sampletypes,
            },
        )

        if not vlt_res["succeeded"]:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_ADD_VAULT)

            try:
                os.remove(file_location)
            except FileNotFoundError:
                pass

            return self.get_status()

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)
        action_result.add_data({"vault_id": vlt_res["vault_id"]})
        action_result.update_summary({"vault_id": vlt_res["vault_id"]})
        action_result.set_status(phantom.APP_SUCCESS)

        self.save_progress("Finished")

        return action_result.get_status()

    def _handle_detonate_file(self, param: Dict[str, Any]):
        status, api = self._get_api()
        if api is None:
            return status

        vault_id = param["vault_id"]
        try:
            _, _, vault_info = phantom_rules.vault_info(vault_id=vault_id)
        except Exception:  # pylint: disable=W0703
            return self.set_status(
                phantom.APP_ERROR,
                f"Error while getting vault info for vault_id {vault_id}",
            )

        if len(vault_info) > 1:
            return self.set_status(
                phantom.APP_ERROR, f"Found multiple files for vault_id {vault_id}"
            )

        if len(vault_info) == 0:
            return self.set_status(
                phantom.APP_ERROR, f"No sample found for vault_id {vault_id}"
            )

        vault_info = vault_info[0]

        file_path = vault_info.get("path")
        if not file_path:
            return self.set_status(
                phantom.APP_ERROR, f"Cannot find a path for vault id {vault_id}"
            )

        self.save_progress("Submitting file %s" % vault_id)

        params = {"reanalyze": True}
        if param.get("comment"):
            params["comment"] = param["comment"]
        if param.get("tags"):
            params["tags"] = param["tags"]
        if param.get("type"):
            params["sample_type"] = param["type"]
        if param.get("config"):
            params["user_config"] = param["config"]
        if param.get("jobrules"):
            params["jobrule_entries"] = param["jobrules"]

        if param.get("file_name"):
            params["sample_filename_b64enc"] = base64.b64encode(
                param["file_name"].encode()
            ).decode()
        elif vault_info.get("name"):
            params["sample_filename_b64enc"] = base64.b64encode(
                vault_info["name"].encode()
            ).decode()

        try:
            res = api.submit_file(file_path, params=params)
        except VMRayRESTAPIError as exc:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SUBMIT_FILE, exc)
            return self.get_status()

        if res["errors"]:
            errors = [
                err.get("error_msg", "NO_ERROR_MSG_GIVEN") for err in res["errors"]
            ]
            self.set_status(phantom.APP_ERROR, ";".join(errors))
            return self.get_status()

        submission_id = res["submissions"][0]["submission_id"]
        submission_url = res["submissions"][0]["submission_webif_url"]
        submission_finished = True

        iocs_only = param["ioc_only"]
        status, report = self._get_report(submission_id, DEFAULT_TIMEOUT, iocs_only)
        if status == phantom.APP_ERROR:
            error_msg, _exc = report
            if error_msg == VMRAY_ERR_SUBMISSION_NOT_FINISHED:
                submission_finished = False
            else:
                self.set_status(phantom.APP_ERROR, error_msg, _exc)
                return self.get_status()
            report = None

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if report:
            for analysis in report["analyses"]:
                action_result.add_data({"analysis": analysis})
            if report["reputation_lookup"]:
                action_result.add_data(
                    {"reputation_lookup": report["reputation_lookup"][0]}
                )
            action_result.update_summary(
                {
                    "billing_type": report["billing_type"],
                    "recursive_submission_ids": report["recursive_submission_ids"],
                    "verdict": report["verdict"],
                }
            )

        action_result.update_summary(
            {
                "submission_id": submission_id,
                "url": submission_url,
                "submission_finished": submission_finished,
            }
        )
        action_result.set_status(phantom.APP_SUCCESS)
        return action_result.get_status()

    def _handle_detonate_url(self, param: Dict[str, Any]) -> bool:
        status, api = self._get_api()
        if api is None:
            return status

        url = param["url"]

        self.save_progress("Submitting url %s" % url)

        params = {"reanalyze": True}
        if param.get("comment"):
            params["comment"] = param["comment"]
        if param.get("tags"):
            params["tags"] = param["tags"]
        if param.get("config"):
            params["user_config"] = param["config"]
        if param.get("jobrules", "") != "":
            params["jobrule_entries"] = param["jobrules"]

        try:
            res = api.submit_url(url, params=params)
        except VMRayRESTAPIError as exc:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SUBMIT_FILE, exc)
            return self.get_status()

        if res["errors"]:
            errors = [
                err.get("error_msg", "NO_ERROR_MSG_GIVEN") for err in res["errors"]
            ]
            self.set_status(phantom.APP_ERROR, ";".join(errors))
            return self.get_status()

        submission_id = res["submissions"][0]["submission_id"]
        submission_url = res["submissions"][0]["submission_webif_url"]

        submission_finished = True

        iocs_only = param["ioc_only"]
        status, report = self._get_report(submission_id, DEFAULT_TIMEOUT, iocs_only)
        if status == phantom.APP_ERROR:
            error_msg, _exc = report
            if error_msg == VMRAY_ERR_SUBMISSION_NOT_FINISHED:
                submission_finished = False
            else:
                self.set_status(phantom.APP_ERROR, error_msg, _exc)
                return self.get_status()
            report = None

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if report:
            for analysis in report["analyses"]:
                action_result.add_data({"analysis": analysis})
            if report["reputation_lookup"]:
                action_result.add_data(
                    {"reputation_lookup": report["reputation_lookup"][0]}
                )
            action_result.update_summary(
                {
                    "billing_type": report["billing_type"],
                    "recursive_submission_ids": report["recursive_submission_ids"],
                    "verdict": report["verdict"],
                }
            )

        action_result.update_summary(
            {
                "submission_id": submission_id,
                "url": submission_url,
                "submission_finished": submission_finished,
            }
        )
        action_result.set_status(phantom.APP_SUCCESS)
        return action_result.get_status()

    def _get_report(
        self, submission_id: int, timeout: int, iocs_only: bool = True
    ) -> Union[Tuple[bool, Tuple[str, Exception]]]:
        status, api = self._get_api()
        if api is None:
            return (status, None)

        if not self._submission_finished_within_timeout(api, submission_id, timeout):
            return (phantom.APP_ERROR, (VMRAY_ERR_SUBMISSION_NOT_FINISHED, None))

        self.save_progress("Submission is finished")

        try:
            submission = api.get_submission(submission_id)
            submission_url = submission["submission_webif_url"]
            billing_type = submission["submission_billing_type"]
        except VMRayRESTAPIError as exc:
            return (phantom.APP_ERROR, (VMRAY_ERR_GET_SUBMISSION, exc))

        self.save_progress("Getting results")
        try:
            analyses = api.get_analyses_by_submission_id(submission_id)
        except VMRayRESTAPIError as exc:
            return (phantom.APP_ERROR, (VMRAY_ERR_GET_SUBMISSION, exc))

        for analysis in analyses:
            # convert serverity to verdict
            if "analysis_verdict" not in analysis:
                verdict = SummaryV2.to_verdict(analysis["analysis_severity"])
                analysis["analysis_verdict"] = verdict

            if analysis.get("analysis_result_code", -1) == 1:
                try:
                    summary = api.get_report(analysis["analysis_id"], iocs_only)
                except VMRayRESTAPIError:
                    continue

                analysis["summary"] = summary

        try:
            reputation_lookup = api.get_reputation_by_submission(submission_id)
        except VMRayRESTAPIError:
            self.save_progress("Reputation lookup failed")
            reputation_lookup = None

        try:
            verdict = api.get_verdict_by_submission_id(submission_id)
        except VMRayRESTAPIError:
            self.save_progress("Failed to fetch verdict")
            verdict = "n/a"

        try:
            recursive_submission_ids = api.get_child_submissions(submission_id)
        except VMRayRESTAPIError:
            self.save_progess("Failed to fetch recursive submissions")
            recursive_submission_ids = None

        return (
            phantom.APP_SUCCESS,
            {
                "analyses": analyses,
                "billing_type": billing_type,
                "reputation_lookup": reputation_lookup,
                "verdict": verdict,
                "submission_url": submission_url,
                "recursive_submission_ids": recursive_submission_ids,
            },
        )

    def _handle_get_report(self, param: Dict[str, Any]) -> bool:
        submission_id = int(param["submission_id"])
        timeout = self._get_timeout(param)

        iocs_only = param["ioc_only"]
        status, res = self._get_report(submission_id, timeout, iocs_only)
        if status == phantom.APP_ERROR:
            error_msg, exc = res
            self.set_status(phantom.APP_ERROR, error_msg, exc)
            return self.get_status()

        analyses = res["analyses"]
        billing_type = res["billing_type"]
        recursive_submission_ids = res["recursive_submission_ids"]
        reputation_lookup = res["reputation_lookup"]
        verdict = res["verdict"]
        submission_url = res["submission_url"]

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        for analysis in analyses:
            action_result.add_data({"analysis": analysis})

        if reputation_lookup:
            action_result.add_data({"reputation_lookup": reputation_lookup[0]})

        action_result.update_summary(
            {
                "verdict": verdict,
                "submission_id": submission_id,
                "url": submission_url,
                "billing_type": billing_type,
                "recursive_submission_ids": recursive_submission_ids,
            }
        )
        action_result.set_status(phantom.APP_SUCCESS)

        return action_result.get_status()

    def _handle_get_info(self, param: Dict[str, Any]) -> bool:
        status, api = self._get_api()
        if api is None:
            return status

        self.debug_print("param", param)
        timeout = self._get_timeout(param)

        try:
            status, res = self._get_sample_by_hash(api, param["hash"])
        except VMRayRESTAPIError:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SAMPLE_NOT_FOUND)
            return self.get_status()

        if status == phantom.APP_ERROR:
            return self.get_status()

        self.save_progress("Check for finished submissions")

        sample_id = res[0]["sample_id"]
        has_finished_submission = False
        seconds_waited = 0
        while True:
            submissions = api.call("GET", f"/rest/submission/sample/{sample_id}")
            if not submissions:
                self.set_status(phantom.APP_ERROR, VMRAY_ERR_NO_SUBMISSIONS)
                return self.get_status()

            has_finished_submission = any(
                [sub.get("submission_finished", False) for sub in submissions]
            )

            if has_finished_submission or timeout == 0:
                break
            if seconds_waited >= timeout:
                break

            self.send_progress("No submission finished yet")
            time_to_wait = min(30, timeout - seconds_waited)
            seconds_waited += time_to_wait
            self.send_progress("Waited %d/%d seconds" % (seconds_waited, timeout))
            time.sleep(time_to_wait)

        if not has_finished_submission:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SUBMISSION_NOT_FINISHED)
            return self.get_status()

        try:
            sample_info = api.get_sample(sample_id)
        except VMRayRESTAPIError as exc:
            self.set_status(phantom.APP_ERROR, (VMRAY_ERR_REST_API, exc))
            return self.get_status()

        try:
            recursive_sample_ids = api.get_recursive_samples(sample_id)
        except VMRayRESTAPIError as exc:
            self.set_status(phantom.APP_ERROR, (VMRAY_ERR_REST_API, exc))
            return self.get_status()

        # convert serverity to verdict
        if "sample_verdict" not in sample_info:
            verdict = SummaryV2.to_verdict(sample_info["sample_severity"])
            sample_info["sample_verdict"] = verdict

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)
        action_result.add_data(sample_info)
        action_result.update_summary(
            {
                "recursive_sample_ids": recursive_sample_ids,
                "score": sample_info["sample_score"],
                "verdict": sample_info["sample_verdict"],
            }
        )
        action_result.set_status(phantom.APP_SUCCESS)

        return action_result.get_status()

    def handle_action(self, param: Dict[str, Any]) -> bool:
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action_id == ACTION_ID_VMRAY_GET_FILE:
            ret_val = self._handle_get_file(param)
        elif action_id == ACTION_ID_VMRAY_DETONATE_FILE:
            ret_val = self._handle_detonate_file(param)
        elif action_id == ACTION_ID_VMRAY_DETONATE_URL:
            ret_val = self._handle_detonate_url(param)
        elif action_id == ACTION_ID_VMRAY_GET_REPORT:
            ret_val = self._handle_get_report(param)
        elif action_id == ACTION_ID_VMRAY_GET_INFO:
            ret_val = self._handle_get_info(param)

        return ret_val
