
from __future__ import print_function, unicode_literals

import base64
import json
import os
import time
import zipfile


from phantom.action_result import ActionResult    # pylint: disable=F0401
import phantom.app as phantom                     # pylint: disable=F0401
from phantom.base_connector import BaseConnector  # pylint: disable=F0401
from phantom.vault import Vault                   # pylint: disable=F0401

from vmray_consts import (                        # pylint: disable=W0403
                            ACTION_ID_VMRAY_DETONATE_FILE,
                            ACTION_ID_VMRAY_DETONATE_URL,
                            ACTION_ID_VMRAY_GET_FILE,
                            ACTION_ID_VMRAY_GET_INFO,
                            ACTION_ID_VMRAY_GET_REPORT,
                            DEFAULT_TIMEOUT,
                            VAULT_TMP_FOLDER,
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
                            VMRAY_JSON_API_KEY,
                            VMRAY_JSON_DISABLE_CERT,
                            VMRAY_JSON_SERVER,
                            VMRAY_SEVERITY_BLACKLISTED,
                            VMRAY_SEVERITY_ERROR,
                            VMRAY_SEVERITY_MALICIOUS,
                            VMRAY_SEVERITY_NOT_SUSPICIOUS,
                            VMRAY_SEVERITY_SUSPICIOUS,
                            # VMRAY_SEVERITY_WHITELISTED,
                            # VMRAY_SEVERITY_UNKNOWN,
                            VMRAY_SUCC_CONNECTIVITY_TEST,
                         )

from rest_cmds import VMRay  # pylint: disable=relative-import

if False:  # pylint: disable=using-constant-test
    # pylint: disable=unused-import,import-error
    from typing import Any, Text, Tuple, Union  # NOQA

# pylint: disable=broad-except


def _analysis_severity_by_score(score):
    # type: (int) -> Text
    """Return severity for given analysis score"""

    if score < 25:
        return VMRAY_SEVERITY_NOT_SUSPICIOUS
    elif score < 75:
        return VMRAY_SEVERITY_SUSPICIOUS
    else:
        return VMRAY_SEVERITY_MALICIOUS


# see sample_model.py severity(self, user)
def _severity(highest_vti_score, reputation_severity):
    # type: (int, Text) -> Text

    if highest_vti_score is not None:
        # there exists at least one analysis score
        analyses_severity = _analysis_severity_by_score(highest_vti_score)

        if analyses_severity == VMRAY_SEVERITY_MALICIOUS:
            # analysis score says malicious -> return malicious
            return VMRAY_SEVERITY_MALICIOUS
        elif reputation_severity == VMRAY_SEVERITY_BLACKLISTED:
            # reputation says blacklisted -> return blacklisted
            return VMRAY_SEVERITY_BLACKLISTED
        elif (analyses_severity == VMRAY_SEVERITY_SUSPICIOUS) or (
                reputation_severity == VMRAY_SEVERITY_SUSPICIOUS):
            # analysis score or reputation say suspicious -> return
            # suspicious
            return VMRAY_SEVERITY_SUSPICIOUS
        else:
            # analysis score says not suspicious, reputation says
            # something uninteresting -> return not suspicious
            return VMRAY_SEVERITY_NOT_SUSPICIOUS
    elif (reputation_severity is not None) and (
            reputation_severity != VMRAY_SEVERITY_ERROR):
        # no analysis score exists, reputation severity exists  -> return
        # mapped reputation result
        return reputation_severity
    else:
        # no analysis score or reputation severity exists -> return None
        return None


class VMRayConnector(BaseConnector):

    def __init__(self):
        # type: () -> None

        # Call the BaseConnectors init first
        super(VMRayConnector, self).__init__()
        self._api = None  # type: VMRay

    def _test_connectivity(self, _):
        # type: (Dict[Text, Any]) -> bool

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
        except Exception as exc:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SERVER_CONNECTION,
                            exc)
            self.append_to_message(VMRAY_ERR_CONNECTIVITY_TEST)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS,
                                             VMRAY_SUCC_CONNECTIVITY_TEST)

    def _get_api(self):
        # type: () -> Tuple[bool, VMRay]

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
        except Exception as exc:
            self._api = None
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SERVER_CONNECTION,
                            exc)
            return (self.get_status(), None)

    def _handle_get_file(self, param):
        # type: (Dict[Text, Any]) -> bool

        status, api = self._get_api()
        if api is None:
            return status

        self.debug_print("param", param)

        hsh = param["hash"]

        self.save_progress("Searching %s" % (hsh))

        if len(hsh) == 32:
            res = api.get_sample_by_md5(hsh)
        elif len(hsh) == 40:
            res = api.get_sample_by_sha1(hsh)
        elif len(hsh) == 64:
            res = api.get_sample_by_sha256(hsh)
        else:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_UNSUPPORTED_HASH)
            return self.get_status()

        if len(res) == 0 or "sample_id" not in res[0]:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SAMPLE_NOT_FOUND)
            return self.get_status()

        if res[0]["sample_is_multipart"]:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_MULTIPART)
            return self.get_status()

        self.save_progress("Downloading file")

        zip_file_location = os.path.join(VAULT_TMP_FOLDER, "%s.zip" % hsh)
        file_location = os.path.join(VAULT_TMP_FOLDER, hsh)
        if os.path.exists(zip_file_location) or os.path.exists(file_location):
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_FILE_EXISTS)
            return self.get_status()

        # added b"wb" otherwise mypy complains
        with api.get_sample_file(res[0]["sample_id"]) as data:
            with open(zip_file_location, str("wb")) as fobj:
                fobj.write(data.read())

        try:
            # again wiredness due to mypy
            zifi = zipfile.ZipFile(str(zip_file_location), str("r"))
        except Exception as exc:
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
            # pylint: disable=bad-continuation
            with zifi.open(
                    zf_names[0], str("r"), VMRAY_DEFAULT_PASSWORD) as ifobj:
                with open(file_location, str("wb")) as ofobj:
                    ofobj.write(ifobj.read())

        except Exception as exc:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_MALFORMED_ZIP, exc)
            if os.path.exists(file_location):
                os.remove(file_location)
            return self.get_status()

        finally:
            zifi.close()
            os.remove(zip_file_location)

        vmray_sampletypes = [x["sample_type"] for x in res]
        phantom_sampletypes = []
        for st in vmray_sampletypes:
            if st == "PDF Document":
                phantom_sampletypes.append("pdf")
            elif st == "Word Document":
                phantom_sampletypes.append("doc")
            elif st == "Excel Document":
                phantom_sampletypes.append("xls")
            elif st == "Powerpoint Document":
                phantom_sampletypes.append("ppt")
            elif st == "Java Archive":
                phantom_sampletypes.append("jar")
            elif st == "JScript":
                phantom_sampletypes.append("javascript")
            elif st.startswith("Windows Exe"):
                phantom_sampletypes.append("pe file")
            elif st.startswith("Windows DLL"):
                phantom_sampletypes.append("pe file")
            elif st.startswith("Windows Driver"):
                phantom_sampletypes.append("pe file")

        phantom_sampletypes = list(set(phantom_sampletypes))

        self.save_progress("Adding file to vault")
        vlt_res = Vault.add_attachment(
            file_location, self.get_container_id(),
            file_name=res[0]["sample_filename"],
            metadata={"size": res[0]["sample_filesize"],
                      "contains": phantom_sampletypes})

        if not vlt_res["succeeded"]:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_ADD_VAULT)

            os.remove(file_location)

            return self.get_status()

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)
        action_result.add_data({"vault_id": vlt_res["vault_id"]})
        action_result.update_summary({"vault_id": vlt_res["vault_id"]})
        action_result.set_status(phantom.APP_SUCCESS)

        # the vault removes the file after successfully finishing. so
        # so we do not need to remove it manually
        # os.remove(file_location)

        self.save_progress("Finished")

        return action_result.get_status()

    def _handle_detonate_file(self, param):
        # type: (Dict[Text, Any]) -> bool

        status, api = self._get_api()
        if api is None:
            return status

        vault_id = param["vault_id"]
        file_path = Vault.get_file_path(vault_id)
        file_info = Vault.get_file_info(vault_id=vault_id)

        self.save_progress("Submitting file %s" % vault_id)

        params = {"reanalyze": True}  # type: Dict[Text, Any]
        if param.get("comment", None) is not None:
            params["comment"] = param["comment"]
        if param.get("tags", None) is not None:
            params["tags"] = param["tags"]
        if param.get("type", "") != "":
            params["sample_type"] = param["type"]
        if param.get("config", "") != "":
            params["user_config"] = param["config"]
        if param.get("jobrules", "") != "":
            params["jobrule_entries"] = param["jobrules"]

        if param.get("file_name", "") != "":
            params["sample_filename_b64enc"] = (
                base64.b64encode(param["file_name"]))
        elif (file_info and len(file_info) == 1 and
              file_info[0].get("name", "") != ""):
            params["sample_filename_b64enc"] = (
                base64.b64encode(file_info[0]["name"]))

        try:
            res = api.submit_file(file_path, params=params)
        except Exception as exc:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SUBMIT_FILE, exc)
            return self.get_status()

        if res["errors"]:
            errors = [err.get("error_msg",
                              "NO_ERROR_MSG_GIVEN") for err in res["errors"]]
            self.set_status(phantom.APP_ERROR, ";".join(errors))
            return self.get_status()

        submission_id = res["submissions"][0]["submission_id"]
        submission_url = res["submissions"][0]["submission_webif_url"]
        submission_finished = True

        status, report = self._get_report(submission_id, DEFAULT_TIMEOUT)
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

        if report is not None:
            for analysis in report["analyses"]:
                action_result.add_data({"analysis": analysis})
            if report["reputation_lookup"]:
                action_result.add_data({"reputation_lookup": report["reputation_lookup"][0]})
            action_result.update_summary({"severity": report["severity"]})

        action_result.update_summary(
            {"submission_id": submission_id, "url": submission_url,
             "submission_finished": submission_finished})
        action_result.set_status(phantom.APP_SUCCESS)
        return action_result.get_status()

    def _handle_detonate_url(self, param):
        # type: (Dict[Text, Any]) -> bool

        status, api = self._get_api()
        if api is None:
            return status

        url = param["url"]

        self.save_progress("Submitting url %s" % url)

        params = {"reanalyze": True}
        if param.get("comment", None) is not None:
            params["comment"] = param["comment"]
        if param.get("tags", None) is not None:
            params["tags"] = param["tags"]
        if param.get("config", "") != "":
            params["user_config"] = param["config"]
        if param.get("jobrules", "") != "":
            params["jobrule_entries"] = param["jobrules"]

        try:
            res = api.submit_url(url, params=params)
        except Exception as exc:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SUBMIT_FILE, exc)
            return self.get_status()

        if res["errors"]:
            errors = [err.get("error_msg",
                              "NO_ERROR_MSG_GIVEN") for err in res["errors"]]
            self.set_status(phantom.APP_ERROR, ";".join(errors))
            return self.get_status()

        submission_id = res["submissions"][0]["submission_id"]
        submission_url = res["submissions"][0]["submission_webif_url"]

        submission_finished = True
        status, report = self._get_report(submission_id, DEFAULT_TIMEOUT)
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

        if report is not None:
            for analysis in report["analyses"]:
                action_result.add_data({"analysis": analysis})
            if report["reputation_lookup"]:
                action_result.add_data({"reputation_lookup": report["reputation_lookup"][0]})
            action_result.update_summary({"severity": report["severity"]})

        action_result.update_summary(
            {"submission_id": submission_id, "url": submission_url,
             "submission_finished": submission_finished})
        action_result.set_status(phantom.APP_SUCCESS)
        return action_result.get_status()

    def _get_report(self, submission_id, timeout):
        # type: (int, int) -> Tuple[bool, Any]
        # not working due to mypy bug ...
        # # type: (int, int) -> Union[Tuple[bool, Tuple[str, Exception]],
        # Tuple[bool, Dict[str, Any]]]

        status, api = self._get_api()
        if api is None:
            return (status, None)

        seconds_waited = 0
        submission_finished = False
        submission_url = None

        self.save_progress("Getting submission %u" % submission_id)
        while True:
            try:
                submission = api.get_submission(submission_id)
            except Exception as exc:
                return (phantom.APP_ERROR, (VMRAY_ERR_GET_SUBMISSION, exc))

            self.send_progress("Checking submission status")
            submission_finished = submission["submission_finished"]
            submission_url = submission["submission_webif_url"]
            if submission_finished or timeout == 0:
                break
            elif seconds_waited >= timeout:
                break
            else:
                self.send_progress("Submission is not finished yet")
                time_to_wait = min(30, timeout - seconds_waited)
                seconds_waited += time_to_wait
                self.send_progress("Waited %d/%d seconds" %
                                   (seconds_waited, timeout))
                time.sleep(time_to_wait)

        if not submission_finished:
            return (phantom.APP_ERROR, (VMRAY_ERR_SUBMISSION_NOT_FINISHED,
                                        None))

        self.save_progress("Submission is finished")

        self.save_progress("Getting results")
        try:
            analyses = api.call("GET",
                                "/rest/analysis?analysis_submission_id=%u" %
                                submission_id)
        except Exception as exc:
            return (phantom.APP_ERROR, (VMRAY_ERR_GET_SUBMISSION, exc))

        reputation_severity = None
        reputation_lookup = None
        try:
            reputation_lookup = api.get_reputation_by_submission(submission_id)
            if reputation_lookup:
                reputation_severity = (
                    reputation_lookup[0]["reputation_lookup_severity"])
        except Exception:
            self.save_progress("Reputation lookup failed")

        highest_vti_score = None
        for analysis in analyses:
            if analysis.get("analysis_result_code", -1) == 1:
                highest_vti_score = max(
                    highest_vti_score,
                    analysis.get("analysis_vti_score", None))
                try:
                    summary_file = api.get_summary(analysis["analysis_id"])
                    summary = json.loads(summary_file.read())
                    analysis["summary"] = summary
                except Exception as exc:
                    pass

        severity = _severity(highest_vti_score, reputation_severity)

        return (phantom.APP_SUCCESS, {"analyses": analyses,
                                      "reputation_lookup": reputation_lookup,
                                      "severity": severity,
                                      "submission_url": submission_url})

    def _handle_get_report(self, param):
        # type: (Dict[Text, Any]) -> bool

        submission_id = int(param["submission_id"])

        try:
            timeout = int(param["timeout"])
            if timeout < 0:
                timeout = DEFAULT_TIMEOUT
        except Exception:
            timeout = DEFAULT_TIMEOUT

        status, res = self._get_report(submission_id, timeout)
        if status == phantom.APP_ERROR:
            error_msg, exc = res
            self.set_status(phantom.APP_ERROR, error_msg, exc)
            return self.get_status()

        analyses = res["analyses"]
        reputation_lookup = res["reputation_lookup"]
        severity = res["severity"]
        submission_url = res["submission_url"]

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        for analysis in analyses:
            action_result.add_data({"analysis": analysis})

        if reputation_lookup:
            action_result.add_data({"reputation_lookup": reputation_lookup[0]})

        action_result.update_summary({"severity": severity,
                                      "submission_id": submission_id,
                                      "url": submission_url})
        action_result.set_status(phantom.APP_SUCCESS)

        return action_result.get_status()

    def _handle_get_info(self, param):
        # type: (Dict[Text, Any]) -> bool

        status, api = self._get_api()
        if api is None:
            return status

        self.debug_print("param", param)

        try:
            timeout = int(param["timeout"])
            if timeout < 0:
                timeout = DEFAULT_TIMEOUT
        except Exception:
            timeout = DEFAULT_TIMEOUT

        hsh = param["hash"]

        self.save_progress("Searching %s" % (hsh))

        if len(hsh) == 32:
            res = api.get_sample_by_md5(hsh)
        elif len(hsh) == 40:
            res = api.get_sample_by_sha1(hsh)
        elif len(hsh) == 64:
            res = api.get_sample_by_sha256(hsh)
        else:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_UNSUPPORTED_HASH)
            return self.get_status()

        if len(res) == 0:
            self.set_status(phantom.APP_ERROR, VMRAY_ERR_SAMPLE_NOT_FOUND)
            return self.get_status()

        self.save_progress("Check for finished submissions")

        has_finished_submission = False
        seconds_waited = 0
        while True:
            submissions = api.call("GET", "/rest/submission/sample/%u" %
                                   res[0]["sample_id"])
            if not submissions:
                self.set_status(phantom.APP_ERROR, VMRAY_ERR_NO_SUBMISSIONS)
                return self.get_status()

            has_finished_submission = any([sub.get("submission_finished",
                                                   False)
                                           for sub in submissions])
            if has_finished_submission or timeout == 0:
                break
            elif seconds_waited >= timeout:
                break
            else:
                self.send_progress("No submission finished yet")
                time_to_wait = min(30, timeout - seconds_waited)
                seconds_waited += time_to_wait
                self.send_progress("Waited %d/%d seconds" %
                                   (seconds_waited, timeout))
                time.sleep(time_to_wait)

        if not has_finished_submission:
            self.set_status(phantom.APP_ERROR,
                            VMRAY_ERR_SUBMISSION_NOT_FINISHED)
            return self.get_status()

        sample_info = api.get_sample(res[0]["sample_id"])

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)
        action_result.add_data(sample_info)
        action_result.update_summary(
            {"score": sample_info["sample_score"],
             "severity": sample_info["sample_severity"]})
        action_result.set_status(phantom.APP_SUCCESS)

        return action_result.get_status()

    def handle_action(self, param):
        # type: (Dict[Text, Any]) -> bool

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


def main():
    # pylint: disable=attribute-defined-outside-init
    # pylint: disable=protected-access
    import sys

    import pudb  # pylint: disable=import-error

    pudb.set_trace()

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as fin:
        in_json = fin.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = VMRayConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
