# File: rest_cmds.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
import json

from argparse import FileType
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Union

try:
    from rest_api import VMRayRESTAPI, VMRayRESTAPIError  # pylint: disable=import-error
except ModuleNotFoundError:
    from .rest_api import VMRayRESTAPI, VMRayRESTAPIError


def remove_no_ioc_artifacts(report: Dict[str, Any]) -> Dict[str, Any]:
    if "artifacts" not in report:
        return report

    for items in report["artifacts"].values():
        if not isinstance(items, list):
            continue

        for item in reversed(items):
            if not isinstance(item, dict):
                continue

            if "ioc" in item and not item["ioc"]:
                items.remove(item)

    return report


class UnicodeFileType(FileType):
    def __init__(self, *args, **kwargs) -> None:
        FileType.__init__(self, *args, **kwargs)

    def __call__(self, string: str) -> None:
        try:
            sanitized_str = str(string)
        except UnicodeDecodeError:
            import ast  # pylint: disable=import-outside-toplevel

            sanitized_str = str(ast.literal_eval("u%s" % repr(string)))
        return FileType.__call__(self, sanitized_str)


class VMRay(VMRayRESTAPI):
    def __init__(self, *args, **kwargs):
        VMRayRESTAPI.__init__(self, *args, **kwargs)
        # test if we can reach the API
        self.call("GET", "/rest/analysis", params={"_limit": "1"})
        try:
            system_info = self.call("GET", "/rest/system_info")
            # get the soft limit from api.
            self.items_per_request = int(system_info["api_items_per_request"])
            self.version = system_info["version"]
            self.version_major = int(system_info["version_major"])
            self.version_minor = int(system_info["version_minor"])
            self.version_revision = int(system_info["version_revision"])
        except VMRayRESTAPIError as excpt:
            # if we do not have admin privs set a sane default value
            # 100 is the default "Items Per Request" given in the
            # "system settings"
            if excpt.status_code == 403:
                self.items_per_request = 100
                self.version = "1.0.0"
                self.version_major = 1
                self.version_minor = 0
                self.version_revision = 0
            else:
                raise excpt

    def has_at_least_version(
        self, major: int, minor: int = 0, revision: int = 0
    ) -> bool:
        wanted_version = (major, minor, revision)
        cur_version = (self.version_major, self.version_minor, self.version_revision)

        return cur_version >= wanted_version

    def get_analyses(
        self, last_analysis_id: int = -1, limit: Optional[int] = None
    ) -> Dict[str, Any]:
        if limit is None:
            limit = self.items_per_request
        params = {"_order": "asc"}
        if last_analysis_id != -1:
            if self.has_at_least_version(4):
                # _last_id parameter was introduced in 4.0
                # uses "greater than" semantics
                params["_last_id"] = str(last_analysis_id)
            else:
                # greater than or equals
                params["_min_id"] = str(last_analysis_id + 1)
        if limit != 0:
            params["_limit"] = str(limit)

        data = self.call("GET", "/rest/analysis", params=params)
        return data

    def get_submissions(
        self, last_submission_id: int = -1, limit: Optional[int] = None
    ) -> Dict[str, Any]:
        if limit is None:
            limit = self.items_per_request
        params = {"_order": "asc"}
        if last_submission_id != -1:
            if self.has_at_least_version(4, 0, 1):
                # _last_id parameter was introduced in 4.0 and fixed in 4.0.1
                # greater than
                params["_last_id"] = str(last_submission_id)
            else:
                # greater than or equals
                params["_min_id"] = str(last_submission_id + 1)
        if limit != 0:
            params["_limit"] = str(limit)

        data = self.call("GET", "/rest/submission", params=params)
        return data

    def get_file_from_archive(self, analysis_id: int, rel_path: str) -> BinaryIO:
        data = self.call(
            "GET",
            f"/rest/analysis/{analysis_id}/archive/{rel_path}",
            raw_data=True,
        )

        return data

    def get_submission(self, submission_id: int) -> Dict[str, Any]:
        return self.call("GET", f"/rest/submission/{submission_id}")

    def get_reputation_by_submission(self, submission_id: int) -> List[Dict[str, Any]]:
        lookups = self.call(
            "GET", f"/rest/reputation_lookup/submission/{submission_id}"
        )

        for lookup in lookups:
            if "reputation_lookup_verdict" not in lookup:
                severity = lookup["reputation_lookup_severity"]
                lookup["reputation_lookup_verdict"] = SummaryV2.to_verdict(severity)
            else:
                verdict = lookup["reputation_lookup_verdict"]
                lookup["reputation_lookup_verdict"] = SummaryV2.convert_verdict(verdict)

        return lookups

    def get_sample(self, sample_id: int) -> Dict[str, Any]:
        return self.call("GET", f"/rest/sample/{sample_id}")

    def get_sample_file(self, sample_id: int) -> BinaryIO:
        return self.call("GET", f"/rest/sample/{sample_id}/file", raw_data=True)

    def get_sample_by_md5(self, hsh: str) -> List[Dict[str, Any]]:
        return self.call("GET", f"/rest/sample/md5/{hsh}")

    def get_sample_by_sha1(self, hsh: str) -> List[Dict[str, Any]]:
        return self.call("GET", f"/rest/sample/sha1/{hsh}")

    def get_sample_by_sha256(self, hsh: str) -> List[Dict[str, Any]]:
        return self.call("GET", f"/rest/sample/sha256/{hsh}")

    def get_stix(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "logs/stix-report.xml")

    def get_flog(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "logs/flog.txt")

    def get_glog(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "logs/glog.xml")

    def get_timing(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "additional/timing.json")

    def get_vti_result(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "additional/vti_result.json")

    def get_yara(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "additional/yara_result.json")

    def get_size(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "additional/archive_size.json")

    def get_summary(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "logs/summary.json")

    def get_summary_v2(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "logs/summary_v2.json")

    def get_report(self, analysis_id: int, iocs_only: bool = True) -> Dict[str, Any]:
        try:
            report_v2 = self.get_summary_v2(analysis_id)
            summary_v2 = SummaryV2(json.load(report_v2))
            summary = summary_v2.to_v1()
        except (VMRayParsingError, VMRayRESTAPIError):
            report_v1 = self.get_summary(analysis_id)
            summary = json.load(report_v1)

        if iocs_only:
            return remove_no_ioc_artifacts(summary)

        return summary

    def get_verdict_by_submission_id(self, submission_id: int) -> str:
        submission = self.get_submission(submission_id)
        return self.get_verdict_by_sample_id(submission["submission_sample_id"])

    def get_verdict_by_sample_id(self, sample_id: int) -> str:
        sample = self.get_sample(sample_id)

        # VMRay Platform >= 4.0.0
        if "sample_verdict" in sample:
            verdict = sample["sample_verdict"]
            return SummaryV2.convert_verdict(verdict)

        # convert the severity to verdict
        if "sample_severity" in sample:
            verdict = SummaryV2.to_verdict(sample["sample_severity"])
            return verdict

        # convert VTI score to verdict
        if "sample_score" in sample:
            verdict = SummaryV2.to_verdict(sample["sample_score"])
            return verdict

        return "n/a"

    def is_submission_finished(self, submission_id: int) -> bool:
        submission = self.get_submission(submission_id)
        return submission["submission_finished"]

    def get_analyses_by_submission_id(self, submission_id: int) -> List[Dict[str, Any]]:
        return self.call(
            "GET", f"/rest/analysis?analysis_submission_id={submission_id}"
        )

    def get_child_submissions(self, submission_id: int) -> Optional[Dict[str, Any]]:
        if not self.has_at_least_version(4, 2, 0):
            return None

        child_submissions = self.call(
            "GET", f"/rest/submission?submission_parent_submission_id={submission_id}"
        )

        child_submission_ids = [
            {"child_submission_id": child["submission_id"]}
            for child in child_submissions
        ]

        return {"child_submission_ids": child_submission_ids}

    def get_recursive_samples(self, sample_id: int) -> Dict[str, Any]:
        info = self.get_sample(sample_id)

        child_sample_ids = {}
        if "sample_child_sample_ids" in info:
            child_sample_ids = [
                {"child_sample_id": child} for child in info["sample_child_sample_ids"]
            ]

        parent_sample_ids = {}
        if "sample_parent_sample_ids" in info:
            parent_sample_ids = [
                {"parent_sample_id": parent}
                for parent in info["sample_parent_sample_ids"]
            ]

        recursive_sample_ids = {
            "parent_sample_ids": parent_sample_ids,
            "child_sample_ids": child_sample_ids,
        }

        return recursive_sample_ids

    # for debugging only
    def get_wrong_file(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "FILE/DOES_NOT_EXIST")

    def submit_file(
        self, filepath: str, params: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        with open(filepath, "rb") as fobj:
            _params = {"sample_file": fobj}
            _params.update(params)
            return self.call("POST", "/rest/sample/submit", params=_params)

    def submit_url(self, url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        _params = {"sample_url": url}
        _params.update(params)
        return self.call("POST", "/rest/sample/submit", params=_params)


class VMRayParsingError(Exception):
    pass


class SummaryV2:
    def __init__(self, report: Dict[str, Any]) -> None:
        if "_type" not in report and report["_type"] != "summary":
            raise VMRayParsingError("Not a summary v2 file")

        self.report = report

    def to_v1(self) -> Dict[str, Any]:
        report_v1 = {}

        artifacts = self._get_v1_artifacts()
        report_v1.update(artifacts)

        extracted_files = self._get_v1_extracted_files()
        report_v1.update(extracted_files)

        vtis = self._get_v1_vtis()
        report_v1.update(vtis)

        mitre_attack = self._get_v1_mitre_attack()
        report_v1.update(mitre_attack)

        return report_v1

    @classmethod
    def convert_verdict(cls, verdict: Optional[str]) -> str:
        if verdict == "not_available" or not verdict:
            return "n/a"

        return verdict

    @classmethod
    def to_verdict(cls, score: Union[int, str]) -> str:
        if isinstance(score, int):
            if 0 <= score <= 24:
                return "clean"
            if 25 <= score <= 74:
                return "suspicious"
            if 75 <= score <= 100:
                return "malicious"
            return "n/a"
        if isinstance(score, str):
            score = score.lower()
            if score in ("not_suspicious", "whitelisted"):
                return "clean"
            if score == "blacklisted":
                return "malicious"
            if score in ("not_available", "unknown"):
                return "n/a"
            return score
        return "n/a"

    def _resolve_refs(
        self, data: Union[List[Dict[str, Any]], Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        if not data:
            return

        if isinstance(data, dict):
            data = [data]

        for ref in data:
            yield self._resolve_ref(ref)

    def _resolve_ref(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if data == {}:
            return {}

        if data["_type"] != "reference" or data["source"] != "logs/summary_v2.json":
            return {}

        resolved_ref = self.report
        for path_part in data["path"]:
            try:
                resolved_ref = resolved_ref[path_part]
            except KeyError:
                return {}

        return resolved_ref

    def _get_v1_artifacts(self) -> Dict[str, Any]:
        if "artifacts" not in self.report:
            return {}

        v1_artifacts = {"artifacts": {}}
        artifacts = self.report["artifacts"]

        domains = []
        ref_domains = artifacts.get("ref_domains", [])
        for domain in self._resolve_refs(ref_domains):
            domains.append(
                {
                    "domain": domain["domain"],
                    "ioc": domain["is_ioc"],
                }
            )

        v1_artifacts["artifacts"].update({"domains": domains})

        emails = []
        ref_emails = artifacts.get("ref_emails", [])
        for email in self._resolve_refs(ref_emails):
            emails.append(
                {
                    "ioc": email["is_ioc"],
                    "sender": email["sender"],
                    "subject": email["subject"],
                }
            )

        v1_artifacts["artifacts"].update({"emails": emails})

        filenames = []
        ref_files = artifacts.get("ref_files", [])
        for file_ in self._resolve_refs(ref_files):
            if "ref_filenames" in file_:
                for filename in self._resolve_refs(file_["ref_filenames"]):
                    if not filename:
                        continue

                    if filename not in filenames:
                        filenames.append(
                            {
                                "ioc": file_["is_ioc"],
                                "norm_filename": filename["filename"],
                            }
                        )

        v1_artifacts["artifacts"].update({"files": filenames})

        ip_addresses = []
        ref_ip_addresses = artifacts.get("ref_ip_addresses", [])
        for ip in self._resolve_refs(ref_ip_addresses):
            ip_addresses.append(
                {
                    "ip_address": ip["ip_address"],
                    "ioc": ip["is_ioc"],
                }
            )

        v1_artifacts["artifacts"].update({"ips": ip_addresses})

        mutexes = []
        ref_mutexes = artifacts.get("ref_mutexes", [])
        for mutex in self._resolve_refs(ref_mutexes):
            mutexes.append(
                {
                    "ioc": mutex["is_ioc"],
                    "mutex_name": mutex["name"],
                }
            )

        v1_artifacts["artifacts"].update({"mutexes": mutexes})

        processes = []
        ref_processes = artifacts.get("ref_processes", [])
        for process in self._resolve_refs(ref_processes):
            processes.append(
                {
                    "cmd_line": process["cmd_line"],
                    "ioc": process["is_ioc"],
                }
            )

        v1_artifacts["artifacts"].update({"processes": processes})

        registry_records = []
        ref_registry_records = artifacts.get("ref_registry_records", [])
        for reg in self._resolve_refs(ref_registry_records):
            registry_records.append(
                {
                    "ioc": reg["is_ioc"],
                    "reg_key_name": reg["reg_key_name"],
                }
            )

        v1_artifacts["artifacts"].update({"registry": registry_records})

        urls = []
        url_refs = artifacts.get("ref_urls", [])
        for url in self._resolve_refs(url_refs):
            urls.append(
                {
                    "ioc": url["is_ioc"],
                    "url": url["url"],
                }
            )

        v1_artifacts["artifacts"].update({"urls": urls})

        return v1_artifacts

    def _get_v1_extracted_files(self) -> Dict[str, Any]:
        if "extracted_files" not in self.report:
            return {}

        extracted_files = []
        for _, extracted_file in self.report["extracted_files"].items():
            file_ = self._resolve_ref(extracted_file["ref_file"])

            for filename in self._resolve_refs(extracted_file["ref_filenames"]):
                extracted_files.append(
                    {
                        "ioc": file_["is_ioc"],
                        "md5_hash": file_["hash_values"]["md5"],
                        "norm_filename": filename.get("filename"),
                        "sha1_hash": file_["hash_values"]["sha1"],
                        "sha256_hash": file_["hash_values"]["sha256"],
                    }
                )

        return {"extracted_files": extracted_files}

    def _get_v1_vtis(self) -> Dict[str, Any]:
        if "matches" not in self.report["vti"]:
            return {}

        vti_rule_matches = []
        vti_matches = self.report["vti"]["matches"]
        for vti in vti_matches.values():
            threat_names = vti.get("threat_names", [])
            threat_names = [{"name": name} for name in threat_names]

            vti_rule_matches.append(
                {
                    "category_desc": vti["category_desc"],
                    "rule_score": vti["analysis_score"],
                    "operation_desc": vti["operation_desc"],
                    "technique_desc": vti["technique_desc"],
                    "rule_classifications": vti.get("classifications", []),
                    "threat_names": threat_names,
                }
            )

        return {"vti": {"vti_rule_matches": vti_rule_matches}}

    def _get_v1_mitre_attack(self) -> Dict[str, Any]:
        mitre_attack = self.report["mitre_attack"]
        techniques = mitre_attack["v4"]["techniques"]

        v1_techniques = []
        for technique_id, technique in techniques.items():
            v1_techniques.append(
                {
                    "description": technique["description"],
                    "id": technique_id.replace("technique_", ""),
                }
            )

        return {"mitre_attack": {"techniques": v1_techniques}}
