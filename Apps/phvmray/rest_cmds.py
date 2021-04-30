#!/usr/bin/python
"""Example uses of VMRay REST API Python library"""

from argparse import FileType

from rest_api import VMRayRESTAPI, VMRayRESTAPIError  # pylint: disable=W0403

if False:  # pylint: disable=using-constant-test
    # pylint: disable=unused-import,import-error
    from typing import Any, List, Text  # NOQA


class UnicodeFileType(FileType):
    def __init__(self, *args, **kwargs):
        FileType.__init__(self, *args, **kwargs)

    def __call__(self, string):
        try:
            sanitized_str = unicode(string)
        except UnicodeDecodeError:
            import ast
            sanitized_str = unicode(ast.literal_eval("u%s" % repr(string)))
        return FileType.__call__(self, sanitized_str)


class VMRay(VMRayRESTAPI):
    def __init__(self, *args, **kwargs):
        VMRayRESTAPI.__init__(self, *args, **kwargs)
        # test if we can reach the API
        self.call("GET", "/rest/analysis", params={"_limit": "1"})
        try:
            # get the soft limit from api.
            self.items_per_request = int(
                self.call("GET", "/rest/system_info")["api_items_per_request"])
        except VMRayRESTAPIError as excpt:
            # if we do not have admin privs set a sane default value
            # 100 is the default "Items Per Request" given in the
            # "system settings"
            if excpt.status_code == 403:
                self.items_per_request = 100
            else:
                raise excpt

    def get_analyses(self, min_analysis_id=-1, limit=None):
        # type: (int, int) -> Dict[Text, Any]
        if limit is None:
            limit = self.items_per_request
        params = {"_order": "asc"}
        if min_analysis_id != -1:
            params["_min_id"] = str(min_analysis_id)
        if limit != 0:
            params["_limit"] = str(limit)

        data = self.call("GET", "/rest/analysis", params=params)
        return data

    def get_submissions(self, min_submission_id=-1, limit=None):
        # type: (int, int) -> Dict[Text, Any]
        if limit is None:
            limit = self.items_per_request
        params = {"_order": "asc"}
        if min_submission_id != -1:
            params["_min_id"] = str(min_submission_id)
        if limit != 0:
            params["_limit"] = str(limit)

        data = self.call("GET", "/rest/submission", params=params)
        return data

    def get_file_from_archive(self, analysis_id, rel_path):
        # type: (int, Text) -> file
        data = None
        try:
            data = self.call("GET",
                             "/rest/analysis/%u/archive/%s" % (analysis_id,
                                                               rel_path),
                             raw_data=True)
        except VMRayRESTAPIError as excpt:
            if excpt.status_code == 404:
                pass
            else:
                raise
        return data

    def get_submission(self, submission_id):
        # type: (int) -> Dict[Text, Any]
        return self.call("GET", "/rest/submission/%u" % (submission_id))

    def get_reputation_by_submission(self, submission_id):
        # type: (int) -> List[Dict[Text, Any]]
        return self.call(
            "GET", "/rest/reputation_lookup/submission/%u" % (submission_id))

    def get_sample(self, sample_id):
        # type: (int) -> Dict[Text, Any]
        return self.call("GET", "/rest/sample/%u" % (sample_id))

    def get_sample_file(self, sample_id):
        # type: (int) -> file
        return self.call("GET", "/rest/sample/%u/file" % (sample_id),
                         raw_data=True)

    def get_sample_by_md5(self, hsh):
        # type: (Text) -> List[Dict[Text, Any]]
        return self.call("GET", "/rest/sample/md5/%s" % (hsh))

    def get_sample_by_sha1(self, hsh):
        # type: (Text) -> List[Dict[Text, Any]]
        return self.call("GET", "/rest/sample/sha1/%s" % (hsh))

    def get_sample_by_sha256(self, hsh):
        # type: (Text) -> List[Dict[Text, Any]]
        return self.call("GET", "/rest/sample/sha256/%s" % (hsh))

    def get_stix(self, analysis_id):
        # type: (int) -> file
        return self.get_file_from_archive(analysis_id, "logs/stix-report.xml")

    def get_flog(self, analysis_id):
        # type: (int) -> file
        return self.get_file_from_archive(analysis_id, "logs/flog.txt")

    def get_glog(self, analysis_id):
        # type: (int) -> file
        return self.get_file_from_archive(analysis_id, "logs/glog.xml")

    def get_timing(self, analysis_id):
        # type: (int) -> file
        return self.get_file_from_archive(analysis_id,
                                          "additional/timing.json")

    def get_vti_result(self, analysis_id):
        # type: (int) -> file
        return self.get_file_from_archive(analysis_id,
                                          "additional/vti_result.json")

    def get_yara(self, analysis_id):
        # type: (int) -> file
        return self.get_file_from_archive(analysis_id,
                                          "additional/yara_result.json")

    def get_size(self, analysis_id):
        # type: (int) -> file
        return self.get_file_from_archive(analysis_id,
                                          "additional/archive_size.json")

    def get_summary(self, analysis_id):
        # type: (int) -> file
        return self.get_file_from_archive(analysis_id,
                                          "logs/summary.json")

    # for debugging only
    def get_wrong_file(self, analysis_id):
        # type: (int) -> file
        return self.get_file_from_archive(analysis_id, "FILE/DOES_NOT_EXIST")

    def submit_file(self, filepath, params=None):
        # type: (Text, Dict[Text, Any]) -> Dict[Text, Any]
        with open(filepath, "rb") as fobj:
            _params = {"sample_file": fobj}  # type: Dict[Text, Any]
            _params.update(params)
            return self.call("POST", "/rest/sample/submit", params=_params)

    def submit_url(self, url, params=None):
        # type: (Text, Dict[Text, Any]) -> Dict[Text, Any]
        _params = {"sample_url": url}  # type: Dict[Text, Any]
        _params.update(params)
        return self.call("POST", "/rest/sample/submit", params=_params)
