# File: zip_and_encrypt.py
#
# Copyright (c) 2014-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
import sys
import os
import uuid
import pexpect
from bs4 import UnicodeDammit

zipexec = "/usr/bin/zip"


def _is_exec(path):
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        return False
    return True


class zip_and_encrypt:
    def __init__(self, prefix, password):
        if not _is_exec(zipexec):
            raise Exception(f"{zipexec} is not executable")

        self._prefix = prefix
        self._password = password
        self._archive = f"{prefix}_{uuid.uuid4()}"
        self._fp = None
        self._output = None

    @property
    def output(self):
        return self._output

    @property
    def archive_name(self):
        return self._archive

    @property
    def archive_path(self):
        return self._archive + ".zip"

    @property
    def archive_fp(self):
        if self._fp:
            return self._fp

        if not os.path.isfile(self.archive_path):
            raise Exception(f"{self.archive_path} doesn't exists")

        self._fp = open(self.archive_path, "rb")
        return self._fp

    def add(self, filename):
        if not os.path.exists(filename):
            raise Exception(f"{filename} does not exists")

        cmd = [
            zipexec,
            "-j",
            "-e",
            self.archive_path,
            filename,
        ]
        command = " ".join(cmd)
        command_output, exitstatus = pexpect.run(command, withexitstatus=True, events={"(?i)password: ": f"{self._password}\n"})

        if exitstatus != 0:
            raise Exception("Unable to perform zip and encryption on file. {}".format(UnicodeDammit(command_output).unicode_markup))

        return True

    def cleanup(self):
        filename = self.archive_path
        if not os.path.exists(filename):
            return False
        return os.remove(self.archive_path)

    def __del__(self):
        self.cleanup()


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print(f"usage: {os.path.basename(sys.argv[0])} <filename>")
        sys.exit(0)

    try:
        zae = zip_and_encrypt("/tmp/phcuckoo_app_", "password")
        if zae.add(sys.argv[1]) is True:
            print("file archived")

    except Exception as e:
        print(f"Error: {e}")

    print(f"archive name: {zae.archive_name}")
    print(f"archive path: {zae.archive_path}")
    try:
        print(f"file description type is {type(zae.archive_fp)}")
    except Exception as e:
        print(f"Error: {e}")
    print(f"output is {zae.output.strip()}")
    zae.cleanup()
    if os.path.exists(zae.archive_path):
        print("cleanup unsuccessful")
    else:
        print("cleanup successful")
