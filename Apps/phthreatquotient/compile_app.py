#!/usr/bin/env python2.7
###########################################################################################################
# ThreatQuotient Proprietary and Confidential
# Copyright (c)2021 ThreatQuotient, Inc. All rights reserved.
#
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
#
# Dissemination of this information or reproduction of this material is strictly forbidden unless prior
# written permission is obtained from ThreatQuotient, Inc.
###########################################################################################################


import argparse
import fnmatch
import glob
import imp
import json
import os
import py_compile
import subprocess
import sys
import time

try:
    from termcolor import colored
except Exception:
    print("Module 'termcolor' does not seem to be installed, Please install it. (pip2.7 can be used)")
    exit(1)

try:
    imp.find_module('flake8')
except Exception:
    print("flake8 does not seem to be installed, Please install it. (pip2.7 can be used)")
    exit(1)


def _get_exclude_cmds(app_dir):

    excludes = ["*.swp", "exclude_files.txt", "dont_install", "dont_post_rpm", "deprecated", "*.py", "**/*.py"]

    exclude_file_path = '{0}/exclude_files.txt'.format(app_dir)

    if (os.path.isfile(exclude_file_path)):
        with open(exclude_file_path, 'r') as f:
            excludes.extend([x.strip() for x in f.readlines()])

    exclude_cmd = ' '.join(['--exclude="{}"'.format(x) for x in excludes])
    # print "Exclude command: '{0}'".format(exclude_cmd)

    return exclude_cmd


def _create_app_tarball(app_dir, app_version):

    print(colored("  Creating tarball...", 'cyan'))
    if app_version:
        filename = "{0}-{1}.tgz".format(app_dir, app_version)
    else:
        filename = "{0}.tgz".format(app_dir)
    exclude_cmds = _get_exclude_cmds(app_dir)
    ret_val = os.system('tar {0} -zcf {1} {2}'.format(exclude_cmds, filename, app_dir))

    if (ret_val != 0):
        print(colored("  Failed...", 'red'))
        exit(1)

    print(colored("  ./{0}".format(filename), 'cyan'))
    return True


def _compile_py_files(py_files, exclude_flake):

    error_files = 0
    for py_file in py_files:
        errored_file = False
        print("Compiling: {0}".format(py_file))

        if (exclude_flake is False):
            command = ['flake8', py_file]
            p = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sout, serr = p.communicate()

            if (len(sout) > 0):
                errored_file = True
                print(colored(sout, 'red'))
                if (not args.continue_on_error):
                    print(colored("Exiting...", 'cyan'))
                    exit(1)
            if (len(serr) > 0):
                print(serr)

        if (errored_file is True):
            error_files += 1
        else:
            py_compile.compile(py_file)

    return error_files


def _install_app(app_tarball):

    sys.path.append('/opt/phantom/www/phantom_ui')
    import import_app as importer

    try:
        importer.main(app_tarball, True)
    except Exception as e:
        return False, e.message

    return True, "App Installed"


def _validate_json_file(app_dir, args):

    print(colored('Validating App Json', 'cyan'))

    # Create the glob to the json file
    json_file_glob = './*.json'

    # Check if it exists
    files_matched = glob.glob(json_file_glob)

    if (not files_matched):
        print(colored('App Json file not found.', 'red'))
        return False

    for json_file in files_matched:
        print(colored('  Working on: {0}'.format(json_file), 'cyan'))

        with open(json_file) as f:
            try:
                app_json = json.load(f)
            except Exception as e:
                print(colored('   Unable to load due to exception: "{0}"'.format(str(e)), 'cyan'))
                continue

            if (not app_json.get('appid')):
                print(colored('   Did not find appid in json, ingoring.', 'cyan'))
                continue

            print(colored('    Looks good', 'cyan'))
            return True

    return False


def main(args):

    if ((not args.install_app) and (not args.single_pyfile) and (not args.create_tarball)):
        print(colored((
            'Nothing to do, please specify one of the following actions:\n'
            '* install_app\n* single_pyfile\n* create_tarball', 'red'
        )))
        argparser.print_help()
        exit(1)

    app_dir = "./threatq_app"
    if (args.create_tarball):
        _create_app_tarball(app_dir, args.app_version)
        print(colored("Done...", 'cyan'))
        exit(0)

    error_files = 0

    if (args.single_pyfile is not None):
        py_files = glob.glob(args.single_pyfile)
        error_files += _compile_py_files(py_files, args.exclude_flake)
        # ignore everything else
        exit(0)

    # make a list of files that are to be ignored
    ignore_fnames = []

    if (args.ignore_file):
        if (os.path.isfile(args.ignore_file)):
            with open(args.ignore_file) as f:
                ignore_fnames = f.readlines()
                # clean up the list a bit
                ignore_fnames = [x.strip() for x in ignore_fnames if len(x.strip()) > 0]
                if (ignore_fnames):
                    print(colored('Will be ignoring: {0}'.format(', '.join(ignore_fnames)), 'cyan'))

    py_files = glob.glob("./*.py")
    if (ignore_fnames):
        # remove the files that we are supposed to ignore
        py_files = [x for x in py_files if not [y for y in ignore_fnames if fnmatch.fnmatch(x, y)]]
    error_files = _compile_py_files(py_files, args.exclude_flake)

    is_valid = _validate_json_file(app_dir, args)
    if (not is_valid):
        print(colored("Unable to find a valid app json, Exiting...", 'red'))
        exit(1)

    if (error_files > 0):
        exit(1)

    if (args.install_app is True):

        print(colored("Installing app...", 'cyan'))
        time.sleep(2)

        _create_app_tarball(app_dir, args.app_version)

        os.chdir('./')
        print(colored("  Calling installer...", 'cyan'))
        ret_val, err_string = _install_app("{0}.tgz".format(app_dir))

        if (ret_val is False):
            print(colored("  Error: {0}".format(err_string), 'red'))
            exit(1)

        os.chdir('./{0}'.format(app_dir))
        exit(0)

    print(colored("Done...", 'green'))


if __name__ == '__main__':
    args = None
    argparser = argparse.ArgumentParser()

    arggroup = argparser.add_mutually_exclusive_group(required=True)
    arggroup.add_argument('-s', '--single_pyfile', help='Compile a Single python file and exit')
    arggroup.add_argument(
        '-i', '--install_app', help='install app after compilation', action='store_true', default=False)
    arggroup.add_argument(
        '-t', '--create_tarball', help='Only create the app tarball and exit', action='store_true', default=False)
    argparser.add_argument('-v', '--app_version', help='App Version', default='2.0.0')
    argparser.add_argument('-a', '--app_dir', help='app directory', default='./')
    argparser.add_argument('-d', '--exclude_flake', help='Dont run flake', action='store_true', default=False)
    argparser.add_argument('-e', '--continue_on_error', help='Stop on error', action='store_true', default=False)
    argparser.add_argument('-g', '--ignore_file', help=(
        'files that contains the list of files to ignore, by default it is .compile_app.ignore'),
        default='./.compile_app.ignore')
    args = argparser.parse_args()

    main(args)
