# File: app/config.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

"""
(C) Copyright Bitglass Inc. 2021. All Rights Reserved.
Author: eng@bitglass.com
"""

import json
import time
import os
from contextlib import contextmanager
import copy
from datetime import datetime
import re
import optparse
from six import PY2, iteritems, string_types


# HACK Avoid dependency on package app/ so it's monkey-patched from there, for the sake of CLI script
_log = None


def log(msg, level='info'):
    if _log is not None:
        _log(msg, level)


# Need to load json properly
def byteify(inp):
    if isinstance(inp, dict):
        # Can't use dict comprehension in 2.6 (the version on QRadar box as of 7.3)
        # return {byteify(key): byteify(value)
        #         for key, value in inp.iteritems()}
        return dict([(byteify(key), byteify(value)) for key, value in iteritems(inp)])
    elif isinstance(inp, list):
        return [byteify(element) for element in inp]
    elif isinstance(inp, string_types):
        if PY2:
            return inp.encode('utf-8')
        else:
            return inp
    else:
        return inp


# Convert the object to dict for saving to json
def to_dict(obj):
    mod = obj.__class__.__module__
    if mod == 'builtins' or mod == '__builtin__':
        if type(obj).__name__ == 'list':
            return [to_dict(el) for el in obj]
        else:
            return obj
    else:
        # TODO Check for methods and classes to exclude them and get rid of the underscore in their names
        # if PY2:
        # Can't use dict comprehension in 2.6 (the version on QRadar box as of 7.3)
        return dict([(key, to_dict(getattr(obj, key)))
                        for key in dir(obj) if not key.startswith('_') and 'status' not in key])
        # else:
        #     return {key: to_dict(getattr(obj, key))
        #             for key in dir(obj) if not key.startswith('_') and 'status' not in key}


# Thread operation status to report to UI
class Status:
    def __init__(self):
        self.lastRes = None
        self.lastMsg = 'No status'
        self.lastLog = '{}'
        self.lastTime = datetime.utcnow()
        self.cntSuccess = 0
        self.cntError = 0

    def ok(self):
        return self.lastMsg == 'ok'


# Need this hack because this ancient Jinja 2.7.3 version used by QRadar
# doesn't have the simple 'in' built-in test! Not even 'equalto'!!
class Feature:
    def __init__(self, name):
        setattr(self, name, True)

    def __getitem__(self, item):
        return getattr(self, item)


@contextmanager
def tempfile(filepath, mode, suffix=''):
    undersplunk = False
    if undersplunk:
        # For Splunk, the run environment is managed by Splunk so there is no need in temp files to sync writes
        # The cloud certification reports 'file operation outside of the app directory' etc. but this is mistaken
        # To be on the safe side, have the temp file code disabled since it's not needed under Splunk anyways
        yield filepath
        return

    import tempfile as tmp

    ddir = os.path.dirname(filepath)
    tf = tmp.NamedTemporaryFile(dir=ddir, mode=mode, delete=False, suffix=suffix)
    tf.file.close()
    yield tf.name

    try:
        os.remove(tf.name)
    except OSError as e:
        if e.errno == 2:
            pass
        else:
            raise e


@contextmanager
def open_atomic(filepath, mode, **kwargs):
    with tempfile(filepath, mode=mode) as tmppath:
        with open(tmppath, mode=mode, **kwargs) as file:
            yield file
            file.flush()
            os.fsync(file.fileno())
        if tmppath != filepath:
            os.rename(tmppath, filepath)


class Config(object):
    _version = '1.0.9'
    _api_version_min = '1.0.7'
    _api_version_max = '1.1.0'
    _default = None

    _flags = dict(
        logging_level=('-l',
                       'loglevel field, defaults to WARNING, options are: CRITICAL, ERROR, WARNING, INFO, DEBUG'),
    )

    def _genOptions(self):
        p = optparse.OptionParser()
        for k, f in iteritems(self._flags):
            p.add_option(
                f[0],
                '--' + (k if k[0] != '_' else k[1:]),
                dest=k,
                default=getattr(self._default, k),
                help=f[1])
        return p

    def _applyOptionsOnce(self, opts=None):
        # No validation is done on command line options letting it fail wherever..
        # It's not too bad as long as no corrupted data is saved
        # TODO Do validation (borrowing from UI code??).. make sure it's never saved for now
        # HACK Reuse _save method as flag
        if self._save is None:
            return ''
        self._save = None

        if opts is None:
            # Unless need to parse the remaining arguments..
            opts, args = self._genOptions().parse_args()
            if len(args) > 0:
                log('Ignored unknown options "%s"' % str(args), level='warn')
        else:
            args = ''

        # If something bad happens, the config may be half-set but it's OK since it's never saved
        for k, f in iteritems(self._flags):
            p = getattr(opts, k)
            # HACK Check for patterns in help string to additionally parse into list etc.
            if ':]' in f[1]:
                if isinstance(p, str):
                    p = p.split(':')
                p.sort()
            elif ', seconds' in f[1]:
                if isinstance(p, str):
                    p = int(p)
            if 'password' in f[1] or 'token' in f[1]:
                s = getattr(self, k)
                v = getattr(self, k).secret
                d = getattr(self._default, k).secret
            else:
                s = None
                v = getattr(self, k)
                d = getattr(self._default, k)
            if p != v:
                if p == d:
                    log('Ignored override with implicit default of config param "%s" of:\n%s' %
                        (k, str(getattr(self, k))), level='info')
                else:
                    log('Overriding config param %s with:\n%s' % (k, str(p)), level='info')
                    if v != d:
                        log('\t- double override of config param "%s" of:\n%s' %
                            (k, str(getattr(self, k))), level='info')
                    if s is None:
                        setattr(self, k, p)
                    else:
                        s.secret = p

        # TODO Only after validation
        self._calculateOptions()

        return args

    def _getvars(self):
        return vars(self)

    def _load(self, fname):
        if fname is None:
            return

        try:
            with open(fname, 'r') as f:
                d = byteify(json.load(f))
                for key, value in iteritems(d):
                    setattr(self, key, value)
                    # if 'config.json' in fname:
                    #     app.config[key] = value
        except Exception as ex:
            log('Could not load last configuration %s across app sessions: %s' % (fname, ex), level='info')

    def _deepcopy(self):
        session = self._session
        self._session = None
        cp = copy.deepcopy(self)
        self._session = session
        return cp

    def __init__(self, fname=None, session={}):

        # Keep it here (rather than at class ini time) to support monkey patching
        try:
            from app.env import datapath
            self._folder = datapath
        except Exception as ex:
            self._folder = '/store/'

        if fname is None:
            self._fname = None
        else:
            self._fname = os.path.join(self._folder, fname)

        self._isDaemon = True

        # Assume QRadar by default so need not to tweak config.json
        self.featureset = [Feature('qradar')]

        self.logging_level = 'WARNING'

        self.updateCount = 0
        if self._default is None:
            self._default = copy.deepcopy(self)

        self._load(self._fname)

        # Read/override common config properties, read-only - never saved
        # TODO Optimize by reading only once for all config objects
        self._load(os.path.join(self._folder, 'config.json'))

        # NOTE Crashes when gets called before active request available (
        # Copy relevant session data so it's available to any page/form
        # self._session = {}
        # sessionKeys = ['logged_in']
        # for k in sessionKeys:
        #     if k in session:
        #         self._session[k] = session[k]
        self._session = session

    @contextmanager
    def _lock(conf, condition, notify=True):
        if condition is not None:
            condition.acquire()
        yield conf
        if notify:
            conf.updateCount = conf.updateCount + 1
        if condition is not None:
            if notify:
                condition.notify()
            condition.release()
        else:
            if notify:
                conf.status['updateCount'] = conf.updateCount

    def _isEnabled(self, featureName):
        for f in self.featureset:
            if hasattr(f, '__dict__'):
                if featureName in f.__dict__:
                    return True
            else:
                if featureName in f:
                    return True
        return False

    def _save(self):
        if self._fname is None:
            # Nothing to save (just config.json - read-only)
            return

        try:
            d = to_dict(self)
            # Exclude base properties (assumed read-only)
            if type(self).__name__ != 'Config':
                vs = vars(Config())
                for el in list(d.keys()):
                    if el in vs:
                        del d[el]
            # Exclude properties with default values
            for el in list(d.keys()):
                if d[el] == getattr(self._default, el):
                    del d[el]
            if len(d) > 0:
                # Protect against writing from multiple sessions
                with open_atomic(self._fname, 'w') as f:
                    json.dump(d, f, indent=2, sort_keys=True)
        except Exception as ex:
            log('Could not save last configuration %s across app sessions: %s' % (self._fname, ex), level='warn')

    def _waitForStatus(self):
        while self.status['updateCount'] < self.updateCount:
            time.sleep(0.5)

    def _updateAndWaitForStatus(self, condition, rform):
        return False

    def _matchHost(self, h):
        # ^(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))\.|(?:(?:[a-z_-][a-z0-9_-]{0,62})?[a-z0-9]\.)+(?:[a-z]{2,}\.?)?)$
        return re.match(
            r'^(?:'      # FIXED Added ^
            # IP address exclusion
            # private & local networks
            # FIXED: Commented out to allow private and local
                # r'(?!(?:10|127)(?:\.\d{1,3}){3})'
                # r'(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})'
                # r'(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})'
            # IP address dotted notation octets
            # excludes loopback network 0.0.0.0
            # excludes reserved space >= 224.0.0.0
            # excludes network & broadcast addresses
            # (first & last IP address of each class)
            # TODO Figure out if need keeping any of those excluded
            r'(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])'
            r'(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}'
            r'(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))'
            r'\.|'    # FIXED original u"|", this is a trick to match 'localhost' by appending '.'
            # host & domain names, may end with dot
            r'(?:'
            r'(?:'
            # r'[a-z0-9\u00a1-\uffff]'
            # r'[a-z0-9\u00a1-\uffff_-]{0,62}'
            # FIXED original u"[a-z0-9_-]", allowing digits in the first position
            # discards all ip matching before (like disallowing 127.x.x.x)
            r'[a-z_-]'
            r'[a-z0-9_-]{0,62}'
            r')?'
            # r'[a-z0-9\u00a1-\uffff]\.'
            r'[a-z0-9]\.'
            r')+'
            # TLD identifier name, may end with dot
            # r'(?:[a-z\u00a1-\uffff]{2,}\.?)"
            r'(?:[a-z]{2,}\.?)?'     # FIXED Made it optional by appending '?' to support 'localhost'
            r')$',                   # FIXED Added $
            h + '.', re.I)           # FIXED Append '.'


startConf = Config()
