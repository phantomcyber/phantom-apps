# File: app/bg.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

"""
(C) Copyright Bitglass Inc. 2021. All Rights Reserved.
Author: eng@bitglass.com
"""

import sys
import os
import json

from six import PY2
from six.moves import socketserver


if PY2:
    import urllib2 as urllib
    from urllib2 import HTTPError
else:
    from urllib.error import HTTPError
    import urllib.request as urllib
    # TODO ?? For some weird reason, the requests session is closed on first reference
    # if imported here globally (to move the failure earlier)
    # import requests_oauth2


import base64

import time
import copy
from threading import Thread, Condition
from datetime import datetime, timedelta
import logging
# from threading import get_ident


import app.env
from app.config import byteify, open_atomic, startConf
import app.configForward
import app.logevent


logger = None
conf = None
lastLogFile = None


def setLoggingLevel(logger, conf=startConf):
    """ Set/override the logging level from the config
    """
    numeric_level = getattr(logging, conf.logging_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % conf.logging_level)
    logger.setLevel(numeric_level)
    for hdlr in logger.handlers:
        hdlr.setLevel(numeric_level)
    logger.info('~~~ LOGGING ENABLED AT LEVEL: %s ~~~' % conf.logging_level)
    return numeric_level


def setLogging(logger=None, defaultlogfolder=startConf._folder):
    """ Set logging options for a script (vs. a Flask app)
    """
    app.env.UpdateLoggingPath(defaultlogfolder)
    filename = app.env.loggingpath

    # Grab the logger object
    addStderr = False
    if logger is None:
        addStderr = True
        logger = logging.getLogger('bitglass_' + __name__)

    # This enables werkzeug logging
    # logging.basicConfig(filename=, level=)

    # Set default logging level from config
    numeric_level = setLoggingLevel(logger)

    # Log to bitglass.log file
    fh = logging.FileHandler(filename=filename)
    fh.setLevel(numeric_level)

    # if 'debug' in startConf.logging_level.lower():
    #     fh.setLevel(logging.DEBUG)
    #     logging.basicConfig(filename=filename, level=logging.DEBUG)
    # elif 'info' in startConf.logging_level.lower():
    #     fh.setLevel(logging.INFO)
    #     logging.basicConfig(filename=filename, level=logging.INFO)
    # else:
    #     fh.setLevel(logging.WARNING)
    #     logging.basicConfig(filename=filename, level=logging.WARNING)

    formatter = logging.Formatter(
        # TODO Adjust format adding time, thread and [] around thread and level
        """%(levelname)s in %(module)s [%(pathname)s:%(lineno)d]:\n%(message)s"""
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    if addStderr:
        # Log to STDERROR as well since it's run as a cli script
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(numeric_level)

        # The errors are loaded into SIEMs like Splunk etc. so careful changing the format
        formatter = logging.Formatter(
            '%(asctime)s,Level=%(levelname)s, ErrorMessage=%(message)s',
            '%m/%d/%Y %H:%M:%S')
        sh.setFormatter(formatter)
        logger.addHandler(sh)

    return logger


# Not started as a script directly or from another module so it's a Flask app (either QRadar or not)
# Use Flask logging facilities (plus qpylib.log optionally) when running as a Flask app.
# This wraps the logging to have the standard pythonic logging interface to use everywhere.
if __name__ != '__main__' and __name__ != 'app.bg':

    from app import log, set_log_level

    # TODO Remove and just use Flask app.logger when the QRadar concern is gone
    # Wraps either QRadar or Flask logging, same interface as the standard logging so it can be easily switched
    class Logger:
        def debug(self, msg):
            log(msg, level='debug')

        def info(self, msg):
            log(msg, level='info')

        def warning(self, msg):
            log(msg, level='warn')

        def error(self, msg):
            log(msg, level='error')

        def nop(self, msg):
            pass
    logger = Logger()
    if 'error' in startConf.logging_level.lower():
        set_log_level('error')
        logger.debug = logger.nop
        logger.info = logger.nop
        logger.warning = logger.nop
    elif 'warn' in startConf.logging_level.lower():
        set_log_level('warn')
        logger.debug = logger.nop
        logger.info = logger.nop
    elif 'info' in startConf.logging_level.lower():
        set_log_level('info')
        logger.info = logger.nop
    else:
        pass


def ingestLogEvent(ctx, d, address, logTime):
    if ctx and ctx.ctx is not None:
        ctx.ctx.bgPushLogEvent(d, address, logTime)

    # TODO Prevent recursion sending to itself with syslog socket
    return app.logevent.pushLog(d, address, logTime)


def flushLogEvents(ctx):
    if ctx and ctx.ctx is not None:
        ctx.ctx.bgFlushLogEvents()


def Initialize(ctx, datapath=app.env.datapath, skipArgs=False, _logger=None, _conf=None):
    global logger
    global conf
    global lastLogFile

    # Monkey patch env.datapath first with the value from the command line to read bg json configs
    updatepath = False
    if datapath:
        updatepath = app.env.UpdateDataPath(datapath)

    if not logger:
        if not _logger:
            logger = setLogging(None, datapath)
            logger.info('~~~ Running in CLI mode ~~~')

    if not datapath:
        # Put in the same directory as the logging file (the latter would be well-defined, without uuids)
        datapath = os.path.split(app.env.loggingpath)[0] + os.sep
        updatepath = app.env.UpdateDataPath(datapath)
        if updatepath:
            conf = None

    if not conf or updatepath:
        if not _conf:
            conf = app.configForward.ConfigForward()
            # Be sure to update the logging level once the config is loaded
            setLoggingLevel(logger, conf)

            if not skipArgs or conf._isEnabled('debug'):
                # Parse and apply command line options. Always process for a local dev run ('debug'), it's compatible
                conf._applyOptionsOnce()
        else:
            conf = _conf

    # Override the configuration
    if ctx and ctx.ctx is not None:
        # Override the config settings and disable daemon mode for explicit cli context
        ctx.ctx.bgLoadConfig(conf)
        conf._isDaemon = False
    conf._calculateOptions()

    if not lastLogFile or updatepath:
        cnf = _conf if _conf else conf

        # For Splunk app upgrade, manually 'cp lastlog.json ../local/' before upgrading to ingest incrementally
        # This is because it was saved in default/ in the previous version 1.0.8 and default/ is yanked during upgrade
        folder = cnf._folder
        if (os.path.sep + 'default') in cnf._folder:
            folder = os.path.join(folder, '..', 'local', '')

        lastLogFile = LastLog(os.path.join(folder, 'lastlog'))

    return conf


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    kwargs = None
    callback = None

    @classmethod
    def start(cls, callback, host, port=514, poll_interval=0.5, **kwargs):
        cls.kwargs = kwargs
        cls.callback = callback
        # TODO Test exception propagation to the main thread (due to a bad host?), may need handling
        try:
            server = socketserver.UDPServer((host, port), cls)
            server.serve_forever(poll_interval=poll_interval)
        except (IOError, SystemExit):
            raise
        except KeyboardInterrupt:
            logger.info("Crtl+C Pressed. Shutting down.")

    def handle(self):
        # logger = self.kwargs['logger']
        data = bytes.decode(self.request[0].strip())

        # Strip the string and convert to json
        try:
            conf = self.kwargs['conf']
            condition = self.kwargs['condition']

            s = u'%s :{' % conf.customer.lower()
            start = data.find(s) + len(s) - 1
            end = data.rfind(u'}') + 1
            logData = json.loads(u'{"response":{"data":[' + data[start:end] + u']}}')

            with conf._lock(condition, notify=False):
                transferLogs(None, log_types=None, logData=logData, npt=None, **self.kwargs)

        except Exception as ex:
            logger.warning('{0}\n - Discarded bad event message in syslog stream:\n"{1}"\n- from sender {2}'.format(
                str(ex),
                data,
                self.client_address[0])
            )
            return


TIME_FORMAT_URL = '%Y-%m-%dT%H:%M:%SZ'
TIME_FORMAT_LOG = '%d %b %Y %H:%M:%S'


def strptime(s):
    # For more reliable (but slower) datetime parsing (non-English locales etc.) use:
    # pip install python-dateutil
    # from dateutil import parser
    # parser.parse("Aug 28 1999 12:00AM")  # datetime.datetime(1999, 8, 28, 0, 0)
    # '06 Nov 2018 08:15:10'

    d = datetime.strptime(s, TIME_FORMAT_LOG)

    return d


class LastLog:
    def __init__(self, fname, shared=None, logtype=''):
        self.fname = '{0}-{1}.json'.format(fname, logtype) if shared else '{0}.json'.format(fname)
        self.shared = shared
        self.log = {}
        self.logtype = logtype
        self.subLogs = {}
        try:
            with open(self.fname, 'r') as f:
                self.log = byteify(json.load(f))

                if self.shared is None:
                    # This is a shared (old) file. Convert to the new format if needed
                    for lt in app.configForward.log_types:
                        if self.get(logtype=lt):
                            if isinstance(self.log[lt], str):
                                self.log[lt] = json.loads(self.log[lt])
        except Exception as ex:
            logger.info('{0}\n - Last log file {1} not found'.format(str(ex), self.fname))
            lastLog = {}
            if self.shared:
                lastLog[logtype] = self.shared.log[logtype]
            else:
                for lt in app.configForward.log_types:
                    lastLog[lt] = {}
            self.log = lastLog

        # Create children one per log type unless sharing the same file for all
        if self.shared is None and logtype != 'share':
            for lt in app.configForward.log_types:
                self.subLogs[lt] = LastLog(fname, self, lt)

    def dump(self):
        try:
            with open_atomic(self.fname, 'w') as f:
                json.dump(self.log, f, indent=4, sort_keys=True)
        except Exception as ex:
            logger.error('Could not save last log event across app sessions: %s' % ex)

    def get(self, field=None, logtype=None):
        if logtype is None:
            logtype = self.logtype
        else:
            if logtype in self.subLogs:
                return self.subLogs[logtype].get(field)

        if field:
            ll = self.log[logtype]
            # Handle the old format to be forward compatible across upgrade
            res = json.loads(ll) if isinstance(ll, str) else ll
            return res[field] if field in res else None

        return True if logtype in self.log and self.log[logtype] != {} else False

    def update(self, ll, logtype=None):
        if logtype is None:
            logtype = self.logtype
        else:
            if logtype in self.subLogs:
                return self.subLogs[logtype].update(ll)

        if ll:
            # Add extra fields for diagnostics. Should not lag event log timestamp more than by the API polling interval
            ll[u'_ingestedtime'] = datetime.utcnow().strftime(TIME_FORMAT_LOG)
            self.log[logtype] = ll
            self.dump()
        else:
            # This is a successful request with empty (exhausted) data so use the last one but handle the (corner) case
            # of error logged inbetween (coinsiding with app relaunch) by clearing the error entries if there are any
            if self.get(logtype=logtype):
                if self.get('_failedtime', logtype):
                    del self.log[logtype]['_failedtime']
                if self.get('_errormessage', logtype):
                    del self.log[logtype]['_errormessage']

        return json.dumps(self.log[logtype])

    def updateError(self, errormsg, logtype=None):
        if logtype is None:
            logtype = self.logtype
        else:
            if logtype in self.subLogs:
                return self.subLogs[logtype].updateError(errormsg)

        if not self.get(logtype=logtype):
            self.log[logtype] = {}

        # Update with failure timestamp and message, keep last ingested success timestamp
        self.log[logtype]['_failedtime'] = datetime.utcnow().strftime(TIME_FORMAT_LOG)
        self.log[logtype]['_errormessage'] = str(errormsg)
        self.dump()


def getAPIToken(logData, conf, logType):
    if not conf.useNextPageToken:
        return None

    try:
        token = logData['nextpagetoken']
        d = json.loads(base64.b64decode(token))
    except Exception as ex:
        logger.warning('Invalid token returned: %s %s' % (token, ex))
        return None

    # TODO Swap the condition for compatibility if the new logtypes introduced use the same fields as in swqweb*
    if logType != u'swgweb' and logType != u'swgwebdlp':
        # Older log types
        if 'log_id' not in d:
            logger.warning('No "log_id" encoded in returned token: %s' % token)
            return None

        if 'datetime' not in d:
            logger.warning('No "datetime" encoded in returned token: %s' % token)
            return None
    else:
        # Newer log types
        if 'start_time' not in d:
            logger.warning('No "start_time" encoded in returned token: %s' % token)
            return None

        if 'end_time' not in d:
            logger.warning('No "end_time" encoded in returned token: %s' % token)
            return None

        if 'page' not in d:
            logger.warning('No "page" encoded in returned token: %s' % token)
            return None

    return token


SKIPPED_REQUEST_ERROR = 'UNAUTHORiZED'


def RestParamsLogs(_, host, api_ver, logType, npt, dtime):
    url = ('https://portal.' + host) if host else ''
    endpoint = '/api/bitglassapi/logs'

    # Adjust the version upwards for new log types as necessary
    if logType == u'swgweb' or logType == u'swgwebdlp':
        # TODO Make sure it's lower before overriding
        api_ver = '1.1.0'

    if npt is None:
        urlTime = dtime.strftime(TIME_FORMAT_URL)
        dataParams = '/?cv={0}&responseformat=json&type={1}&startdate={2}'.format(api_ver, str(logType), urlTime)
    else:
        dataParams = '/?cv={0}&responseformat=json&type={1}&nextpagetoken={2}'.format(api_ver, str(logType), npt)

    return (url, endpoint, dataParams)


def RestParamsConfig(_, host, api_ver, type_, action):
    url = ('https://portal.' + host) if host else ''

    # This is a POST, version is not a proper param, unlike in logs (?? for some reason)
    endpoint = '/api/bitglassapi/config/v{0}/?type={1}&action={2}'.format(api_ver, type_, action)
    return (url, endpoint)


def restCall(_,
             url, endpoint, dataParams,
             auth_token,
             proxies=None,
             method=None,
             verify=True,
             username=None,
             password=None):
    if dataParams is None:
        dataParams = ''

    if auth_token is None or auth_token == '':
        auth_type = 'Basic'

        # Must have creds supplied for basic
        if (username is None or username == '' or
                password is None or password == ''):
            # Emulate an http error instead of calling with empty password (when the form initially loads)
            # to avoid counting against API count quota
            raise HTTPError(url + endpoint, 401, SKIPPED_REQUEST_ERROR, {}, None)

        if PY2:
            auth_token = base64.b64encode(username + ':' + password)
        else:
            auth_token = base64.b64encode((username + ':' + password).encode('utf-8'))
            auth_token = auth_token.decode('utf-8')
    else:
        auth_type = 'Bearer'

    try:
        # This check is done earlier for PY3 to fail before run time
        # if PY2:
        import requests_oauth2
        haveOAuth2 = True
    except ImportError as ex:
        logger.warning('{0}\n - Defaulting to the legacy urllib module'.format(str(ex)))
        haveOAuth2 = False

    # Use requests by default if available
    # Note: requests-oauth2 is not installed on QRadar by default
    r = None
    if (method is None or method == 'requests') and haveOAuth2:
        import requests
        from requests.auth import HTTPBasicAuth

        # The authentication header is added below
        headers = {'Content-Type': 'application/json'}

        d = {}
        with requests.Session() as s:
            if auth_type == 'Basic':
                s.auth = HTTPBasicAuth(username, password)
            else:
                s.auth = requests_oauth2.OAuth2BearerToken(auth_token)

            if proxies is not None and len(proxies) > 0:
                s.proxies = proxies

            if isinstance(dataParams, dict):
                # Assume json
                r = s.post(url + endpoint, headers=headers, verify=verify, json=dataParams)
            else:
                r = s.get(url + endpoint + dataParams, headers=headers, verify=verify)

            r.raise_for_status()
            d = r.json()
    else:
        headers = {'Content-Type': 'application/json', 'Authorization': auth_type + ' ' + auth_token}

        if isinstance(dataParams, dict):
            # Assume json
            req = urllib.Request(url + endpoint, json.dumps(dataParams), headers, unverifiable=not verify)
            if PY2:
                req = urllib.Request(url + endpoint, json.dumps(dataParams), headers, unverifiable=not verify)
            else:
                req = urllib.Request(url + endpoint, json.dumps(dataParams).encode('utf-8'), headers, unverifiable=not verify)
        else:
            req = urllib.Request(url + endpoint + dataParams, None, headers, unverifiable=not verify)

        if proxies is not None and len(proxies) > 0:
            # TODO ?? Do it once at init time unless this option ends up exposed in the UI
            opener = urllib.build_opener(urllib.ProxyHandler(proxies))
            urllib.install_opener(opener)

        # TODO Security scan medium. Remove urllib fallback use when QRadar moves to Python 3
        resp = urllib.urlopen(req)  # nosec: <explanation>No custom schemes allowed as the url is validated to be https</explanation>
        respTxt = resp.read()
        d = json.loads(respTxt)

    return d, r


def RestCall(_, endpoint, dataParams):
    return restCall(
        _,
        'https://portal.' + conf.host,
        endpoint,
        dataParams,
        conf._auth_token.pswd,
        conf.proxies,
        conf.method,
        conf.verify,
        conf._username,
        conf._password.pswd
    )


def drainLogEvents(ctx, dtime, conf, logType, logData=None, nextPageToken=None):

    logTime = dtime

    status = conf.status[logType]
    r = None

    isSyslog = (logData is not None)

    try:
        i = 0
        drained = False
        while not drained:
            if isSyslog:
                drained = True
            else:
                if i > 0:
                    # This is a crude way to control max event rate for Splunk / QRadar etc. as required
                    # without adding another thread and a queue which is a design over-kill
                    time.sleep(1.0 / conf._max_request_rate)

                if conf.host == conf._default.host:
                    # Avoid the overhead of invalid request even if there is no traffic generated
                    raise HTTPError(conf.host, -2, SKIPPED_REQUEST_ERROR, {}, None)

                # TODO If there is a hint from API that all data is drained can save the
                # split second sleep and the extra request
                url, endpoint, dataParams = RestParamsLogs(None,
                                                           conf.host,
                                                           conf.api_ver,
                                                           logType,
                                                           nextPageToken,
                                                           logTime + timedelta(seconds=1))
                logData, r = restCall(None,
                                      url, endpoint, dataParams,
                                      conf._auth_token.pswd,
                                      conf.proxies,
                                      conf.method,
                                      conf.verify,
                                      conf._username,
                                      conf._password.pswd)
                i = i + 1

            lastLog = None
            nextPageToken = getAPIToken(logData, conf, logType)

            # Querying API data by 'time' field (not using nextpagetoken) is broken for 1.1.0 log types
            # swgweb and swgwebdlp causing overlaps. So disable the fallback path for them (no nextpagetoken)
            # No fix planned, so this workaround is a keeper
            # TODO Swap the condition for compatibility when new logtypes get introduced7
            isNewLogType = logType == u'swgweb' or logType == u'swgwebdlp'
            if nextPageToken is None and isNewLogType:
                raise ValueError('Invalid page token for swgweb* log types is not supported')

            data = logData['response']['data']
            if len(data) == 0:
                drained = True
            else:
                # Cover the case of reverse chronological order (in case of not reversing it back)
                lastLog = data[0]

                for d in data[::-1 if strptime(data[0]['time']) > strptime(data[-1]['time']) else 1]:
                    # In some new log types like swgweb the data are sorted from recent to older
                    # So let's not assume chronological order to be on the safe side..
                    tm = strptime(d['time'])

                    # Inject logtype field, it's needed by QRadar Event ID definition (defined in DSM editor)
                    if u'logtype' not in d:
                        d[u'logtype'] = logType

                    # NOTE Use logTime if QRadar has problems with decreasing time (as in swgweb and swgwebdlp)
                    ingestLogEvent(ctx, d, conf._syslogDest, tm)

                    if nextPageToken is None:
                        d[u'nextpagetoken'] = u''
                    else:
                        d[u'nextpagetoken'] = nextPageToken

                    if (tm > logTime or
                            # This is to avoid the possible +1 sec skipping data problem (if no npt)
                            not isNewLogType):
                        logTime = tm
                        lastLog = d
                        # json.dumps(d, sort_keys=False, indent=4, separators = (',', ': '))

            status.cntSuccess = status.cntSuccess + 1
            status.lastMsg = 'ok'
            status.lastLog = lastLogFile.update(lastLog, logType)

            flushLogEvents(ctx)

    except Exception as ex:
        msg = 'Polling: failed to fetch log event data "%s": %s' % (str(logType), ex)
        if SKIPPED_REQUEST_ERROR in msg:
            # No valid settings have been set yet so avoid polluting the log. IMO this is still useful for debugging
            # logger.debug(msg)
            pass
        else:
            logger.error(msg)
            r = ex
            lastLogFile.updateError(r, logType)

        status.cntError = status.cntError + 1
        status.lastMsg = str(ex)
        status.lastLog = ''

    # NOTE  Last successful result has empty data now (drained), instead, could merge all data and return
    #       making it optional if ingestLogEvent is not set.. Without it, attaching data to result is rather useless
    status.lastRes = r
    status.lastTime = logTime

    conf.status['last'] = status

    return logTime


def transferLogs(ctx, conf, condition, dtime, log_types=None, logData=None, npt=None):
    myConf = conf._deepcopy()
    condition.release()

    if not log_types:
        log_types = myConf.log_types

    logTime = {}
    if logData is None:
        for log_type in log_types:
            logTime[log_type] = drainLogEvents(ctx, dtime[log_type], myConf, log_type, logData,
                                                  npt[log_type] if npt is not None else None)
    else:
        # syslog source
        # Make sure nextpagetoken is disabled
        myConf.useNextPageToken = False
        log_type = logData['response']['data'][0]['logtype']
        logTime[log_type] = drainLogEvents(None, dtime[log_type], myConf, log_type, logData=logData)

    condition.acquire()
    myConf.status['updateCount'] = conf.updateCount

    # Load the latest state for the UI
    conf.status = copy.deepcopy(myConf.status)

    # Increment by smallest delta to avoid repeating same entries
    # TODO Using microseconds=1 causes event duplication.. what is the minimum resolution to increment??
    #       without data loss but with guaranteed no repetitions
    if logData is None:
        if conf._isDaemon:
            condition.wait(myConf.log_interval)
        for log_type in log_types:
            dtime[log_type] = logTime[log_type] + timedelta(seconds=1)
    else:
        # syslog source
        dtime[log_type] = logTime[log_type] + timedelta(seconds=1)


def PollLogs(ctx, conf, log_types=None, condition=Condition()):
    """
    Pump BG log events from BG API to QRadar
    """

    time.sleep(10)

    pid = os.getpid()
    # tid = get_ident()
    tid = 0
    logger.info('================================================================')
    logger.info('Polling: start polling log events.. pid=%s, tid=%s' % (pid, tid))
    logger.info('----------------------------------------------------------------')

    # Have to complicate things b/c the API doesn't support combining different log types
    dtime = {}
    npt = {}
    now = datetime.utcnow()
    for log_type in app.configForward.log_types:
        # = datetime.utcnow() + timedelta(days=-1)
        dtime[log_type] = now + timedelta(seconds=-1 * conf.log_initial)
        npt[log_type] = None

        # Adjust to avoid the overlap with a previous run, warn on a possible gap
        # The gap is caused by either: app down time or the log source being disabled in earlier app run
        # was greater than 30 days (default of 'log_initial')
        try:
            if lastLogFile.get(logtype=log_type):
                try:
                    # Could be missing due to the old file format
                    npt[log_type] = lastLogFile.get('nextpagetoken', log_type)
                    if npt[log_type] == '':
                        npt[log_type] = None
                except Exception as ex:
                    npt[log_type] = None

                d = strptime(lastLogFile.get('time', log_type))
                if dtime[log_type] <= d:
                    dtime[log_type] = d
                else:
                    # Important! For a possible gap, discard nextpagetoken loaded from lastlog
                    # NOTE: This still has an extremely remote possibility of data duplication
                    #       (no messages over the gap period is a necessary condition then - unpopulated gap)
                    npt[log_type] = None
                    logger.warning('Possible gap for log type %s from %s to %s' %
                                   (str(log_type),
                                    d.strftime(TIME_FORMAT_LOG),
                                    dtime[log_type].strftime(TIME_FORMAT_LOG))
                                   )
        except Exception as ex:
            # Bad data in lastLogFile? Treat overlap as data corruption so exclude its possibility and warn
            # Discard nextpagetoken loaded from lastlog, also see the comment just above
            npt[log_type] = None
            dtime[log_type] = now
            logger.warning('Possible gap for log type %s to %s due to bad last log data: %s' %
                           (str(log_type),
                            dtime[log_type].strftime(TIME_FORMAT_LOG),
                               ex)
                           )

    # Assume syslog daemon
    # TODO Add a mechanism to stop to switch back to API poll mode, restart is
    # required for now (after manual config edit)
    isSyslog = ('://' not in conf.api_url and
                len(conf.api_url.split(':')) == 2)
    res = None
    if isSyslog:
        host, port = conf.api_url.split(':')
        # TODO: At least verify that sink_url is different to reduce the loop possibility sending back to itself
        SyslogUDPHandler.start(transferLogs,
                               host=int(host),
                               port=int(port),
                               conf=conf,
                               condition=condition,
                               dtime=dtime
                               )
    else:
        with conf._lock(condition, notify=False):
            isDaemon = True
            while isDaemon:
                transferLogs(ctx, conf, condition, dtime, log_types, None, npt)

                # Run only once if not in the daemon mode
                isDaemon = conf._isDaemon

        res = conf.status

    logger.info('Polling: stop polling log events.. pid=%s, tid=%s' % (pid, tid))
    logger.info('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    return res

class bitglassapi:

    Initialize = Initialize

    # TODO Implement OverrideConfig(), it will also validate all settings (the validation is to be moved from UI)

    # Low level (overriding settings params)
    restCall = restCall

    RestParamsLogs = RestParamsLogs
    RestParamsConfig = RestParamsConfig

    RestCall = RestCall

    # Higher level calls relying on serialized data and synchronization
    PollLogs = PollLogs

    def __init__(self, ctx=None):
        if ctx is None:
            # Use default callbacks
            ctx = self

        self.ctx = ctx

    # Default callbacks command mode without explicit context (like Splunk)
    def bgPushLogEvent(self, d, address, logTime):
        # Additional processing for the script
        from app import cli
        cli.pushLog(d, address, logTime)

    def bgFlushLogEvents(self):
        from app import cli
        cli.flushLogs()

    def bgLoadConfig(self, conf):
        from app import cli
        cli.loadConfiguration(conf)


def startWorkerThread(conf, isDaemon=True, bgapi=None):

    Initialize(bgapi, _logger=logger, _conf=conf)

    condition = Condition()
    thread = Thread(target=PollLogs, args=(bgapi, conf, None, condition))

    conf._isDaemon = isDaemon
    thread.start()
    if not isDaemon:
        thread.join()
    return condition


if __name__ == '__main__':

    from app import cli

    Initialize(None)

    # Only for debugging full context cli variants so that can use one debug setting for all
    if conf._isEnabled('debug'):
        cli.main(logger, conf, bitglassapi)

    # Start the worker thread explicitly if main() above didn't exit()
    startWorkerThread(conf, False, bitglassapi())
