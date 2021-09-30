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

import os
import random

from . import exceptions
from .bulk_object import ThreatQSource
from .tqobject import ThreatQuotientObject


class File(ThreatQuotientObject):
    """ Represents an Adversary in the ThreatQ system """

    def __init__(self, tq):
        self.tq = tq
        self.path = None
        self.name = None
        self.fid = None
        self.ftype = None
        self.locked = False
        self.tags = []
        self.title = None
        self.content = None

    @staticmethod
    def _get_base_endpoint_name():
        return 'attachments'

    def _id(self):
        return self.fid

    def _set_id(self, value):
        self.fid = value

    def fill_from_api_response(self, api_response):
        self.fid = api_response['id']
        self.name = api_response['name']
        self.description = None

    def set_content(self, content):
        self.content = content

    def _to_dict(self):
        raise NotImplementedError("File uploads don't serialize well")

    def _file_url(self, fid):
        """ Get a link to the file suitable for presentation to an
        end user

        :param fid: File ID
        :type fid: int
        """
        base = self.tq.threatq_host + '/files/'
        return base + str(fid) + '/details'

    def find(self, md5=None):
        """
        Searches for an attachment (allows searching by hash)
        """

        params = {}
        if md5:
            params['hash'] = md5
        else:
            params['name'] = self.name

        try:
            res = self.tq.get('/api/attachments', params=params)
            if res and res.get('data') and res['data']:
                self.fill_from_api_response(res['data'][0])
        except Exception:
            pass

    def parse_and_import(self, source, status='Review', parser='Generic Text', normalize=True, delete=False):
        """ Parse the file and import the indicators using a parser

        :param str source: Source to use for each Indicator
        :param str status: Indicator status
        :param str parser: What parser to use
        :param bool normalize: Normalize URL indicators
        :param bool delete: Delete the file/attachment after import

        :returns: Import message
        """

        parser_id = self.tq.getparseridbyname(parser)
        status_id = self.tq.getstatusidbyname(status)

        if source and isinstance(source, ThreatQSource):
            source = source.to_dict()

        if not parser_id:
            raise ValueError('Invalid parser')

        if not status_id:
            raise ValueError('{} is not a valid status'.format(status))

        res = self.tq.post(
            '/api/imports',
            data={
                'attachment_id': self.fid,
                'normalize': normalize,
                'content_type_id': parser_id
            })

        r = res.get('data')
        if not r or 'id' not in r:
            raise exceptions.UploadFailedError(res)

        iid = r['id']
        self.tq.put(
            '/api/imports/%i' % iid,
            data={
                'delete_after_import': delete,
                'import_source': source,
                'indicator_global_status': status_id
            })
        return self.tq.get('/api/imports/%i/commit' % iid)

    def upload(self, sources=None):
        """ Upload ourself to threatq """

        # Backwards compatible with < v1.4
        if self.path is None:
            self.path = self.name

        if self.name is None:
            raise ValueError("Cannot upload without a file name")

        if self.ftype is None:
            raise ValueError("Cannot upload without a file type")

        data = {}
        sources = ThreatQSource.make_source_list(sources)
        if sources:
            data['sources'] = [src.to_dict() for src in sources if src]

        fname = os.path.basename(self.name)
        new_filename = "%i-%s" % (
            random.randint(1, 100000),
            fname.replace('.', ''))

        content = self.content
        if not content:
            inf = open(self.path, 'rb')
            content = inf.read()
            inf.close()

        res = self.tq.post(
            '/api/attachments/upload',
            data={
                'resumableIdentifier': new_filename,
                'resumableRelativePath': fname,
                'resumableTotalChunks': 1,
                'resumableFilename': fname,
            },
            files={
                'file': ('blob', content, 'application/octet-stream')
            })

        data['name'] = fname
        if self.title:
            data['title'] = self.title
        data['type'] = self.ftype
        data['malware_locked'] = self.locked

        res = self.tq.post('/api/attachments', data=data)

        r = res.get('data')
        if not r or 'id' not in r:
            raise exceptions.UploadFailedError(res)

        for t in self.tags:
            res = self.tq.post('/api/attachments/%i/tags' % r['id'], data={'name': t})

        self.fid = r['id']
        return self

    def get_related_indicators(self):
        """ Get the indicators related to this Adversary

        .. deprecated:: 1.01
            Use :py:meth:`threatqsdk.tqobject.get_related_objects` instead
        """
        # imported here to prevent circular deps
        from fn_threatq.threatqsdk.indicator import Indicator
        return self.get_related_objects(Indicator)

    def url(self):
        """ Get a link to the file suitable for presentation to an
        end user

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the indicator has yet to be created
        """
        if not self.fid:
            raise exceptions.NotCreatedError(object=self)

        return self._file_url(self.fid)
