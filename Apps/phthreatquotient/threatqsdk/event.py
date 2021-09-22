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

from threatqsdk import exceptions
from threatqsdk.bulk_object import ThreatQSource
from threatqsdk.tqobject import ThreatQuotientObject


class Event(ThreatQuotientObject):
    """ Represents an event

    :param tq: ThreatQuotient connection
    :type tq: ~threatqsdk.Threatq
    """

    def __init__(self, tq):
        if not tq:
            raise ValueError("Must provide a Threatq instance")

        self.tq = tq
        self.desc = ''
        self.title = ''
        self.typename = None
        self.happened_at = None
        self.eid = None

        # Spearphish
        self.text = ""
        self.statusname = ""

    def set_desc(self, desc):
        """ Set our description
        This change is not automatically committed to ThreatQuotient

        :param str desc: The description
        """
        self.desc = desc

    def set_text(self, text):
        """ Set our Spearphish text
        This change is not automatically committed to ThreatQuotient

        :param str desc: The description
        """
        self.text = text

    def set_status(self, status):
        """ Set our Spearphish text
        This change is not automatically committed to ThreatQuotient

        :param str desc: The description
        """
        self.statusname = status

    def set_title(self, title):
        """ Set our title
        This change is not automatically committed to ThreatQuotient

        :param str title: The description
        """
        self.title = title

    def set_date(self, date):
        """ Set the date at which this event occurred.
        This change is not automatically committed to ThreatQuotient

        :param str date: Date at which this event occurred, in the format
            ``%Y-%m-%d %H:%M:%S``
        """
        self.happened_at = date

    def set_type(self, typename):
        """ Set the type of the event
        This change is not automatically committed to ThreatQuotient

        :param str typename: Human-readable type name
        """
        # self.typeid = self.tq.geteventtypeidbyname(typename)
        self.typename = typename

    @staticmethod
    def _get_base_endpoint_name():
        return 'events'

    def _id(self):
        return self.eid

    def _set_id(self, value):
        self.eid = value

    def _event_url(self, eid):
        """ Get a link to the event suitable for presentation to an
        end user

        :param eid: Event ID
        :type eid: int
        """
        base = self.tq.threatq_host + '/events/'
        return base + str(eid) + '/details'

    def fill_from_api_response(self, api_response):
        """ Fill ourselves in based on an API response """
        self.eid = api_response['id']
        if 'title' in api_response:
            self.title = api_response['title']
        else:
            self.title = ''
        self.description = api_response['description']
        self.happened_at = api_response['happened_at']

    def _to_dict(self):
        # Ensure title is set
        if not self.title:
            raise ValueError("Cannot upload without a title")
        if not self.typename:
            raise ValueError("Type name must be set before upload")
        if not self.happened_at:
            raise ValueError("Occurance date must be set before upload")
        data = {
            'type': self.typename,
            'type_id': self.tq.geteventtypeidbyname(self.typename),
            'description': self.desc,
            'title': self.title,
            'happened_at': self.validate_date(str(self.happened_at)),
            'text': self.text
        }
        return data

    def add_spearphish(self, text):
        if not text:
            raise ValueError("Must provide spearphish text.")

        data = {'value': text}

        self.tq.post("/api/events/%i/spearphish" % self.eid, data)

    def upload(self, sources=None):
        """
        This is a copy of the upload function from the Event.py file in the SDK.
        The problem with the version in the SDK, is there is bug when uploading a Spearphish event.
        This copy of it fixes the issue

        What it fixes:
          - Issue with getting the ID out of a spearphish import
          - Issue with setting the description for a spearphish event
          - Implements new "ThreatQSource" object
        """

        data = self._to_dict()
        sources = ThreatQSource.make_source_list(sources)
        if sources:
            data['sources'] = [src.to_dict() for src in sources if src]

        if self.typename == "Spearphish":
            if not self.text or not self.statusname or not self.title:
                raise ValueError(
                    "Must provide spearphish text, default Indicator Status, and Title (Subject).")

            result = self.tq.post("/api/events/import", data)
            if not result or 'data' not in result or 'id' not in result['data']:
                raise exceptions.UploadFailedError(result)

            eid = result['data']['id']
            data = {
                "indicator_status_id": self.tq.getstatusidbyname(self.statusname),
                "globals": {
                    "indicators": {"attributes": []},
                    "relations": {
                        "adversaries": [], "events": [], "attachments": [], "indicators": [], "signatures": []}
                }}
            result = self.tq.put("/api/events/import/%i?with=attachments,events" % eid, data)
            if not result or 'data' not in result or 'id' not in result['data']:
                raise exceptions.UploadFailedError(result)

            result = self.tq.get("/api/events/import/%i?with=attachments,events" % eid)
            if not result or 'data' not in result or 'id' not in result['data']:
                raise exceptions.UploadFailedError(result)

            otherid = result["data"]["events"][0]["id"]
            data = {"title": self.title,
                    "happened_at": self.happened_at, "description": self.desc}
            result = self.tq.put(
                'api/events/import/%i/events/%i' % (eid, otherid), data=data)
            if not result or 'data' not in result or 'id' not in result['data']:
                raise exceptions.UploadFailedError(result)

            result = self.tq.get('/api/events/import/%i/commit' % eid)
            if not result or 'data' not in result:
                raise exceptions.UploadFailedError(result)

            if not result['data'].get('events', []) or not result['data']['events'][0].get('id'):
                raise exceptions.UploadFailedError('No event ID found in response')

            self.eid = result['data']['events'][0]['id']
        else:
            result = self.tq.post("/api/events", data)
            if not result or 'data' not in result or 'id' not in result['data']:
                raise exceptions.UploadFailedError(result)

            self.eid = result['data']['id']

        return self.eid

    def relate_indicator(self, ind):
        """ Relate an indicator to ourselves

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the event has yet to be created
        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the indicator has yet to be created
        :raises: :py:class:`~threatqsdk.exceptions.ActionFailedError` if
                The relation is not added successfully

        .. deprecated:: 1.00
            Use :py:meth:`threatqsdk.tqobject.ThreatQuotientObject.relate_object` instead.
        """
        return self.relate_object(ind)

    def get_related_indicators(self):
        """ Get all the indicators related to this event

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the event has yet to be created

        .. deprecated:: 1.01
            Use :py:meth:`~threatqsdk.tqobject.ThreatQuotientObject.get_related_objects` instead
        """
        from threatqsdk.indicator import Indicator
        return self.get_related_objects(Indicator)

    def url(self):
        """ Get a link to the event suitable for presentation to an
        end user

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the indicator has yet to be created
        """
        if not self.eid:
            raise exceptions.NotCreatedError(object=self)

        return self._event_url(self.eid)
