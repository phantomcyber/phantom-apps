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

import logging
import math

from random import randint
from six import string_types
from time import sleep

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

VERSION = '1.1.1'

tlp_map = {
    'red': 1,
    'amber': 2,
    'green': 3,
    'white': 4
}


class ThreatQObject(object):
    """
    Object to encapsulate all object types in ThreatQ
    """

    # Not including Files/Attachments because we can't bulk upload
    object_list = [
        'indicators', 'adversaries', 'events', 'malware',
        'campaign', 'course_of_action', 'exploit_target',
        'identities', 'attack_pattern', 'exploit_target',
        'instrusion_set', 'report', 'ttp', 'vulnerability',
        'tool', 'stix_pattern'
    ]

    def __init__(self, tq, api_name):
        self.tq = tq
        self.api_name = api_name

        # Object metadata
        self.oid = None
        self.value = ''
        self.name = ''
        self.title = ''
        self.description = ''
        self.attributes = []
        self.published_at = None
        self.happened_at = None
        self.comments = []
        self.tlp = None
        self.status_id = None
        self.status = None
        self.type_id = None
        self.type = None
        self.score = None
        self.sources = []

        # Related objects
        self.relationships = {}
        self.metadata = {}

    def _get_base_endpoint_name(self):
        return self.api_name

    def _get_api_endpoint(self):
        return '/api/' + self.api_name + '/' + str(self.oid)

    def _id(self):
        """
        Get the ID of this object within its namespace
        """

        return self.oid

    def _set_id(self, value):
        """
        Set the ID value
        """

        self.oid = value
        return self

    def set_value(self, value):
        """
        Set the value for the custom object
        """

        # Fix any user errors ;)
        if self.api_name == 'adversaries':
            self.name = value
        elif self.api_name == 'events':
            self.title = value
        else:
            self.value = value

    def set_type(self, type_value):
        """
        Set the type for the object
        """

        if isinstance(type_value, int):
            self.type_id = type_value
        else:
            self.type = type_value

    def set_status(self, status):
        """
        Set the status for the object
        """

        if isinstance(status, int):
            self.status_id = status
        else:
            self.status = status

    def set_TLP(self, tlp):
        """
        Set the tlp for the custom object
        """

        self.tlp = tlp

    def set_name(self, name):
        """
        Set the name for the custom object
        """

        self.name = name

    def set_title(self, title):
        """
        Set the title for the custom object
        """

        self.title = title

    def add_source(self, *args, **kwargs):
        """
        Handler for adding sources via old vs. new method
        """

        if len(args) == 1 and isinstance(args[0], string_types):
            self._add_source_quick(args[0], tlp_id=kwargs.get('tlp_id'), tlp=kwargs.get('tlp'))
        elif len(args) == 1 and isinstance(args[0], ThreatQSource):
            self._add_source_object(args[0])
        elif len(args) == 1 and isinstance(args[0], list):
            for i in args[0]:
                self.add_source(i)

    def _add_source_quick(self, name, tlp_id=None, tlp=None):
        """
        Add a source to the object
        """

        if not name:
            return

        src = ThreatQSource(name, tlp=tlp_id or tlp)
        self._add_source_object(src)

    def _add_source_object(self, source):
        """
        Add the source object to the list
        """

        if not source or not source.name:
            return

        self.sources.append(source)

    def add_metadata(self, name, value):
        """
        Add any extra info to the object for tracking
        """

        self.metadata[name] = value

    def relate_object(self, *args):
        """
        Relates an object based on the ID
        """

        if len(args) == 2 and args[0] and args[1]:
            self._relate_object_deprecated(args[0], args[1])
        elif len(args) == 1 and args[0]:
            self._relate_object(args[0])

    def _relate_object_deprecated(self, api_name, obj):
        """
        Relates an object to another the "old" way
        """

        if api_name not in self.relationships:
            self.relationships[api_name] = []

        # Don't relate if duplicate
        if any(item.oid == obj.oid for item in self.relationships[api_name] if item.oid is not None):
            return

        self.relationships[api_name].append(obj)

    def _relate_object(self, obj):
        """
        Relates an object to another the "new" way
        """

        if obj.api_name not in self.relationships:
            self.relationships[obj.api_name] = []

        # Don't relate if duplicate
        if any(item.oid == obj.oid for item in self.relationships[obj.api_name] if item.oid is not None):
            return

        self.relationships[obj.api_name].append(obj)

    def fill_from_api_response(self, api_response, sources=[], attr_sources=[]):
        """
        Fill ourselves in based on an API response
        """

        # Load basic data
        self.api_name = api_response.get('api_name', self.api_name)
        self.oid = api_response.get('id')
        self.value = api_response.get('value', '')
        self.name = api_response.get('name', '')
        self.title = api_response.get('title', '')
        self.description = api_response.get('description', '')
        self.happened_at = api_response.get('happened_at')
        self.type_id = api_response.get('type_id')
        if 'type' in api_response:
            if isinstance(api_response['type'], dict):
                self.type = api_response.get('type', {}).get('name')
            elif isinstance(api_response['type'], string_types):
                self.type = api_response['type']
            elif isinstance(api_response['type'], int):
                self.type_id = api_response['type']
        self.status_id = api_response.get('status_id')
        if 'status' in api_response:
            if isinstance(api_response['status'], dict):
                self.status = api_response.get('status', {}).get('name')
            elif isinstance(api_response['status'], string_types):
                self.status = api_response['status']
            elif isinstance(api_response['status'], int):
                self.status_id = api_response['status']

        # Load score
        if self.api_name == "indicators" and "score" in api_response:
            if isinstance(api_response['score'], dict):
                self.score = api_response['score'].get('manual_score')
                if self.score is None:
                    self.score = api_response['score'].get('generated_score')
            else:
                self.score = api_response['score']

            self.score = math.floor(float(self.score))

        # Load relationships
        for item in self.object_list:
            if item in api_response:
                # Make sure we have a place to store the relationship
                if item not in self.relationships:
                    self.relationships[item] = []

                # Turn all dictionaries into Threat objects
                for rel in api_response.get(item, []):
                    obj = ThreatQObject(self.tq, item)
                    obj.fill_from_api_response(rel)
                    self.relationships[item].append(obj)

        # Load soures
        for item in api_response.get('sources', []):
            self.add_source(item['name'], tlp_id=item.get('tlp_id'), tlp=item.get('tlp'))
        for item in sources:
            if isinstance(item, dict):
                self.add_source(item['name'], tlp_id=item.get('tlp_id'), tlp=item.get('tlp'))
            else:
                self.add_source(item)

        # Load attributes
        for item in api_response.get('attributes', []):
            if not item['name'] or not item['value']:  # You wouldn't think this would get hit, but it can
                continue

            attr_src = item.get('sources', [])

            # Append custom attribute sources
            if attr_sources:
                for src in attr_sources:
                    if isinstance(item, dict):
                        attr_src.append(src)
                    else:
                        attr_src.append({'name': src})

            self.add_attribute(item['name'], item['value'], sources=attr_sources, tlp=item.get('tlp'))

        # Load comments
        self.comments = api_response.get('comments', [])

        return self

    @staticmethod
    def bulk_upload(tq, objects, show_debug=True, ignored_fields=[]):
        """
        Bulk upload a list of ThreatObjects
        """

        if not objects:
            return []

        # Load the obejcts
        data = [obj._to_dict(ignore=ignored_fields) for obj in objects if obj]
        output = []
        i = 0
        batch = 500

        # Create batches to upload
        while i < len(data):
            delay = randint(1, 3)
            if show_debug:
                logger.debug('Bulk uploading [{}] entries {} - {}'.format(objects[0].api_name, i, i + batch))

            try:
                # Upload the objects
                res = tq.post('/api/{}/consume'.format(objects[0].api_name), data=data[i:i + batch])
                res = [] if not res else res.get('data', [])
                output.extend(res)

                # Load in the ID from the upload
                for item in res:
                    for obj in objects:
                        if (
                            obj.name and obj.name == item.get('name') or
                            obj.value and obj.value == item.get('value') or
                            obj.title and obj.title == item.get('title')
                        ):
                            obj._set_id(item.get('id'))
                            break
            except Exception:
                logger.error('Failed to upload entries {} - {}. Continuing...'.format(i, i + batch))

            sleep(delay)
            i += batch

        return output

    def _to_dict(self, ignore=[], for_api=True):
        """
        Serialize this object to a representation suitable for upload to ThreatQ
        """

        output = {}

        if not self.value and not self.name and not self.title:
            raise ValueError('Threat Object has no value or name!')

        # The default fields
        if not for_api:
            output['api_name'] = self.api_name
        if self.value:
            output['value'] = self.value
        if self.name:
            output['name'] = self.name
        if self.title:
            output['title'] = self.title
        if self.description and 'description' not in ignore:
            # Need this case because of the techdebt in the API
            if self.api_name == 'adversaries':
                output['description'] = [{'value': self.description[:65500]}]
            else:
                output['description'] = self.description[:65500]  # Max MariaDB TEXT length

        if self.oid and 'id' not in ignore:
            output['id'] = self.oid
        if self.comments and 'comments' not in ignore:
            output['comments'] = self.comments
        if self.attributes and 'attributes' not in ignore:
            self.attributes = ThreatQAttribute.merge_attributes(self.attributes)
            output['attributes'] = [
                attr.to_dict() for attr in self.attributes if attr and isinstance(attr, ThreatQAttribute)]
        if self.tlp and self.tlp in tlp_map and 'tlp' not in ignore:
            output['tlp_id'] = tlp_map.get(self.tlp)
        if self.status and 'status' not in ignore:
            output['status'] = {'name': self.status}
        if self.status_id and 'status' not in ignore and 'status_id' not in ignore:
            output['status_id'] = self.status_id
        if self.type and 'type' not in ignore:
            output['type'] = {'name': self.type}
        if self.type_id and 'type' not in ignore and 'type_id' not in ignore:
            output['type_id'] = self.type_id
        if self.sources and 'sources' not in ignore:
            self.sources = ThreatQSource.merge_sources(self.sources)  # Merge the sources by hierarchy
            output['sources'] = [
                src.to_dict() for src in self.sources if src and isinstance(src, ThreatQSource)]
        if self.happened_at and 'happened_at' not in ignore:
            output['happened_at'] = self.happened_at
        if self.api_name == "indicators" and self.score is not None and 'score' not in ignore and not for_api:
            output['score'] = self.score

        # Add relationships
        if 'relationships' not in ignore:
            for k, v in self.relationships.items():
                output[k] = []
                for item in v:
                    # Only add if an ID is available
                    if isinstance(item, dict) and 'id' in item:
                        output[k].append({'id': item['id']})
                    elif isinstance(item, ThreatQObject) and item.oid:
                        output[k].append({'id': item.oid} if for_api else item._to_dict())

        if self.published_at and 'published_at' not in ignore:
            output['published_at'] = self.published_at

        return output

    def add_comment(self, value):
        """
        Add a comment to a custom object
        """

        if not value:
            raise Exception('Cannot add a comment to a Threat Object without a value!')

        self.comments.append({'value': value})

    def get_comments(self):
        """
        Gets comments for a custom object
        """

        if not self.oid:
            raise Exception('Cannot get comments for a Threat Object without an ID!')

        p = {'with': 'sources'}
        res = self.tq.get(self._get_api_endpoint() + '/comments', params=p)
        self.comments = res.get('data')

        return self.comments

    def add_attribute(self, *args, **kwargs):
        if len(args) == 1:
            self._add_attribute_object(args[0])
        elif len(args) == 2:
            self._add_attribute_quick(*args, **kwargs)

        return self

    def _add_attribute_quick(self, key, value, sources=None, tlp=None):
        """
        Add an attribute to the Threat Object
        """

        if not key or not value:
            return

        if isinstance(value, bool):
            value = 'Yes' if value else 'No'

        attr = ThreatQAttribute(key, value, sources=sources, tlp=tlp)
        self._add_attribute_object(attr)

    def _add_attribute_object(self, attribute):
        """
        Adds a ThreatQ Attribute object as an attribute
        """

        if isinstance(attribute, list):
            for i in attribute:
                if isinstance(i, ThreatQAttribute):
                    self.add_attribute(i)
        elif isinstance(attribute, ThreatQAttribute) and attribute.name and attribute.value:
            self.attributes.append(attribute)

    def get_attributes(self):
        """
        Get attributes associated with this object

        :raises: :py:class:`~threatqsdk.exceptions.NotCreatedError` if
                the object has yet to be created
        """

        if not self.oid:
            raise Exception('Cannot get attributes of a Threat Object without an ID!')

        endpoint = self._get_api_endpoint() + '/attributes'
        results = self.tq.get(endpoint, withp='attribute')
        if 'data' not in results:
            return []

        self.attributes = results['data']
        return self.attributes

    def _get_api_suffix(self, obj_type):
        return obj_type._get_base_endpoint_name()

    def get_related_objects(self, obj_type):
        """
        Get related objects
        """

        if not self.oid:
            raise Exception('Cannot get related objects of the Threat Object without an ID!')

        suffix = self._get_api_suffix(obj_type)
        if obj_type == self.__class__ and suffix == 'adversaries':
            return []
        endpoint = self._get_api_endpoint() + '/' + suffix
        results = self.tq.get(endpoint)
        if 'data' not in results:
            return []

        tr = []
        for obj in results['data']:
            inst = obj_type(self.tq)
            inst.fill_from_api_response(obj)
            tr.append(inst)

        return tr

    def _object_url(self, oid):
        """
        Get a link to the identity suitable for presentation to an
        end user

        :param int iid: Identity ID
        """

        if not self.oid:
            raise Exception('Cannot get Threat Object URL without an ID!')

        base = self.tq.threatq_host + '/{}/'.format(self.add_attribute)
        return base + str(oid) + '/details'

    def upload(self):
        """
        Upload object to ThreatQ
        """

        ThreatQObject.bulk_upload(self.tq, [self])

    def find(self, withp=''):
        """
        Finds an object by its value
        """

        params = {}
        if self.value:
            params['value'] = self.value
        elif self.name:
            params['name'] = self.name
        elif self.title:
            params['title'] = self.title
            if ',' in params['title']:
                params['title'] = params['title'].split(',')[0] + '%'
        if withp:
            params['with'] = withp

        res = self.tq.get('/api/{}'.format(self.api_name), params=params)
        if res and res.get('data') and res['data']:
            self.fill_from_api_response(res['data'][0])

        return self

    def add_tag(self, tag_name):
        self.add_tags([tag_name])

    def upload_tags(self, tags):

        if not self.oid:
            raise Exception('Cannot add tag to a Threat Object without an ID!')

        data = []
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, string_types):
                    data.append({'name': tag})
                elif isinstance(tag, dict) and 'name' in tag:
                    data.append(tag)

        if data:
            self.tq.post('/api/{}/{}/tags'.format(self.api_name, self.oid), data=data)

    @staticmethod
    def parse_tlp(tlp):
        """
        Parse a generic TLP string/int into a valid ThreatQ one
        """

        if tlp and isinstance(tlp, string_types) and tlp in tlp_map.keys():
            return tlp_map[tlp]
        elif tlp and isinstance(tlp, int) and tlp in tlp_map.values():
            return tlp


class ThreatQSource(object):

    def __init__(self, name, tlp=None):
        """
        An encapsulation of a ThreatQ source
        """

        self.name = name
        self.tlp = ThreatQObject.parse_tlp(tlp)

    @staticmethod
    def make_source_list(sources):
        """
        Parses sources from an "any" variable
        """

        new_sources = []
        if isinstance(sources, string_types):
            for src in sources.split(','):  # Support comma separated sources
                new_sources.append(ThreatQSource(src))
        elif isinstance(sources, list):
            for src in sources:
                new_sources.extend(ThreatQSource.make_source_list(src))
        elif isinstance(sources, dict) and 'name' in sources:
            tlp = sources.get('tlp', sources.get('tlp_id'))
            new_sources.append(ThreatQSource(sources['name'], tlp=tlp))
        elif isinstance(sources, ThreatQSource) and sources.name:
            new_sources.append(sources)

        return new_sources

    @staticmethod
    def merge_sources(source_list):
        """
        Merge sources with the same name together.
        This is so we can apply TLPs by hierarchy.
        """

        new_sources = []
        for i in source_list:

            # Find a match
            found = None
            for j in new_sources:
                if i.name == j.name:
                    found = j
                    break

            # If there is no match, add the source
            if not found:
                new_sources.append(i)
                continue

            # If there is a match, compare based on TLP hierarchy
            # If the TLP is more "secret", remove old source and apply new one
            if (i.tlp and not j.tlp) or (i.tlp and j.tlp and i.tlp < j.tlp):
                new_sources.remove(j)
                new_sources.append(i)

        # Set the source list to the merged source list
        return new_sources

    def to_dict(self):
        output = {'name': self.name}
        if self.tlp:
            output['tlp_id'] = self.tlp

        return output


class ThreatQAttribute(object):

    def __init__(self, name, value, sources=None, tlp=None):
        """
        An encapsulation of a ThreatQ attribute

        Parameters:
            - name (str): The name of the attribute
            - value (str): The value of the attribute
            - sources (any): Sources for the attribute
            - tlp (str,int): Default TLP for the attribute
        """

        if sources is None:
            sources = []
        self.name = name
        self.value = value
        self.sources = ThreatQSource.make_source_list(sources)
        self.tlp = ThreatQObject.parse_tlp(tlp)

    @staticmethod
    def merge_attributes(attribute_list):
        """
        Merge sources with the same name together.
        This is so we can apply TLPs by hierarchy.
        """

        new_attrs = []
        for i in attribute_list:
            # Find a match
            found = None
            for j in range(len(new_attrs)):
                if i.name == new_attrs[j].name and i.value == new_attrs[j].value:
                    found = j
                    break

            # If there is no match, add the attribute
            if not found:
                new_attrs.append(i)
                continue

            # If there is a match, merge the sources
            new_attrs[j].sources.extend(i.sources)

        # Set the source list to the merged source list
        return new_attrs

    def add_source(self, source, tlp=None):
        """
        Adds a source to the list
        """

        if not source:
            return

        if isinstance(source, ThreatQSource):
            self.sources.append(source)
        elif isinstance(source, dict) and 'name' in source:
            if tlp:
                source['tlp'] = tlp
            self.sources.extend(ThreatQSource.make_source_list(source))
        elif isinstance(source, string_types):
            for i in source.split(','):
                self.sources.append(ThreatQSource(i, tlp=tlp))
        elif isinstance(source, list):
            for i in source:
                self.add_source(i, tlp=tlp)

    def to_dict(self):
        output = {'name': self.name, 'value': self.value}
        if isinstance(output['value'], bool):
            output['value'] = 'Yes' if output['value'] else 'No'

        if self.sources:
            self.sources = ThreatQSource.merge_sources(self.sources)  # Merge the sources by hierarchy
            output['sources'] = [src.to_dict() for src in self.sources if src]
        if self.tlp:
            output['tlp_id'] = self.tlp

        return output
