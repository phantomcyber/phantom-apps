#
# Copyright (c) 2017 Digital Shadows Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

from ..transform.ds_api_to_pipeline_transform import DSAPIToPipelineTransform


class Pipeline(object):

    def __init__(self, incidents, analyst_assessed, all_mentions):
        self._incidents = incidents
        self._analyst_assessed = analyst_assessed
        self._all_mentions = all_mentions

    @property
    def incidents(self):
        return self._incidents

    @property
    def analyst_assessed(self):
        return self._analyst_assessed

    @property
    def all_mentions(self):
        return self._all_mentions

    def __str__(self):
        return 'Pipeline[incidents={}, analyst_assessed={}, all_mentions={}]'\
            .format(self._incidents, self.analyst_assessed, self._all_mentions)

    @classmethod
    def from_json(cls, json, pipeline_range):
        return DSAPIToPipelineTransform.apply(cls, json, pipeline_range)
