# File: ds_api_to_pipeline_transform.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

class DSAPIToPipelineTransform(object):

    @staticmethod
    def apply(cls, json, pipeline_range):
        """
        Transform Digital Shadows pipeline api data to Pipeline object.
        
        :type pipeline_range: PipelineRange
        :param cls: Pipeline constructor 
        :param json: api data
        :param pipeline_range:
        :return: Pipeline
        """
        date_from = json['from']
        date_until = json['until']
        for stage in json['stages']:
            stage[str('date_range')] = str(pipeline_range)
            stage[str('from')] = str(date_from)
            stage[str('until')] = str(date_until)

            stage_type = stage['type']
            if stage_type == 'INCIDENTS':
                incidents = stage
            elif stage_type == 'ANALYST_ASSESSED':
                analyst_assessed = stage
            elif stage_type == 'ALL_MENTIONS':
                all_mentions = stage
        return cls(incidents, analyst_assessed, all_mentions)
