# File: digital_shadows_connector.py
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
#

import phantom.app as phantom
from phantom.base_connector import BaseConnector

import json

from digital_shadows_consts import DS_ACTION_NOT_SUPPORTED

from ds_test_connectivity_connector import DSTestConnectivityConnector
# from ds_lookup_username_connector import DSLookupUsernameConnector
from ds_on_poll_connector import DSOnPollConnector
from ds_incidents_connector import DSIncidentsConnector
from ds_intelligence_incidents_connector import DSIntelligenceIncidentsConnector
from ds_databreach_connector import DSDataBreachConnector
# from ds_infrastructure_connector import DSInfrastructureConnector
from ds_search_entities_connector import DSSearchEntitiesConnector


class DigitalShadowsConnector(BaseConnector):

    def __init__(self):
        super(DigitalShadowsConnector, self).__init__()

    def handle_action(self, param):
        action_id = self.get_action_identifier()
        if param:
            self.save_progress("Ingesting handle action in: {}".format(param))
        if action_id == 'test_connectivity':
            test_connectivity_connector = DSTestConnectivityConnector(self)
            return test_connectivity_connector.test_connectivity()
        elif action_id == 'get_incident_by_id':
            incidents_connector = DSIncidentsConnector(self)
            return incidents_connector.get_incident_by_id(param)
        elif action_id == 'get_incident_review_by_id':
            incidents_connector = DSIncidentsConnector(self)
            return incidents_connector.get_incident_review_by_id(param)
        elif action_id == 'get_incident_list':
            incidents_connector = DSIncidentsConnector(self)
            return incidents_connector.get_incident_list(param)
        elif action_id == 'post_incident_review':
            incidents_connector = DSIncidentsConnector(self)
            return incidents_connector.post_incident_review(param)
        elif action_id == 'get_intelligence_incident_by_id':
            intelligence_incidents_connector = DSIntelligenceIncidentsConnector(self)
            return intelligence_incidents_connector.get_intelligence_incident_by_id(param)
        elif action_id == 'get_intel_incident_ioc_by_id':
            intelligence_incidents_connector = DSIntelligenceIncidentsConnector(self)
            return intelligence_incidents_connector.get_intel_incident_ioc_by_id(param)
        elif action_id == 'get_intelligence_incident':
            intelligence_incidents_connector = DSIntelligenceIncidentsConnector(self)
            return intelligence_incidents_connector.get_intelligence_incident(param)
        elif action_id == 'get_data_breach':
            databreach_connector = DSDataBreachConnector(self)
            return databreach_connector.get_data_breach(param)
        elif action_id == 'get_data_breach_by_id':
            databreach_connector = DSDataBreachConnector(self)
            return databreach_connector.get_data_breach_by_id(param)
        elif action_id == 'get_data_breach_record':
            databreach_connector = DSDataBreachConnector(self)
            return databreach_connector.get_data_breach_record(param)
        elif action_id == 'get_data_breach_record_by_id':
            databreach_connector = DSDataBreachConnector(self)
            return databreach_connector.get_data_breach_record_by_id(param)
        elif action_id == 'get_data_breach_record_by_username':
            databreach_connector = DSDataBreachConnector(self)
            return databreach_connector.get_data_breach_record_by_username(param)
        elif action_id == 'get_data_breach_record_reviews':
            databreach_connector = DSDataBreachConnector(self)
            return databreach_connector.get_data_breach_record_reviews(param)
        elif action_id == 'post_breach_record_review':
            databreach_connector = DSDataBreachConnector(self)
            return databreach_connector.post_breach_record_review(param)
        elif action_id == 'search_entities':
            search_entities_connector = DSSearchEntitiesConnector(self)
            return search_entities_connector.search_entities(param)
        elif action_id == 'on_poll':
            on_poll_connector = DSOnPollConnector(self)
            return on_poll_connector.on_poll(param)
        else:
            self.save_progress(DS_ACTION_NOT_SUPPORTED.format(action_id))
            return self.set_status(phantom.APP_ERROR, DS_ACTION_NOT_SUPPORTED.format(action_id))


if __name__ == '__main__':

    import sys

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = DigitalShadowsConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
