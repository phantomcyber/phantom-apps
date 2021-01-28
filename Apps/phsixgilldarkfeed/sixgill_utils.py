# File: sixgill_utils.py
#
# Copyright (c) 2021 Cybersixgill Ltd.
#
# Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)

from sixgilldarkfeed_consts import *

import requests
import re


class SixgillUtils(object):
    def __init__(self, connector):
        """
        :param connector: CyberSixgillConnector
        """
        self._connector = connector
        config = connector.get_config()

        self._headers = {"ph-auth-token": config[AUTH_TOKEN]}

    def ds_to_phantom_severity_transform(self, severity):
        """
        Map Sixgill Darkfeed severity to Phantom severity.

        :param severity: Sixgill Darkfeed Severity: 60, 70, 80, 90
        :return: Phantom Severity: high, medium, low
        """
        if severity >= 0 and severity < 60:
            return "low", "green"
        if severity == 60:
            return "medium", "amber"
        if severity > 60:
            return "high", "red"

    def search_feed(self, indicator_id):
        feed_dict = dict()
        artifact_list = []
        query_url = f"{BASE_URL}{REST_ARTIFACT_API}{SOURCE_FEED_ID}'{indicator_id}'"
        search_indicator = requests.get(query_url, headers=self._headers, verify=False)
        if search_indicator is not None and search_indicator.status_code == 200:
            event_dict = search_indicator.json()
            if event_dict.get(COUNT, 0) > 0:
                for event in event_dict.get(DATA, []):
                    if CONTAINER_ID in event and ARTIFACT_ID in event:
                        artifact_list.append(event.get(ARTIFACT_ID))
                        container_id = event.get(CONTAINER_ID)
                feed_dict.update({CONTAINER: container_id, ARTIFACT_LIST: artifact_list})
            return feed_dict
        else:
            return feed_dict

    def sixgill_delimit_id(self, indicator_id):
        return indicator_id.split("--")[-1]

    def get_labels(self, indicator):
        label_list = indicator.get(SIXGILL_LABELS, [])
        for index, label in enumerate(label_list):
            label = label.replace(" ", "-").replace("/", "-or-")
            label_list[index] = label
        return label_list

    def update_event(
        self, feed_dict, indicator_list, indicator, prepare_container, sixgill_container, sixgill_artifact, verify_ssl
    ):
        if CONTAINER in feed_dict:
            container_id = feed_dict.get(CONTAINER)
            for count in range(int(TRY_AGAIN)):
                update_container = sixgill_container.update_container(container_id, prepare_container, verify_ssl)
                if update_container is not None and update_container.status_code == 200:
                    break
            for artifact_id in feed_dict.get(ARTIFACT_LIST):
                if SEVERTITY in prepare_container:
                    for indicator_dict in indicator_list:
                        prepare_artifact = sixgill_artifact.prepare_artifact(
                            container_id, prepare_container.get(SEVERTITY), indicator, indicator_dict
                        )
                        for count in range(int(TRY_AGAIN)):
                            update_artifact = sixgill_artifact.update_artifact(
                                artifact_id, prepare_artifact, verify_ssl
                            )
                            if update_artifact is not None and update_artifact.status_code == 200:
                                break

    def delete_event(self, feed_dict, indicator, sixgill_container, sixgill_artifact, verify_ssl):
        # If the indicator includes a "revoked" = true flag, the indicator will get deleted from the phantom SOAR platform
        if indicator.get(REVOKED, False) is TRUE and CONTAINER in feed_dict:
            for artifact_id in feed_dict.get(ARTIFACT_LIST):
                for count in range(int(TRY_AGAIN)):
                    delete_artifact = sixgill_artifact.delete_artifact(artifact_id, verify_ssl)
                    if delete_artifact is not None and delete_artifact.status_code == 200:
                        break
            for count in range(int(TRY_AGAIN)):
                delete_container = sixgill_container.delete_container(feed_dict[CONTAINER], verify_ssl)
                if delete_container is not None and delete_container.status_code == 200:
                    break

    def sixgill_get_sixgill_pattern_type(self, indicator):
        """This method parses the 'Pattern' of the darkfeed to retrieve the IOC's

        Arguments:
            indicator - Sixgill Darkfeed Indicator

        Returns:
            list -- Key, Value pair of the retrived IOC's
        """
        stix_regex_parser = re.compile(r"([\w-]+?):(\w.+?) (?:[!><]?=|IN|MATCHES|LIKE) '(.*?)' *[OR|AND|FOLLOWEDBY]?")
        indicator_list = []
        if "pattern" in indicator:
            for indicator_type, sub_type, value in stix_regex_parser.findall(indicator.get("pattern")):
                indicator_dict = {}
                if indicator_type == "file":
                    if "MD5" in sub_type:
                        indicator_dict.update({"Type": "MD5", "Value": value})
                    if "SHA-1" in sub_type:
                        indicator_dict.update({"Type": "SHA-1", "Value": value})
                    if "SHA-256" in sub_type:
                        indicator_dict.update({"Type": "SHA-256", "Value": value})
                    indicator_list.append(indicator_dict)
                elif indicator_type == "url":
                    indicator_dict.update({"Type": "URL", "Value": value})
                    indicator_list.append(indicator_dict)
                elif indicator_type == "ipv4-addr":
                    indicator_dict.update({"Type": "IP Address", "Value": value})
                    indicator_list.append(indicator_dict)
                elif indicator_type == "domain":
                    indicator_dict.update({"Type": "DOMAIN", "Value": value})
                    indicator_list.append(indicator_dict)
        return indicator_list

    def create_repuation_dict(self, indicator):
        enrich_indicator_dict = dict()
        sixgill_utils = SixgillUtils(self._connector)
        indicator_list = sixgill_utils.sixgill_get_sixgill_pattern_type(indicator)
        for indicator_dict in indicator_list:
            indicator_type = indicator_dict.get(SIXGILL_INDICATOR_TYPE)
            if indicator_type in ["MD5", "SHA-256", "SHA-1"]:
                indicator_type = f"Hash - {indicator_type}"
            enrich_indicator_dict["indicator_type"] = indicator_type
            enrich_indicator_dict["indicator_value"] = indicator_dict.get(SIXGILL_INDICATOR_VALUE)
            enrich_indicator_dict["description"] = indicator.get("description")
            enrich_indicator_dict["labels"] = self.get_labels(indicator)
            enrich_indicator_dict["sixgill_actor"] = indicator.get("sixgill_actor")
            enrich_indicator_dict["sixgill_confidence"] = indicator.get("sixgill_confidence")
            enrich_indicator_dict["sixgill_feedid"] = indicator.get("sixgill_feedid")
            enrich_indicator_dict["sixgill_feedname"] = indicator.get("sixgill_feedname")
            enrich_indicator_dict["sixgill_post_virustotallink"] = indicator.get("sixgill_post_virustotallink")
            enrich_indicator_dict[
                "sixgill_postid"
            ] = f"https://portal.cybersixgill.com/#/search?q=_id:{indicator.get(SIXGILL_FEED_POSTID)}"
            enrich_indicator_dict["sixgill_posttitle"] = indicator.get("sixgill_posttitle")
            enrich_indicator_dict["sixgill_source"] = indicator.get("sixgill_source")
            enrich_indicator_dict["valid_from"] = indicator.get("valid_from")
            enrich_indicator_dict["modified"] = indicator.get("modified")
            enrich_indicator_dict["created"] = indicator.get("created")
            enrich_indicator_dict["sixgill_severity"] = indicator.get("sixgill_severity")
            mitre_data = self.get_mitre_vt_data(indicator)
            for key, value in mitre_data.items():
                data = []
                for mitre_vt_key, mitre_vt_value in value.items():
                    if mitre_vt_key is not None and mitre_vt_value is not None:
                        data.append(f'{mitre_vt_key.replace(" ", "_")}:{mitre_vt_value.replace(" ", "_")}')
                enrich_indicator_dict[key] = data
        return enrich_indicator_dict

    def get_mitre_vt_data(self, indicator):
        mitre_vt = dict()
        if SIXGILL_FEED_EXTERNAL_REFERENCE in indicator:
            for mitre in indicator.get(SIXGILL_FEED_EXTERNAL_REFERENCE):
                if SIXGILL_FEED_SOURCENAME in mitre and mitre.get(SIXGILL_FEED_SOURCENAME) == MITRE_ATTACK:
                    mitre_vt["Mitre_Pattern"] = {
                        SIXGILL_MITRE_ATTACK_TATIC: mitre.get(MITRE_ATTACK_TATIC),
                        SIXGILL_MITRE_ATTACK_TATIC_ID: mitre.get(MITRE_ATTACK_TATIC_ID),
                        SIXGILL_MITRE_ATTACK_TATIC_URL: mitre.get(MITRE_ATTACK_TATIC_URL),
                        SIXGILL_MITRE_ATTACK_TECHNIQUE: mitre.get(MITRE_ATTACK_TECHNIQUE),
                        SIXGILL_MITRE_ATTACK_TECHNIQUE_ID: mitre.get(MITRE_ATTACK_TECHNIQUE_ID),
                        SIXGILL_MITRE_ATTACK_TECHNIQUE_URL: mitre.get(MITRE_ATTACK_TECHNIQUE_URL),
                    }
                if SIXGILL_FEED_SOURCENAME in mitre and mitre.get(SIXGILL_FEED_SOURCENAME) == VIRUSTOTAL:
                    mitre_vt["Virus_Total"] = {
                        SIXGILL_VIRUSTOTAL_POSITIVE_RATE: mitre.get(VIRUSTOTAL_POSITIVE_RATE),
                        SIXGILL_VIRUSTOTAL_URL: mitre.get(VIRUSTOTAL_URL),
                    }
        return mitre_vt
